// Command ca-trust-audit scans the local Linux filesystem and running Docker containers.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/andersundsehr/ca-trust-audit/pkg/audit"
	"github.com/andersundsehr/ca-trust-audit/pkg/report"
)

var version = "dev"
var commit = "unknown"
var buildDate = "unknown"

type paths []string

func (p *paths) String() string     { return fmt.Sprint([]string(*p)) }
func (p *paths) Set(v string) error { *p = append(*p, v); return nil }
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && (args[0] == "self-update" || args[0] == "selfupdate") {
		return runSelfUpdate(ctx, args[1:], stdout, stderr)
	}
	flags := flag.NewFlagSet("ca-trust-audit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: ca-trust-audit [scan flags]\n       ca-trust-audit self-update [--check | --force] [--timeout 2m]\n\nScan flags:")
		flags.PrintDefaults()
	}
	var o audit.Options
	var output, progressMode, colorMode string
	var verbose, strict, showVersion bool
	var ca, dirs paths
	flags.StringVar(&colorMode, "color", "auto", "terminal colors: auto, always, or never (NO_COLOR disables auto)")
	flags.StringVar(&progressMode, "progress", "auto", "progress on stderr: auto (terminal only), always, or never")
	flags.BoolVar(&o.HostOnly, "host-only", false, "scan only the local filesystem")
	flags.BoolVar(&o.HostOnly, "host", false, "alias for --host-only")
	flags.BoolVar(&o.ContainersOnly, "containers-only", false, "scan only running containers")
	flags.StringVar(&o.Container, "container", "", "scan one running container by name or ID")
	flags.BoolVar(&o.Offline, "offline", false, "disable live network probes; use verified bundled chains")
	flags.StringVar(&output, "json", "", "write schema 1.0 JSON to a new file, or - for stdout")
	flags.BoolVar(&verbose, "verbose", false, "include all per-chain results")
	flags.BoolVar(&strict, "strict", false, "exit 3 on incomplete supported TLS coverage unless vulnerable")
	flags.DurationVar(&o.Timeout, "timeout", 10*time.Second, "deadline per file, discovery or client request (1ms..5m)")
	flags.IntVar(&o.Workers, "workers", runtime.NumCPU(), "maximum concurrent container scans (default: available CPUs; minimum 1)")
	flags.Var(&dirs, "ca-dir", "additional absolute certificate directory (repeatable; bounded traversal)")
	flags.Var(&ca, "ca-file", "additional absolute PEM bundle path (repeatable, applied in each target)")
	flags.BoolVar(&showVersion, "version", false, "print build metadata")
	if e := flags.Parse(args); e != nil {
		if e == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return 2
	}
	if showVersion {
		fmt.Fprintf(stdout, "ca-trust-audit %s commit=%s built=%s %s/%s\n", version, commit, buildDate, runtime.GOOS, runtime.GOARCH)
		return 0
	}
	if o.Workers < 1 || o.Timeout < time.Millisecond {
		fmt.Fprintln(stderr, "workers must be at least 1 and timeout must be 1ms..5m")
		return 2
	}
	o.CAPaths = ca
	o.CADirectories = dirs
	useColor, e := colorEnabled(colorMode, stdout)
	if e != nil {
		fmt.Fprintln(stderr, e)
		return 2
	}
	showProgress, e := progressEnabled(progressMode, stderr)
	if e != nil {
		fmt.Fprintln(stderr, e)
		return 2
	}
	var progress *scanProgress
	if showProgress {
		progress = newScanProgress(stderr, isTerminal(stderr), o.Workers)
		o.Progress = progress.Update
	}
	r, e := audit.Scan(ctx, o)
	if progress != nil {
		progress.Close(e)
	}
	if e != nil {
		fmt.Fprintln(stderr, "scan failed:", e)
		return 2
	}
	if output != "" {
		var w io.Writer = stdout
		var f *os.File
		if output != "-" {
			f, e = os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if e != nil {
				fmt.Fprintln(stderr, "create JSON report:", e)
				return 2
			}
			w = f
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		e = enc.Encode(r)
		if f != nil {
			if ce := f.Close(); e == nil {
				e = ce
			}
		}
		if e != nil {
			fmt.Fprintln(stderr, "write JSON report:", e)
			return 2
		}
	}
	if output != "-" {
		if e = report.TerminalWithOptions(stdout, r, report.TerminalOptions{Verbose: verbose, Color: useColor}); e != nil {
			fmt.Fprintln(stderr, "write report:", e)
			return 2
		}
	}
	return r.ExitCode(strict)
}
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
