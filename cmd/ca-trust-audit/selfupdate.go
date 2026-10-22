package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/andersundsehr/ca-trust-audit/internal/selfupdate"
)

func runSelfUpdate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ca-trust-audit self-update", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var check, force bool
	var timeout time.Duration
	var colorMode string
	flags.StringVar(&colorMode, "color", "auto", "command colors in errors: auto, always, or never (NO_COLOR disables auto)")
	flags.BoolVar(&check, "check", false, "check the latest release without changing files")
	flags.BoolVar(&force, "force", false, "reinstall even if current or newer than the latest release")
	flags.DurationVar(&timeout, "timeout", 2*time.Minute, "whole-update deadline (1s..10m)")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || timeout < time.Second || timeout > 10*time.Minute || (check && force) {
		fmt.Fprintln(stderr, "self-update accepts --check, --force, --color auto|always|never and --timeout 1s..10m; check and force are mutually exclusive")
		return 2
	}
	useColor, err := colorEnabled(colorMode, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	r, err := selfupdate.Run(ctx, selfupdate.Options{CurrentVersion: version, CheckOnly: check, Force: force, Progress: func(message string) {
		fmt.Fprintln(stderr, "[update]", message)
	}})
	if err != nil {
		fmt.Fprintln(stderr, "self-update failed:", updateErrorDetail(err, useColor))
		return 2
	}
	switch {
	case r.Updated:
		fmt.Fprintf(stdout, "Updated ca-trust-audit: %s -> %s\nExecutable: %s\n", r.Current, r.Latest, r.Path)
	case r.Current == r.Latest:
		fmt.Fprintf(stdout, "ca-trust-audit is up to date (%s).\n", r.Latest)
	case r.Ahead:
		fmt.Fprintf(stdout, "Current version %s is newer than the latest stable release %s; executable unchanged.\n", r.Current, r.Latest)
	default:
		fmt.Fprintf(stdout, "Update available: %s -> %s\nRun: ca-trust-audit self-update\n", r.Current, r.Latest)
	}
	return 0
}

func updateErrorDetail(err error, color bool) string {
	detail := progressText(err.Error())
	if !color || !errors.Is(err, selfupdate.ErrInstallLocation) {
		return detail
	}
	return strings.NewReplacer(
		"sudo ca-trust-audit self-update", "\x1b[36msudo ca-trust-audit self-update\x1b[0m",
		"--install-dir", "\x1b[36m--install-dir\x1b[0m",
	).Replace(detail)
}
