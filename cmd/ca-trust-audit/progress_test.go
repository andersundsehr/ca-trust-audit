package main

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/andersundsehr/ca-trust-audit/pkg/audit"
	"github.com/andersundsehr/ca-trust-audit/pkg/report"
)

func TestOutputModes(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	for _, mode := range []string{"auto", "always", "never", "invalid"} {
		var b bytes.Buffer
		color, ce := colorEnabled(mode, &b)
		progress, pe := progressEnabled(mode, &b)
		if (ce != nil) != (mode == "invalid") || (pe != nil) != (mode == "invalid") {
			t.Fatalf("%s: color=%v progress=%v", mode, ce, pe)
		}
		if color != (mode == "always") || progress != (mode == "always") {
			t.Fatalf("%s: color=%v progress=%v; redirected auto must be plain", mode, color, progress)
		}
	}
}

func TestProgressConcurrentTargetsAndCancellation(t *testing.T) {
	var b bytes.Buffer
	p := newScanProgress(&b, false)
	p.Update(audit.Progress{Phase: audit.PhaseTargetsDiscovered, Total: 3})
	var wg sync.WaitGroup
	for _, name := range []string{"web", "worker"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			target := report.Target{Kind: "container", Name: name}
			p.Update(audit.Progress{Phase: audit.PhaseTargetStarted, Target: target})
			for i := 0; i <= 100; i++ {
				p.Update(audit.Progress{Phase: audit.PhaseStores, Target: target, Completed: i, Total: 100})
			}
			p.Update(audit.Progress{Phase: audit.PhaseTargetCompleted, Target: target})
		}(name)
	}
	wg.Wait()
	p.Update(audit.Progress{Phase: audit.PhaseTargetCanceled, Target: report.Target{Kind: "container", Name: "unsafe\x1b[31m\nname"}})
	p.Close(context.Canceled)
	text := b.String()
	if !strings.Contains(text, "Scan stopped before completion | 2/3 targets processed") || strings.Contains(text, "3/3 targets processed") {
		t.Fatalf("cancellation must not count as completed: %s", text)
	}
	if strings.Contains(text, "\x1b") || strings.Contains(text, "\r") || strings.Contains(text, "\nname") {
		t.Fatalf("control characters in redirected progress: %q", text)
	}
	if strings.Count(text, "reading CA files") != 2 {
		t.Fatal("redirected progress must log stages, not hundreds of file updates")
	}
	if strings.Contains(text, "PASSED") || strings.Contains(text, "PROBLEM") {
		t.Fatal("progress must not imply a security outcome")
	}
}

func TestInvalidPresentationFlags(t *testing.T) {
	for _, args := range [][]string{{"--color", "invalid"}, {"--progress", "invalid"}} {
		var out, errout bytes.Buffer
		if code := run(context.Background(), args, &out, &errout); code != 2 || out.Len() != 0 || errout.Len() == 0 {
			t.Fatalf("%v: wrong error behavior: %d %q %q", args, code, out.String(), errout.String())
		}
	}
}
