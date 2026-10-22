package main

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

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
	p := newScanProgress(&b, false, 2, time.Minute)
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
	last := strings.TrimSpace(text[strings.LastIndex(strings.TrimSuffix(text, "\n"), "\n")+1:])
	if !strings.Contains(last, "Scan stopped before completion") || !strings.Contains(last, "2/3 targets processed") || !strings.Contains(last, "n/a") || strings.Contains(text, "3/3 targets processed") {
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

func TestParallelETA(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name  string
		p     *scanProgress
		want  time.Duration
		known bool
	}{
		{"discovery without active work", &scanProgress{}, 0, false},
		{"active host before total is known", &scanProgress{active: map[string]progressTarget{"host": {"host", now.Add(-5 * time.Second)}}}, 55 * time.Second, true},
		{"initial budget without container samples", &scanProgress{totalKnown: true, total: 4, completed: 1, workers: 2}, 2 * time.Minute, true},
		{"parallel active and queued work", &scanProgress{totalKnown: true, total: 5, completed: 1, workers: 2, containerLongest: 10 * time.Second, active: map[string]progressTarget{"a": {"container", now.Add(-5 * time.Second)}, "b": {"container", now.Add(-5 * time.Second)}}}, 55 * time.Second, true},
		{"one worker", &scanProgress{totalKnown: true, total: 4, completed: 1, workers: 1, containerLongest: 10 * time.Second, active: map[string]progressTarget{"a": {"container", now.Add(-5 * time.Second)}}}, 85 * time.Second, true},
		{"overrunning jobs also expand queued budgets", &scanProgress{totalKnown: true, total: 3, completed: 1, workers: 2, containerLongest: 10 * time.Second, active: map[string]progressTarget{"a": {"container", now.Add(-31 * time.Second)}}}, 72 * time.Second, true},
		{"overdue target keeps a generous numeric ETA", &scanProgress{totalKnown: true, total: 2, completed: 1, workers: 2, containerLongest: 10 * time.Second, active: map[string]progressTarget{"a": {"container", now.Add(-11 * time.Second)}}}, 21 * time.Second, true},
		{"no last-second prediction before average finish", &scanProgress{totalKnown: true, total: 2, completed: 1, workers: 2, containerLongest: 10 * time.Second, active: map[string]progressTarget{"a": {"container", now.Add(-9500 * time.Millisecond)}}}, 20500 * time.Millisecond, true},
		{"slow host gets an expanded budget", &scanProgress{totalKnown: true, total: 1, active: map[string]progressTarget{"host": {"host", now.Add(-2 * time.Minute)}}}, 130 * time.Second, true},
		{"complete", &scanProgress{totalKnown: true, total: 3, completed: 3}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, known := tc.p.estimate(now)
			if got != tc.want || known != tc.known {
				t.Fatalf("ETA=%s known=%v, want %s known=%v", got, known, tc.want, tc.known)
			}
		})
	}
}

func TestETAExpandsAsSlowTargetKeepsRunning(t *testing.T) {
	start := time.Now()
	p := &scanProgress{totalKnown: true, total: 2, completed: 1, workers: 4, containerLongest: time.Second, active: map[string]progressTarget{"slow": {"container", start}}}
	var previous time.Duration
	for _, age := range []time.Duration{11, 20, 40, 80} {
		eta, known := p.estimate(start.Add(age * time.Second))
		if !known || eta <= previous || eta < age*time.Second {
			t.Fatalf("age=%ss ETA=%s known=%v previous=%s", age, eta, known, previous)
		}
		previous = eta
	}
}

func TestETAIsScopedUntilTargetsAreDiscovered(t *testing.T) {
	var b bytes.Buffer
	p := newScanProgress(&b, false, 2, time.Minute)
	target := report.Target{Kind: "host", Name: "local filesystem"}
	p.Update(audit.Progress{Phase: audit.PhaseTargetStarted, Target: target})
	if !strings.Contains(b.String(), "target ETA") || strings.Contains(b.String(), "estimating") {
		t.Fatalf("undiscovered target count must scope the estimate: %q", b.String())
	}
	b.Reset()
	p.Update(audit.Progress{Phase: audit.PhaseTargetsDiscovered, Total: 1})
	p.Update(audit.Progress{Phase: audit.PhaseConfiguration, Target: target})
	if strings.Contains(b.String(), "target ETA") || !strings.Contains(b.String(), " | ETA ") {
		t.Fatalf("discovered total must show whole-scan ETA: %q", b.String())
	}
	p.Close(nil)
}

func TestProgressFitsTerminalWithTargetLast(t *testing.T) {
	for _, width := range []int{10, 40, 79, 119, 159} {
		line := fitProgress("[progress] 2/12 | 1m4s | ETA estimating", "HTTPS positive control for PHP cURL", "container webapp", width)
		if len([]rune(line)) > width || strings.ContainsAny(line, "\r\n") {
			t.Fatalf("progress wraps at width %d: %q", width, line)
		}
		if width >= 79 && !strings.HasSuffix(line, " | container webapp") {
			t.Fatalf("target must remain last: %q", line)
		}
	}
	var b bytes.Buffer
	p := newScanProgress(&b, false, 2, time.Minute)
	p.Update(audit.Progress{Phase: audit.PhaseTargetStarted, Target: report.Target{Kind: "container", Name: "webapp"}})
	p.Close(nil)
	line := strings.Split(b.String(), "\n")[0]
	if !strings.HasSuffix(line, " | container webapp") || !strings.Contains(line, "ETA") || strings.Index(line, "elapsed") > strings.Index(line, "starting scan") {
		t.Fatalf("unstable progress ordering: %q", line)
	}
}

func TestProgressThrottlesConcurrentPhaseChanges(t *testing.T) {
	var b bytes.Buffer
	p := newScanProgress(&b, true, 4, time.Minute)
	begin := time.Now()
	for i := 0; i < 1000; i++ {
		phase := audit.PhaseStores
		if i%2 == 0 {
			phase = audit.PhaseClientDiscovery
		}
		p.Update(audit.Progress{Phase: phase, Target: report.Target{Kind: "container", Name: "webapp"}, Client: "curl"})
	}
	p.Close(nil)
	frames := strings.Count(b.String(), "\r\x1b[2K")
	if frames > 2+int(time.Since(begin)/(250*time.Millisecond)) {
		t.Fatalf("phase transitions bypassed the shared rate limit: %d frames", frames)
	}
}

func TestInvalidPresentationFlags(t *testing.T) {
	for _, args := range [][]string{{"--color", "invalid"}, {"--progress", "invalid"}, {"self", "--color", "invalid"}} {
		var out, errout bytes.Buffer
		if code := run(context.Background(), args, &out, &errout); code != 2 || out.Len() != 0 || errout.Len() == 0 {
			t.Fatalf("%v: wrong error behavior: %d %q %q", args, code, out.String(), errout.String())
		}
	}
}
