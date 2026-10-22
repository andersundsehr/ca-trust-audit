package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/andersundsehr/ca-trust-audit/pkg/audit"
	"github.com/andersundsehr/ca-trust-audit/pkg/report"
)

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return terminalColumns(f) > 0 && os.Getenv("TERM") != "dumb"
}
func progressEnabled(mode string, w io.Writer) (bool, error) {
	switch mode {
	case "auto":
		return isTerminal(w), nil
	case "always":
		return true, nil
	case "never":
		return false, nil
	default:
		return false, fmt.Errorf("progress must be auto, always or never")
	}
}

type scanProgress struct {
	lastDraw          time.Time
	mu                sync.Mutex
	w                 io.Writer
	interactive       bool
	start             time.Time
	message           string
	target            string
	completed, total  int
	totalKnown        bool
	workers           int
	active            map[string]progressTarget
	initialTargetTime time.Duration
	containerLongest  time.Duration
	finalETA          string
	lastLog           map[string]string
	stop, done        chan struct{}
}

type progressTarget struct {
	kind    string
	started time.Time
}

func newScanProgress(w io.Writer, interactive bool, workers int, initialTargetTime time.Duration) *scanProgress {
	p := &scanProgress{w: w, interactive: interactive, workers: max(1, workers), initialTargetTime: initialTargetTime, start: time.Now(), active: map[string]progressTarget{}, lastLog: map[string]string{}, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(p.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-ticker.C:
				p.mu.Lock()
				if p.interactive && p.message != "" && time.Since(p.lastDraw) >= 250*time.Millisecond {
					p.draw()
				}
				p.mu.Unlock()
			}
		}
	}()
	return p
}
func progressText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}
func (p *scanProgress) Update(event audit.Progress) {
	p.mu.Lock()
	defer p.mu.Unlock()
	target := strings.TrimSpace(event.Target.Kind + " " + event.Target.Name)
	key := event.Target.Kind + ":" + event.Target.ID + ":" + event.Target.Name
	now := time.Now()
	message := ""
	logKey := key + ":" + string(event.Phase) + ":" + event.Client
	switch event.Phase {
	case audit.PhaseDockerDiscovery:
		message = "Discovering running Docker containers"
	case audit.PhaseTargetsDiscovered:
		p.total = event.Total
		p.totalKnown = true
		// This count updates the next state line without interrupting the active work.
		return
	case audit.PhaseContainerInspect:
		message = "reading container configuration"
		p.startTarget(key, event.Target, now)
	case audit.PhaseTargetStarted:
		message = "starting scan"
		p.startTarget(key, event.Target, now)
	case audit.PhaseConfiguration:
		message = "discovering CA configuration"
	case audit.PhaseStores:
		message = fmt.Sprintf("reading CA files (%d/%d)", event.Completed, event.Total)
	case audit.PhaseClientDiscovery:
		message = "detecting " + event.Client
	case audit.PhasePositiveControl:
		message = "HTTPS positive control for " + event.Client
	case audit.PhaseTLS:
		message = fmt.Sprintf("checking %s (%d/%d chains processed)", event.Client, event.Completed, event.Total)
	case audit.PhaseTargetCompleted:
		if sample, ok := p.active[key]; ok && sample.kind == "container" {
			p.containerLongest = max(p.containerLongest, now.Sub(sample.started))
		}
		delete(p.active, key)
		p.completed++
		message = "target scan finished"
	case audit.PhaseTargetCanceled:
		delete(p.active, key)
		message = "target scan interrupted"
	default:
		return
	}
	p.message = progressText(message)
	p.target = progressText(target)
	if p.interactive {
		// Apply one rate limit across all workers and phases, including transitions.
		if now.Sub(p.lastDraw) >= 250*time.Millisecond {
			p.draw()
		}
		return
	}
	// In pipes/CI, log stage transitions instead of one line for every CA file.
	if p.lastLog[logKey] == "" {
		p.lastLog[logKey] = "shown"
		p.draw()
	}
}

func (p *scanProgress) startTarget(key string, target report.Target, now time.Time) {
	if _, exists := p.active[key]; !exists {
		p.active[key] = progressTarget{kind: target.Kind, started: now}
	}
}

// estimate deliberately favors generous estimates: twice the slowest completed
// container plus a buffer, expanded when active jobs take longer. Before samples
// exist it uses an initial budget. Host timings cannot predict container work.
// Without a discovered total the estimate covers active targets only.
func (p *scanProgress) estimate(now time.Time) (time.Duration, bool) {
	remaining := p.total - p.completed
	if !p.totalKnown {
		remaining = len(p.active)
		if remaining == 0 {
			return 0, false
		}
	}
	if remaining <= 0 {
		return 0, true
	}
	capacity := min(max(1, p.workers), remaining)
	if len(p.active) > capacity {
		return 0, false
	}
	initial := p.initialTargetTime
	if initial <= 0 {
		initial = time.Minute
	}
	const buffer = 10 * time.Second
	containerBudget := initial
	if p.containerLongest > 0 {
		containerBudget = 2*p.containerLongest + buffer
	}
	for _, target := range p.active {
		if target.kind == "container" {
			containerBudget = max(containerBudget, 2*max(0, now.Sub(target.started))+buffer)
		}
	}
	loads := make([]time.Duration, capacity)
	index := 0
	for _, target := range p.active {
		age := max(0, now.Sub(target.started))
		budget := containerBudget
		if target.kind != "container" {
			budget = max(initial, 2*age+buffer)
		}
		loads[index] = budget - age
		index++
	}
	for queued := remaining - len(p.active); queued > 0; queued-- {
		least := 0
		for i := range loads {
			if loads[i] < loads[least] {
				least = i
			}
		}
		loads[least] += containerBudget
	}
	var eta time.Duration
	for _, load := range loads {
		eta = max(eta, load)
	}
	return eta, true
}

func (p *scanProgress) draw() {
	now := time.Now()
	p.lastDraw = now
	counter := fmt.Sprintf("%d targets processed", p.completed)
	if p.totalKnown {
		counter = fmt.Sprintf("%d/%d targets processed", p.completed, p.total)
	}
	eta := "estimating"
	etaLabel := "ETA"
	if !p.totalKnown && len(p.active) > 0 {
		etaLabel = "target ETA"
	}
	if remaining, known := p.estimate(now); known {
		eta = "~" + ((remaining + time.Second - 1) / time.Second * time.Second).String()
	}
	if p.finalETA != "" {
		eta = p.finalETA
	}
	elapsed := now.Sub(p.start).Truncate(time.Second)
	prefix := fmt.Sprintf("[progress] %s | elapsed %6s | %s %10s", counter, elapsed, etaLabel, eta)
	width := 0
	if p.interactive {
		if f, ok := p.w.(*os.File); ok {
			width = terminalColumns(f) - 1 // avoid terminal autowrap at the last column
		}
		if width > 0 && width < 110 {
			counter = fmt.Sprintf("%d/?", p.completed)
			if p.totalKnown {
				counter = fmt.Sprintf("%d/%d", p.completed, p.total)
			}
			prefix = fmt.Sprintf("[progress] %s | %5s | %s %10s", counter, elapsed, etaLabel, eta)
		}
	}
	line := fitProgress(prefix, p.message, p.target, width)
	if p.interactive {
		fmt.Fprintf(p.w, "\r\x1b[2K%s", line)
	} else {
		fmt.Fprintln(p.w, line)
	}
}

// Keep the target last and retain counters/times when a narrow terminal needs a
// shorter stage description. Default target/client labels are ASCII; rune-based
// truncation also preserves UTF-8 for library-supplied labels.
func fitProgress(prefix, stage, target string, width int) string {
	if width > 0 && width < 20 {
		if target != "" {
			return clipProgress(target, width)
		}
		return clipProgress(stage, width)
	}
	if target == "" {
		return clipProgress(prefix+" | "+stage, width)
	}
	if width > 0 {
		target = clipProgress(target, max(8, width/3))
		room := width - len([]rune(prefix)) - len([]rune(target)) - 6
		if room < 4 {
			return clipProgress(prefix, width-len([]rune(target))-3) + " | " + target
		}
		stage = clipProgress(stage, room)
	}
	return prefix + " | " + stage + " | " + target
}

func clipProgress(text string, width int) string {
	if width <= 0 || len([]rune(text)) <= width {
		return text
	}
	return string([]rune(text)[:width-1]) + "…"
}

func (p *scanProgress) Close(scanErr error) {
	close(p.stop)
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.message == "" {
		return
	}
	p.message = "Scan finished"
	p.target = ""
	p.finalETA = "0s"
	if scanErr != nil {
		p.message = "Scan stopped before completion"
		p.finalETA = "n/a"
	}
	p.draw()
	if p.interactive {
		fmt.Fprintln(p.w)
	}
}

func colorEnabled(mode string, w io.Writer) (bool, error) {
	switch mode {
	case "auto":
		return os.Getenv("NO_COLOR") == "" && isTerminal(w), nil
	case "always":
		return true, nil
	case "never":
		return false, nil
	default:
		return false, fmt.Errorf("color must be auto, always or never")
	}
}
