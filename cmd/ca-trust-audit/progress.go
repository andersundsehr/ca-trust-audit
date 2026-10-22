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
)

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	s, e := f.Stat()
	return e == nil && s.Mode()&os.ModeCharDevice != 0 && os.Getenv("TERM") != "dumb"
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
	lastDraw         time.Time
	lastPhase        audit.Phase
	mu               sync.Mutex
	w                io.Writer
	interactive      bool
	start            time.Time
	message          string
	completed, total int
	lastLog          map[string]string
	stop, done       chan struct{}
}

func newScanProgress(w io.Writer, interactive bool) *scanProgress {
	p := &scanProgress{w: w, interactive: interactive, start: time.Now(), lastLog: map[string]string{}, stop: make(chan struct{}), done: make(chan struct{})}
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
				if p.interactive && p.message != "" {
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
	message := ""
	logKey := key + ":" + string(event.Phase) + ":" + event.Client
	switch event.Phase {
	case audit.PhaseDockerDiscovery:
		message = "Discovering running Docker containers"
	case audit.PhaseTargetsDiscovered:
		p.total = event.Total
		// This count updates the next state line without interrupting the active work.
		return
	case audit.PhaseContainerInspect:
		message = target + ": reading container configuration"
	case audit.PhaseTargetStarted:
		message = target + ": starting scan"
	case audit.PhaseConfiguration:
		message = target + ": discovering CA configuration"
	case audit.PhaseStores:
		message = fmt.Sprintf("%s: reading CA files (%d/%d)", target, event.Completed, event.Total)
	case audit.PhaseClientDiscovery:
		message = target + ": detecting " + event.Client
	case audit.PhasePositiveControl:
		message = target + ": HTTPS positive control for " + event.Client
	case audit.PhaseTLS:
		message = fmt.Sprintf("%s: checking %s (%d/%d chains processed)", target, event.Client, event.Completed, event.Total)
	case audit.PhaseTargetCompleted:
		p.completed++
		message = target + ": scan finished"
	case audit.PhaseTargetCanceled:
		message = target + ": scan interrupted"
	default:
		return
	}
	p.message = progressText(message)
	if p.interactive {
		if event.Phase != p.lastPhase || time.Since(p.lastDraw) >= 100*time.Millisecond {
			p.draw()
		}
		p.lastPhase = event.Phase
		return
	}
	// In pipes/CI, log stage transitions instead of one line for every CA file.
	if p.lastLog[logKey] == "" {
		p.lastLog[logKey] = "shown"
		p.draw()
	}
}
func (p *scanProgress) draw() {
	p.lastDraw = time.Now()
	counter := fmt.Sprintf("%d targets processed", p.completed)
	if p.total > 0 {
		counter = fmt.Sprintf("%d/%d targets processed", p.completed, p.total)
	}
	line := fmt.Sprintf("[progress] %s | %s | elapsed %s", p.message, counter, time.Since(p.start).Truncate(time.Second))
	if p.interactive {
		fmt.Fprintf(p.w, "\r\x1b[2K%s", line)
	} else {
		fmt.Fprintln(p.w, line)
	}
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
	if scanErr != nil {
		p.message = "Scan stopped before completion"
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
