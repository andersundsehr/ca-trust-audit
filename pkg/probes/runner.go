// Package probes executes bounded, non-destructive runtime probes. Installed
// runtimes execute their own initialization; see the README security limitations.
package probes

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"sync"
	"time"
)

const MaxOutput = 1 << 20

// Runner is also implemented by Docker. Arguments are passed directly, without a shell.
type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type HostRunner struct{}
type limitBuffer struct {
	mu       sync.Mutex
	b        bytes.Buffer
	overflow bool
}

func (b *limitBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	left := MaxOutput - b.b.Len()
	if len(p) > left {
		p = p[:left]
		b.overflow = true
	}
	_, _ = b.b.Write(p)
	return n, nil
}
func (HostRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out limitBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if out.overflow {
		return nil, errors.New("runtime output exceeded limit")
	}
	return out.b.Bytes(), err
}

// Exists probes a command using a harmless version or import command. Output is
// discarded and never copied into the report (which might otherwise leak secrets).
func Exists(ctx context.Context, r Runner, name string, args ...string) bool {
	_, err := r.Run(ctx, name, args...)
	return err == nil
}
