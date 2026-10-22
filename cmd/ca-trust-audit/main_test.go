package main

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestCLIErrorsAndVersion(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want int
	}{{[]string{"--version"}, 0}, {[]string{"--help"}, 0}, {[]string{"--unknown"}, 2}, {[]string{"extra"}, 2}, {[]string{"--host-only", "--containers-only"}, 2}, {[]string{"--workers", "0", "--timeout", "-1s"}, 2}, {[]string{"self-update", "--help"}, 0}, {[]string{"selfupdate", "--help"}, 0}, {[]string{"self-update", "extra"}, 2}, {[]string{"self-update", "--check", "--force"}, 2}, {[]string{"self-update", "--timeout", "0"}, 2}} {
		var out, err bytes.Buffer
		got := run(context.Background(), tc.args, &out, &err)
		if got != tc.want {
			t.Fatalf("%v exit=%d err=%s", tc.args, got, err.String())
		}
	}
}

func TestHostAliasAndWorkerHelp(t *testing.T) {
	for _, selector := range []string{"--host", "--host-only"} {
		for _, conflict := range []string{"--containers-only", "--container=webapp"} {
			var out, errout bytes.Buffer
			if code := run(context.Background(), []string{selector, conflict}, &out, &errout); code != 2 || out.Len() != 0 {
				t.Fatalf("%s %s: exit=%d stdout=%q stderr=%q", selector, conflict, code, out.String(), errout.String())
			}
		}
	}
	var out, errout bytes.Buffer
	if code := run(context.Background(), []string{"--help"}, &out, &errout); code != 0 {
		t.Fatal(code)
	}
	for _, text := range []string{"-host", "alias for --host-only", "maximum concurrent container scans", fmt.Sprintf("(default %d)", runtime.NumCPU())} {
		if !strings.Contains(errout.String(), text) {
			t.Fatalf("missing help %q: %s", text, errout.String())
		}
	}
}
