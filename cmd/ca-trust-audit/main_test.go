package main

import (
	"bytes"
	"context"
	"testing"
)

func TestCLIErrorsAndVersion(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want int
	}{{[]string{"--version"}, 0}, {[]string{"--help"}, 0}, {[]string{"--unknown"}, 2}, {[]string{"extra"}, 2}, {[]string{"--host-only", "--containers-only"}, 2}, {[]string{"--workers", "0", "--timeout", "-1s"}, 2}} {
		var out, err bytes.Buffer
		got := run(context.Background(), tc.args, &out, &err)
		if got != tc.want {
			t.Fatalf("%v exit=%d err=%s", tc.args, got, err.String())
		}
	}
}
