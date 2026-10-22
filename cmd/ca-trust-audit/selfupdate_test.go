package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/andersundsehr/ca-trust-audit/internal/selfupdate"
)

func TestUpdateErrorCommands(t *testing.T) {
	err := selfupdate.ErrInstallLocation
	if got := updateErrorDetail(err, false); got != err.Error() || strings.Contains(got, "\x1b") {
		t.Fatalf("plain error changed: %q", got)
	}
	colored := updateErrorDetail(err, true)
	for _, command := range []string{"sudo ca-trust-audit self-update", "--install-dir"} {
		if !strings.Contains(colored, "\x1b[36m"+command+"\x1b[0m") {
			t.Fatalf("missing command highlighting: %q", colored)
		}
	}
	stripped := strings.NewReplacer("\x1b[36m", "", "\x1b[0m", "").Replace(colored)
	if stripped != err.Error() {
		t.Fatal("coloring changed the suggested commands")
	}
	if got := updateErrorDetail(fmt.Errorf("\x1b[31mcontext: %w", err), true); strings.Contains(got, "\x1b[31m") {
		t.Fatal("untrusted error escape survived sanitization")
	}
	if got := updateErrorDetail(errors.New("unrelated sudo ca-trust-audit self-update"), true); strings.Contains(got, "\x1b") {
		t.Fatal("arbitrary errors were treated as command suggestions")
	}
}
