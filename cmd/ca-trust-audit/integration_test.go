package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/andersundsehr/ca-trust-audit/pkg/audit"
	"github.com/andersundsehr/ca-trust-audit/pkg/report"
)

// TestPHP85CLI exercises the standalone executable, not only the audit API or
// renderer. The image CA stores remain unmodified. A separate read-only test
// bundle is selected explicitly only for the deliberately trusting store case.
func TestPHP85CLI(t *testing.T) {
	if os.Getenv("CA_TRUST_AUDIT_PHP_IMAGE_TESTS") != "1" {
		t.Skip("enable CA_TRUST_AUDIT_PHP_IMAGE_TESTS after pulling webdevops/php-apache:8.5-alpine")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const image = "webdevops/php-apache:8.5-alpine"
	if e := exec.CommandContext(ctx, "docker", "image", "inspect", image).Run(); e != nil {
		t.Fatal("pull the PHP image before enabling this integration test")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "ca-trust-audit")
	build := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-trimpath", "-o", binary, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build standalone CLI: %v\n%s", e, b)
	}
	incident, e := audit.DefaultIncident()
	if e != nil {
		t.Fatal(e)
	}
	var trusting bytes.Buffer
	for _, root := range incident.Roots {
		trusting.WriteString(root.PEM)
		trusting.WriteByte('\n')
	}
	trustingPath := filepath.Join(dir, "deliberately-trusting-public-roots.pem")
	if e := os.WriteFile(trustingPath, trusting.Bytes(), 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(trustingPath, 0644); e != nil {
		t.Fatal(e)
	}
	name := "ca-trust-audit-cli-" + time.Now().Format("20060102150405.000000000")
	const secretMarker = "dummy-private-value-must-not-appear-in-report"
	create := exec.CommandContext(ctx, "docker", "run", "-d", "--name", name, "--read-only", "--network", "none", "--cap-drop", "ALL", "--mount", "type=bind,src="+trustingPath+",dst=/fixture/incident-roots.pem,readonly", "-e", "CA_AUDIT_TEST_SECRET="+secretMarker, "--entrypoint", "php", image, "-r", "sleep(180);")
	if b, e := create.CombinedOutput(); e != nil {
		t.Fatalf("create CLI fixture: %v\n%s", e, b)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if e := exec.CommandContext(cleanup, "docker", "rm", "-f", name).Run(); e != nil {
			t.Errorf("remove test container: %v", e)
		}
	})
	invoke := func(t *testing.T, args ...string) ([]byte, []byte, int) {
		t.Helper()
		cmd := exec.CommandContext(ctx, binary, args...)
		var out, errout bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &errout
		e := cmd.Run()
		status := 0
		if e != nil {
			var exit *exec.ExitError
			if !errors.As(e, &exit) {
				t.Fatal(e)
			}
			status = exit.ExitCode()
		}
		if bytes.Contains(out.Bytes(), []byte(secretMarker)) || bytes.Contains(errout.Bytes(), []byte(secretMarker)) {
			t.Fatal("fixture environment secret leaked into CLI output")
		}
		return out.Bytes(), errout.Bytes(), status
	}
	checkReport := func(t *testing.T, b []byte) report.Report {
		t.Helper()
		if bytes.Contains(b, []byte(secretMarker)) {
			t.Fatal("fixture environment secret leaked into JSON")
		}
		var r report.Report
		d := json.NewDecoder(bytes.NewReader(b))
		if e := d.Decode(&r); e != nil {
			t.Fatal("invalid JSON", e)
		}
		var trailing any
		if e := d.Decode(&trailing); e != io.EOF {
			t.Fatalf("JSON stdout contains extra output: %v", e)
		}
		if r.SchemaVersion != "1.0" || len(r.Targets) != 1 || r.Summary.Containers != 1 || r.Summary.Hosts != 0 {
			t.Fatalf("wrong target/schema: %+v", r.Summary)
		}
		target := r.Targets[0]
		if target.Target.Name != name || target.Target.Image != image {
			t.Fatal("wrong container identity", target.Target)
		}
		if target.Coverage.Complete {
			t.Fatal("offline CLI claimed complete live coverage")
		}
		found := false
		for _, s := range target.TrustStores {
			if s.Path == "/etc/ssl/certs/ca-certificates.crt" {
				found = true
				if s.Status != report.Rejected || s.Rejected != 14 || s.Accepted != 0 {
					t.Fatalf("standard PHP bundle: %+v", s)
				}
			}
		}
		if !found {
			t.Fatal("standard CA bundle missing from JSON")
		}
		return r
	}
	t.Run("JSON stdout", func(t *testing.T) {
		out, errout, code := invoke(t, "--container", name, "--offline", "--json", "-")
		if code != 0 || len(errout) != 0 {
			t.Fatalf("exit=%d stderr=%s", code, errout)
		}
		checkReport(t, out)
	})
	t.Run("English terminal and protected JSON file", func(t *testing.T) {
		path := filepath.Join(dir, "report.json")
		out, errout, code := invoke(t, "--container", name, "--offline", "--json", path)
		if code != 0 || len(errout) != 0 {
			t.Fatalf("exit=%d stderr=%s", code, errout)
		}
		for _, text := range []string{"CA FILES: PASSED", "LIVE CLIENTS: NOT VERIFIED", "14/14 chains rejected", "Coverage: PARTIAL"} {
			if !strings.Contains(string(out), text) {
				t.Fatalf("missing %q in terminal: %s", text, out)
			}
		}
		if bytes.Contains(out, []byte("VULNERABLE_STORE")) || bytes.Contains(out, []byte("INCONCLUSIVE")) {
			t.Fatal("machine statuses leaked into administrator wording")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		checkReport(t, b)
		stat, e := os.Stat(path)
		if e != nil || stat.Mode().Perm() != 0600 {
			t.Fatalf("report mode must be 0600: %v %v", stat, e)
		}
		_, _, code = invoke(t, "--container", name, "--offline", "--json", path)
		if code != 2 {
			t.Fatalf("existing report exit=%d, want 2", code)
		}
		after, e := os.ReadFile(path)
		if e != nil || !bytes.Equal(b, after) {
			t.Fatal("existing JSON report was changed", e)
		}
	})
	t.Run("Strict incomplete coverage", func(t *testing.T) {
		out, errout, code := invoke(t, "--container", name, "--offline", "--strict", "--json", "-")
		if code != 3 || len(errout) != 0 {
			t.Fatalf("strict exit=%d stderr=%s", code, errout)
		}
		checkReport(t, out)
	})
	t.Run("Problem and vulnerability exit precedence", func(t *testing.T) {
		path := filepath.Join(dir, "problem.json")
		out, errout, code := invoke(t, "--container", name, "--offline", "--strict", "--ca-file", "/fixture/incident-roots.pem", "--json", path)
		if code != 1 || len(errout) != 0 {
			t.Fatalf("confirmed store problem must exit 1 despite strict incomplete coverage: exit=%d stderr=%s", code, errout)
		}
		if !bytes.Contains(out, []byte("CA FILES: PROBLEM")) {
			t.Fatalf("missing problem wording: %s", out)
		}
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		r := checkReport(t, b)
		if r.Summary.VulnerableStores != 1 || r.Summary.VulnerableClients != 0 {
			t.Fatalf("store and live evidence mixed: %+v", r.Summary)
		}
		found := false
		for _, store := range r.Targets[0].TrustStores {
			if store.Path == "/fixture/incident-roots.pem" {
				found = true
				if store.Status != report.VulnerableStore || store.Accepted != 14 {
					t.Fatalf("deliberately trusting store: %+v", store)
				}
			}
		}
		if !found {
			t.Fatal("explicit test bundle absent from report")
		}
	})

}
