package audit

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/andersundsehr/ca-trust-audit/internal/testcert"
	"github.com/andersundsehr/ca-trust-audit/pkg/probes"
)

// TestRealDockerShellless creates only disposable scratch images/containers of
// its own, with networking disabled and a read-only filesystem. No registry or
// privileged Docker access is needed. Existing containers are not changed.
func TestRealDockerShellless(t *testing.T) {
	if os.Getenv("CA_TRUST_AUDIT_DOCKER_TESTS") != "1" {
		t.Skip("set CA_TRUST_AUDIT_DOCKER_TESTS=1 for disposable shell-less Docker integration")
	}
	if _, e := exec.LookPath("docker"); e != nil {
		t.Skip("Docker CLI unavailable (test fixture creation only)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if e := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").Run(); e != nil {
		t.Skip("Docker daemon unavailable for optional integration")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "hold.go")
	binary := filepath.Join(dir, "hold")
	if e := os.WriteFile(source, []byte("package main\nimport \"time\"\nfunc main(){time.Sleep(24*time.Hour)}\n"), 0600); e != nil {
		t.Fatal(e)
	}
	build := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", binary, source)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("fixture helper build: %s %v", b, e)
	}
	executable, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	f := testcert.Make(t)
	unrelated := testcert.Make(t)
	stamp := fmt.Sprintf("%d", time.Now().UnixNano())
	var names []string
	for _, tc := range []struct {
		name   string
		bundle []byte
		vuln   bool
	}{{"vulnerable", testcert.PEM(f.Root), true}, {"corrected", testcert.PEM(unrelated.Root), false}} {
		tag := "ca-trust-audit-test-" + tc.name + ":" + stamp
		name := "ca-trust-audit-test-" + tc.name + "-" + stamp
		var rootfs bytes.Buffer
		tw := tar.NewWriter(&rootfs)
		for _, entry := range []struct {
			name string
			mode int64
			data []byte
		}{{"hold", 0755, executable}, {"etc/ssl/certs/ca-certificates.crt", 0644, tc.bundle}} {
			if e := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: entry.mode, Size: int64(len(entry.data)), Typeflag: tar.TypeReg}); e != nil {
				t.Fatal(e)
			}
			if _, e := tw.Write(entry.data); e != nil {
				t.Fatal(e)
			}
		}
		if e := tw.Close(); e != nil {
			t.Fatal(e)
		}
		cmd := exec.CommandContext(ctx, "docker", "import", "-", tag)
		cmd.Stdin = &rootfs
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("import fixture: %s %v", b, e)
		}
		t.Cleanup(func() {
			_ = exec.Command("docker", "rm", "-f", name).Run()
			_ = exec.Command("docker", "image", "rm", tag).Run()
		})
		cmd = exec.CommandContext(ctx, "docker", "run", "-d", "--name", name, "--network", "none", "--read-only", "--cap-drop", "ALL", tag, "/hold")
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("start fixture: %s %v", b, e)
		}
		names = append(names, name)
		result, e := Scan(ctx, Options{Container: name, Offline: true, Incident: &f.Incident, Probes: []probes.Probe{}})
		if e != nil {
			t.Fatal(e)
		}
		if result.Summary.Containers != 1 || (result.Summary.VulnerableStores > 0) != tc.vuln {
			t.Fatalf("%s: %+v", tc.name, result.Summary)
		}
		if result.Targets[0].Coverage.Complete {
			t.Fatal("shell-less offline scan claimed complete")
		}
	}
	// The default container discovery must see both independently and keep findings scoped.
	result, e := Scan(ctx, Options{ContainersOnly: true, Offline: true, Incident: &f.Incident, Probes: []probes.Probe{}})
	if e != nil {
		t.Fatal(e)
	}
	seen := 0
	for _, target := range result.Targets {
		for _, name := range names {
			if target.Target.Name == name {
				seen++
			}
		}
	}
	if seen != 2 {
		t.Fatal("running fixture container discovery incomplete")
	}
}
