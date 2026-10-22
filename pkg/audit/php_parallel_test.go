package audit

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andersundsehr/ca-trust-audit/internal/testcert"
	"github.com/andersundsehr/ca-trust-audit/pkg/docker"
	"github.com/andersundsehr/ca-trust-audit/pkg/probes"
	"github.com/andersundsehr/ca-trust-audit/pkg/report"
)

// Prove that the engine actually overlaps verified TLS requests executed through
// Docker, rather than only overlapping fake probes or scheduling goroutines.
func TestPHP85ParallelChains(t *testing.T) {
	if os.Getenv("CA_TRUST_AUDIT_PHP_IMAGE_TESTS") != "1" {
		t.Skip("enable CA_TRUST_AUDIT_PHP_IMAGE_TESTS after pulling webdevops/php-apache:8.5-alpine")
	}
	const image = "webdevops/php-apache:8.5-alpine"
	const workers = 4
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := exec.CommandContext(ctx, "docker", "image", "inspect", image).Run(); err != nil {
		t.Fatal("pull the requested PHP image before enabling this test")
	}
	fixture := testcert.Make(t)
	var active, peak, requests atomic.Int32
	var ready sync.Once
	firstBatch := make(chan struct{})
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/control" {
			requests.Add(1)
			n := active.Add(1)
			defer active.Add(-1)
			for old := peak.Load(); n > old; old = peak.Load() {
				if peak.CompareAndSwap(old, n) {
					break
				}
			}
			if n == workers {
				ready.Do(func() { close(firstBatch) })
			}
			select {
			case <-firstBatch:
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	s.Listener.Close()
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	s.Listener = listener
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{fixture.Leaf.Raw, fixture.Intermediate.Raw}, PrivateKey: fixture.LeafKey}}}
	s.StartTLS()
	defer s.Close()
	host := fmt.Sprintf("tls-fixture.test:%d", listener.Addr().(*net.TCPAddr).Port)
	incident := fixture.Incident
	incident.Chains = nil
	for i := 0; i < 14; i++ {
		chain := fixture.Chain
		chain.ID, chain.Host = fmt.Sprintf("synthetic-%02d", i), host
		incident.Chains = append(incident.Chains, chain)
	}
	bundle := filepath.Join(t.TempDir(), "public-test-ca.pem")
	if err := os.WriteFile(bundle, testcert.PEM(fixture.Root), 0644); err != nil {
		t.Fatal(err)
	}
	// The environment may use umask 077; the image's runtime user still needs
	// read access to this public CA fixture, as in the other PHP integration test.
	if err := os.Chmod(bundle, 0644); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("ca-trust-audit-php-parallel-%d", time.Now().UnixNano())
	args := []string{"run", "-d", "--name", name, "--read-only", "--cap-drop", "ALL", "--add-host", "tls-fixture.test:host-gateway", "--mount", "type=bind,src=" + bundle + ",dst=/fixture/ca.pem,readonly", "-e", "NO_PROXY=tls-fixture.test", "-e", "no_proxy=tls-fixture.test", "--entrypoint", "php", image, "-r", "sleep(120);"}
	if b, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("create fixture: %v %s", err, b)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := exec.CommandContext(cleanup, "docker", "rm", "-f", name).Run(); err != nil {
			t.Error("remove fixture container", err)
		}
	})
	client, err := docker.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, probe := range probes.Defaults() {
		if probe.Name() != "PHP cURL" {
			continue
		}
		script := probe.(probes.Script)
		// Only these transient processes select a read-only public fixture CA.
		script.Prefix = []string{"-d", "curl.cainfo=/fixture/ca.pem", "-r"}
		result := ScanTarget(ctx, report.Target{Kind: "container", Name: name, ID: name, Image: image}, containerFiles{client, name}, docker.Runner{Client: client, ID: name}, nil, incident, Options{Workers: workers, PositiveControl: "https://" + host + "/control", Probes: []probes.Probe{script}})
		if peak.Load() != workers || requests.Load() != 14 || countStatus(result, report.VulnerableClient) != 14 {
			t.Fatalf("peak=%d requests=%d accepted=%d; expected %d overlapping verified requests and all 14 pinned chains; coverage=%+v", peak.Load(), requests.Load(), countStatus(result, report.VulnerableClient), workers, result.Coverage)
		}
		t.Logf("%s: %d concurrent verified TLS requests; %d/14 synthetic chains correctly identified as VULNERABLE_CLIENT", image, peak.Load(), countStatus(result, report.VulnerableClient))
		return
	}
	t.Fatal("built-in PHP cURL probe missing")
}
