package probes_test

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
	"testing"
	"time"

	"github.com/andersundsehr/ca-trust-audit/internal/incidents/emudhra"
	"github.com/andersundsehr/ca-trust-audit/internal/testcert"
	"github.com/andersundsehr/ca-trust-audit/pkg/certificates"
	"github.com/andersundsehr/ca-trust-audit/pkg/docker"
	"github.com/andersundsehr/ca-trust-audit/pkg/probes"
	"github.com/andersundsehr/ca-trust-audit/pkg/report"
)

// TestPHP85Image checks the user's representative PHP image without network
// endpoints. The image must be pulled explicitly; ordinary tests never pull it.
func TestPHP85Image(t *testing.T) {
	if os.Getenv("CA_TRUST_AUDIT_PHP_IMAGE_TESTS") != "1" {
		t.Skip("set CA_TRUST_AUDIT_PHP_IMAGE_TESTS=1 after pulling webdevops/php-apache:8.5-alpine")
	}
	const image = "webdevops/php-apache:8.5-alpine"
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if e := exec.CommandContext(ctx, "docker", "image", "inspect", image).Run(); e != nil {
		t.Fatal("pull the requested PHP image first")
	}
	fixture := testcert.Make(t)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	s.Listener.Close()
	listener, e := net.Listen("tcp", "0.0.0.0:0")
	if e != nil {
		t.Fatal(e)
	}
	s.Listener = listener
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{fixture.Leaf.Raw, fixture.Intermediate.Raw}, PrivateKey: fixture.LeafKey}}}
	s.StartTLS()
	defer s.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	endpoint := fmt.Sprintf("https://tls-fixture.test:%d/", port)
	dir := t.TempDir()
	bundle := filepath.Join(dir, "public-test-ca.pem")
	if e := os.WriteFile(bundle, testcert.PEM(fixture.Root), 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(bundle, 0644); e != nil {
		t.Fatal(e)
	}
	name := fmt.Sprintf("ca-trust-audit-php85-tls-%d", time.Now().UnixNano())
	args := []string{"run", "-d", "--name", name, "--read-only", "--cap-drop", "ALL", "--add-host", "tls-fixture.test:host-gateway", "--mount", "type=bind,src=" + bundle + ",dst=/fixture/ca.pem,readonly", "-e", "SSL_CERT_FILE=/fixture/ca.pem", "-e", "CURL_CA_BUNDLE=/fixture/ca.pem", "-e", "NO_PROXY=tls-fixture.test", "-e", "no_proxy=tls-fixture.test", "--entrypoint", "php", image, "-r", "sleep(120);"}
	if b, e := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); e != nil {
		t.Fatalf("create fixture: %s %v", b, e)
	}
	defer exec.Command("docker", "rm", "-f", name).Run()
	client, e := docker.New(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	runner := docker.Runner{Client: client, ID: name}
	publicBundle, e := client.ReadFile(ctx, name, "/etc/ssl/certs/ca-certificates.crt")
	if e != nil {
		t.Fatal(e)
	}
	roots, e := certificates.ParsePEM(publicBundle)
	if e != nil {
		t.Fatal(e)
	}
	incident, e := emudhra.Load()
	if e != nil {
		t.Fatal(e)
	}
	rejectedCount := 0
	for _, chain := range incident.Chains {
		_, e := certificates.Evaluate(chain, roots, certificates.Policy{Time: time.Date(2026, 10, 22, 16, 0, 0, 0, time.UTC)})
		if e == nil {
			t.Fatalf("image's standard bundle accepts published chain %s", chain.ID)
		}
		if certificates.RejectionCategory(e) != "untrusted_issuer" {
			t.Fatalf("unexpected rejection reason: %v", e)
		}
		rejectedCount++
	}
	t.Logf("image standard CA bundle: REJECTED %d/%d actual published eMudhra chains (untrusted issuer)", rejectedCount, len(incident.Chains))

	for _, p := range probes.Defaults() {
		script, ok := p.(probes.Script)
		if !ok || script.Executable != "php" {
			continue
		}
		t.Run(p.Name(), func(t *testing.T) {
			if !p.Discover(ctx, runner) {
				t.Fatal("required PHP extension missing in requested image")
			}
			// The test fixture configures only these ephemeral CLI processes, with
			// read-only public fixture files; no target ini or trust store is changed.
			script.Prefix = []string{"-d", "openssl.cafile=/fixture/ca.pem", "-d", "curl.cainfo=/fixture/ca.pem", "-r"}
			accepted := script.Check(ctx, runner, endpoint)
			if accepted.Status != report.VulnerableClient || accepted.LeafSHA256 != certificates.SHA256(fixture.Leaf.Raw) {
				t.Fatalf("trusted synthetic chain: %+v", accepted)
			}
			t.Logf("trusted synthetic compromised chain: %s; pinned leaf matched", accepted.Status)
			// Select the image's unmodified system roots, which lack our synthetic root.
			script.Prefix = []string{"-d", "openssl.cafile=/etc/ssl/certs/ca-certificates.crt", "-d", "curl.cainfo=/etc/ssl/certs/ca-certificates.crt", "-r"}
			rejected := script.Check(ctx, runner, endpoint)
			if rejected.Status != report.Rejected {
				t.Fatalf("corrected system store: %+v", rejected)
			}
			t.Logf("unmodified system store rejecting synthetic chain: %s (%s)", rejected.Status, rejected.Category)
		})
	}
}
