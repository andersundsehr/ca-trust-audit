package probes

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andersundsehr/ca-trust-audit/internal/testcert"
	"github.com/andersundsehr/ca-trust-audit/pkg/certificates"
	"github.com/andersundsehr/ca-trust-audit/pkg/report"
)

func TestNativeTLS(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer s.Close()
	p := Native{Transport: s.Client().Transport.(*http.Transport)}
	got := p.Check(context.Background(), nil, s.URL)
	if got.Status != report.VulnerableClient || got.LeafSHA256 == "" {
		t.Fatalf("TLS acceptance even with HTTP 503: %+v", got)
	}
	// A substituted, legitimately trusted certificate must not confirm the incident.
	f := testcert.Make(t)
	finding := EvidenceFor(got, f.Chain, p.Name())
	if finding.Status != report.Inconclusive {
		t.Fatalf("proxy/rotation accepted: %+v", finding)
	}
	got = Native{}.Check(context.Background(), nil, s.URL)
	if got.Status != report.Rejected {
		t.Fatalf("untrusted peer=%+v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got = p.Check(ctx, nil, s.URL)
	if got.Status != report.Inconclusive {
		t.Fatal("canceled request classified as trustworthy", got)
	}
}
func TestNativeTimeoutAndDNS(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	r := Native{}.Check(ctx, nil, s.URL)
	if r.Status != report.Inconclusive || r.Category != "timeout" {
		t.Fatalf("%+v", r)
	}
	tr := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "synthetic.invalid", IsNotFound: true}
	}}
	got := (Native{Transport: tr}).Check(context.Background(), nil, "https://synthetic.invalid/")
	if got.Status != report.Inconclusive || got.Category != "dns" {
		t.Fatalf("%+v", got)
	}
}
func TestProtocol(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	cases := []struct {
		input string
		want  report.Status
	}{
		{"CTA1 ACCEPT " + hash, report.VulnerableClient},
		{"CTA1 REJECT certificate_validation", report.Rejected},
		{"CTA1 ERROR dns", report.Inconclusive}, {"CTA1 ERROR timeout", report.Inconclusive},
		{"CTA1 REJECT dns", report.Inconclusive}, {"warning\nCTA1 ACCEPT " + hash, report.Inconclusive},
		{"CTA1 ACCEPT xxx", report.Inconclusive}, {"", report.Inconclusive},
	}
	for _, c := range cases {
		if r := ParseResult(c.input); r.Status != c.want {
			t.Fatalf("%q -> %+v", c.input, r)
		}
	}
}
func TestCurlProtocol(t *testing.T) {
	f := testcert.Make(t)
	r := ParseCurl(append([]byte("\nCTA_CURL 0 200\n"), testcert.PEM(f.Leaf)...))
	if r.Status != report.VulnerableClient || r.LeafSHA256 != certificates.SHA256(f.Leaf.Raw) {
		t.Fatalf("%+v", r)
	}
	for _, c := range []struct {
		code string
		want report.Status
		cat  string
	}{{"60", report.Rejected, "certificate_validation"}, {"6", report.Inconclusive, "dns"}, {"28", report.Inconclusive, "timeout"}, {"7", report.Inconclusive, "connection_or_proxy"}} {
		r := ParseCurl([]byte("\nCTA_CURL " + c.code + " 000\n"))
		if r.Status != c.want || r.Category != c.cat {
			t.Fatalf("%+v", r)
		}
	}
	if ParseCurl([]byte("curl: unknown variable certs")).Status != report.NotSupported {
		t.Fatal("old curl not marked unsupported")
	}
}
func TestPinnedEvidence(t *testing.T) {
	f := testcert.Make(t)
	r := Result{Status: report.VulnerableClient, LeafSHA256: certificates.SHA256(f.Leaf.Raw)}
	if got := EvidenceFor(r, f.Chain, "synthetic"); got.Status != report.VulnerableClient {
		t.Fatal(got)
	}
	r.LeafSHA256 = certificates.SHA256(f.Root.Raw)
	if got := EvidenceFor(r, f.Chain, "synthetic"); got.Status != report.Inconclusive {
		t.Fatal(got)
	}
}
func TestMissingExecutable(t *testing.T) {
	_, e := (HostRunner{}).Run(context.Background(), "ca-trust-audit-definitely-absent")
	if e == nil {
		t.Fatal("missing command succeeded")
	}
}

// TestInstalledRuntimeTLS uses a loopback HTTPS server and public test certificate.
// Each installed runtime must accept the trusted peer and reject it with unrelated
// roots; absent optional runtimes are explicitly skipped, never counted as passes.
func TestInstalledRuntimeTLS(t *testing.T) {
	if os.Getenv("CA_TRUST_AUDIT_RUNTIME_TESTS") != "1" {
		t.Skip("set CA_TRUST_AUDIT_RUNTIME_TESTS=1 to exercise installed clients against loopback TLS")
	}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		w.WriteHeader(204)
	}))
	defer s.Close()
	dir := t.TempDir()
	bundle := filepath.Join(dir, "ca.pem")
	if e := os.WriteFile(bundle, testcert.PEM(s.Certificate()), 0600); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"} {
		t.Setenv(name, bundle)
	}
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	t.Setenv("no_proxy", "127.0.0.1,localhost")
	for _, p := range Defaults() {
		t.Run(p.Name(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			runner := HostRunner{}
			// PHP's libcurl extension does not consume the curl executable's
			// CURL_CA_BUNDLE environment setting. Configure the same public test
			// CA through CLI ini settings for these ephemeral fixture processes.
			if script, ok := p.(Script); ok && script.Executable == "php" {
				script.Prefix = []string{"-d", "openssl.cafile=" + bundle, "-d", "curl.cainfo=" + bundle, "-r"}
				p = script
			}
			if !p.Discover(ctx, runner) {
				t.Skip("optional runtime/module not installed")
			}
			r := p.Check(ctx, runner, s.URL)
			if r.Status == report.NotSupported {
				t.Skip("installed curl lacks peer certificate introspection")
			}
			if r.Status != report.VulnerableClient || r.LeafSHA256 != certificates.SHA256(s.Certificate().Raw) {
				t.Fatalf("trusted peer: %+v", r)
			}
			unrelated := testcert.Make(t)
			if e := os.WriteFile(bundle, testcert.PEM(unrelated.Root), 0600); e != nil {
				t.Fatal(e)
			}
			rejected := p.Check(ctx, runner, s.URL)
			if e := os.WriteFile(bundle, testcert.PEM(s.Certificate()), 0600); e != nil {
				t.Fatal(e)
			}
			if rejected.Status != report.Rejected {
				t.Fatalf("untrusted peer: %+v", rejected)
			}
		})
	}
}
