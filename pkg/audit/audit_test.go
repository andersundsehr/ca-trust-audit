package audit

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/andersundsehr/ca-trust-audit/internal/testcert"
	"github.com/andersundsehr/ca-trust-audit/pkg/certificates"
	"github.com/andersundsehr/ca-trust-audit/pkg/probes"
	"github.com/andersundsehr/ca-trust-audit/pkg/report"
)

type memoryFiles struct {
	data map[string][]byte
	fail map[string]error
}

func (m memoryFiles) ReadFile(_ context.Context, p string) ([]byte, error) {
	if e := m.fail[p]; e != nil {
		return nil, e
	}
	if b, ok := m.data[p]; ok {
		return b, nil
	}
	return nil, fs.ErrNotExist
}
func (m memoryFiles) CAFiles(context.Context, string) ([]string, error) { return nil, fs.ErrNotExist }

type missingRunner struct{}

func (missingRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return nil, errors.New("command missing")
}
func countStatus(t report.TargetReport, s report.Status) int {
	n := 0
	for _, f := range t.Findings {
		if f.Status == s {
			n++
		}
	}
	return n
}
func TestOfflineStores(t *testing.T) {
	f := testcert.Make(t)
	path := "/etc/ssl/cert.pem"
	for _, tc := range []struct {
		name       string
		data       []byte
		fail       error
		vulnerable bool
		stores     int
	}{
		{"vulnerable", testcert.PEM(f.Root), nil, true, 1},
		{"corrected unrelated root", testcert.PEM(testcert.Make(t).Root), nil, false, 1},
		{"malformed", []byte("-----BEGIN CERTIFICATE-----"), nil, false, 0},
		{"empty", []byte{}, nil, false, 0},
		{"missing", nil, fs.ErrNotExist, false, 0},
		{"inaccessible", nil, fs.ErrPermission, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := ScanTarget(context.Background(), report.Target{Kind: "container", Name: "distroless"}, memoryFiles{data: map[string][]byte{path: tc.data}, fail: map[string]error{path: tc.fail}}, missingRunner{}, nil, f.Incident, Options{Offline: true, Probes: []probes.Probe{}})
			if (countStatus(out, report.VulnerableStore) > 0) != tc.vulnerable || out.Coverage.Stores != tc.stores {
				t.Fatalf("unexpected result: %+v", out)
			}
			if out.Coverage.Complete {
				t.Fatal("offline/shell-less coverage claimed complete")
			}
			b, e := json.Marshal(out)
			if e != nil || !json.Valid(b) {
				t.Fatal("JSON", e)
			}
		})
	}
}

type fakeProbe struct{ control, incident probes.Result }

func (fakeProbe) Name() string                                 { return "synthetic client" }
func (fakeProbe) Discover(context.Context, probes.Runner) bool { return true }
func (p fakeProbe) Check(_ context.Context, _ probes.Runner, url string) probes.Result {
	if strings.Contains(url, "control.invalid") {
		return p.control
	}
	return p.incident
}
func TestPositiveControlAndClientSeparation(t *testing.T) {
	f := testcert.Make(t)
	accept := probes.Result{Status: report.VulnerableClient, LeafSHA256: certificates.SHA256(f.Leaf.Raw)}
	for _, tc := range []struct {
		name    string
		control probes.Result
		want    report.Status
	}{
		{"working", accept, report.VulnerableClient},
		{"DNS is not safety", probes.Result{Status: report.Inconclusive, Category: "dns"}, report.Inconclusive},
		{"control TLS failure", probes.Result{Status: report.Rejected, Category: "certificate_validation"}, report.Inconclusive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := ScanTarget(context.Background(), report.Target{Kind: "container"}, memoryFiles{}, missingRunner{}, nil, f.Incident, Options{PositiveControl: "https://control.invalid/", Probes: []probes.Probe{fakeProbe{tc.control, accept}}})
			if countStatus(out, tc.want) != 2 {
				t.Fatalf("%+v", out.Findings)
			}
			if countStatus(out, report.VulnerableStore) != 0 {
				t.Fatal("live evidence confused with stores")
			}
		})
	}
}
func TestHostFileLimits(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bundle.pem")
	if e := os.WriteFile(p, []byte("public cert data"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := (HostFiles{}).ReadFile(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	if _, e := (HostFiles{}).ReadFile(context.Background(), dir); e == nil {
		t.Fatal("directory read accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := (HostFiles{}).ReadFile(ctx, p); e == nil {
		t.Fatal("cancellation ignored")
	}
}
func TestOptions(t *testing.T) {
	for _, o := range []Options{{Workers: -1}, {Timeout: -time.Second}, {HostOnly: true, ContainersOnly: true}, {PositiveControl: "http://insecure.invalid"}, {CAPaths: []string{"relative"}}} {
		if normalize(&o) == nil {
			t.Fatal("invalid options accepted", o)
		}
	}
}

func TestWorkerDefaultsAndOverrides(t *testing.T) {
	for _, tc := range []struct{ requested, want int }{{0, runtime.NumCPU()}, {1, 1}, {4, 4}, {128, 128}} {
		o := Options{Workers: tc.requested}
		if err := normalize(&o); err != nil || o.Workers != tc.want {
			t.Fatalf("workers=%d: got %d, want %d: %v", tc.requested, o.Workers, tc.want, err)
		}
	}
}
func TestMaterialIsOnlyPotential(t *testing.T) {
	f := testcert.Make(t)
	findings := materialFindings([]*x509.Certificate{f.Intermediate}, "/bundle", f.Incident)
	if len(findings) != 1 || findings[0].Status != report.Potential {
		t.Fatal(findings)
	}
}
