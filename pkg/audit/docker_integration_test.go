package audit

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andersundsehr/ca-trust-audit/internal/testcert"
	"github.com/andersundsehr/ca-trust-audit/pkg/probes"
	"github.com/andersundsehr/ca-trust-audit/pkg/report"
)

// Deterministic Engine API integration: two independently scoped shell-less
// containers, one accepting a synthetic incident and one with unrelated roots.
func TestMultipleShelllessContainers(t *testing.T) {
	vulnerable, corrected := testcert.Make(t), testcert.Make(t)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/containers/json") {
			if r.URL.Query().Get("all") != "false" {
				t.Error("stopped containers included")
			}
			_, _ = w.Write([]byte(`[{"Id":"bad","Names":["/web"],"Image":"scratch:test"},{"Id":"good","Names":["/worker"],"Image":"distroless:test"}]`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/json") {
			_ = json.NewEncoder(w).Encode(map[string]any{"Config": map[string]any{"Env": []string{"SECRET=not-for-reports"}}})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/exec") {
			http.NotFound(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/archive") && r.URL.Query().Get("path") == "/etc/ssl/certs/ca-certificates.crt" {
			data := testcert.PEM(corrected.Root)
			if strings.Contains(r.URL.Path, "/bad/") {
				data = testcert.PEM(vulnerable.Root)
			}
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			_ = tw.WriteHeader(&tar.Header{Name: "ca-certificates.crt", Size: int64(len(data)), Mode: 0644, Typeflag: tar.TypeReg})
			_, _ = tw.Write(data)
			_ = tw.Close()
			_, _ = w.Write(buf.Bytes())
			return
		}
		http.NotFound(w, r)
	}))
	defer s.Close()
	t.Setenv("DOCKER_HOST", s.URL)
	t.Setenv("DOCKER_CONTEXT", "")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_TLS", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	r, e := Scan(context.Background(), Options{ContainersOnly: true, Offline: true, Incident: &vulnerable.Incident, Probes: []probes.Probe{}})
	if e != nil {
		t.Fatal(e)
	}
	if r.Summary.Containers != 2 || r.Summary.VulnerableStores != 1 {
		t.Fatalf("%+v", r.Summary)
	}
	for _, target := range r.Targets {
		if target.Target.ID == "good" && countStatus(target, report.VulnerableStore) != 0 {
			t.Fatal("trust crossed target boundary")
		}
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "not-for-reports") {
		t.Fatal("secret leaked")
	}
	if r.ExitCode(true) != 1 {
		t.Fatal(fmt.Sprint(r.Summary))
	}
}
func TestDockerPermissionFailurePreservesHost(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "denied", 403) }))
	defer s.Close()
	t.Setenv("DOCKER_HOST", s.URL)
	t.Setenv("DOCKER_CONTEXT", "")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_TLS", "")
	t.Setenv("DOCKER_CERT_PATH", "")
	f := testcert.Make(t)
	r, e := Scan(context.Background(), Options{Offline: true, Incident: &f.Incident, Probes: []probes.Probe{}})
	if e != nil || r.Summary.Hosts != 1 || len(r.Warnings) == 0 || r.ExitCode(true) != 3 {
		t.Fatalf("host preservation: %+v %v", r.Summary, e)
	}
}
