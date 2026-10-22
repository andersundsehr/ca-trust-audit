package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func fakeClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return &Client{http: s.Client(), base: s.URL}
}
func archive(t *testing.T, name string, data []byte, link string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	h := &tar.Header{Name: name, Mode: 0644, Size: int64(len(data)), Typeflag: tar.TypeReg}
	if link != "" {
		h.Typeflag = tar.TypeSymlink
		h.Linkname = link
		h.Size = 0
	}
	if e := w.WriteHeader(h); e != nil {
		t.Fatal(e)
	}
	if link == "" {
		if _, e := w.Write(data); e != nil {
			t.Fatal(e)
		}
	}
	if e := w.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func TestRunningAndPermissionDenied(t *testing.T) {
	c := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Query().Get("all") != "false" {
			t.Error("must only list running containers")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"Id":"abc","Names":["/web"],"Image":"minimal:latest"}]`))
	})
	cs, e := c.Running(context.Background())
	if e != nil || len(cs) != 1 || cs[0].Image != "minimal:latest" {
		t.Fatal(cs, e)
	}
	c = fakeClient(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "permission denied SECRET", 403) })
	_, e = c.Running(context.Background())
	if e == nil || strings.Contains(e.Error(), "SECRET") {
		t.Fatal(e)
	}
}
func TestArchiveNoShellAndSymlink(t *testing.T) {
	data := []byte("public certificate bundle")
	c := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "exec") {
			t.Fatal("archive scan executed a command")
		}
		p := r.URL.Query().Get("path")
		if p == "/etc/ssl/cert.pem" {
			_, _ = w.Write(archive(t, "cert.pem", nil, "certs/ca-certificates.crt"))
		} else if p == "/etc/ssl/certs/ca-certificates.crt" {
			_, _ = w.Write(archive(t, "ca-certificates.crt", data, ""))
		} else {
			http.NotFound(w, r)
		}
	})
	b, e := c.ReadFile(context.Background(), "distroless", "/etc/ssl/cert.pem")
	if e != nil || !bytes.Equal(b, data) {
		t.Fatal(string(b), e)
	}
	_, e = c.ReadFile(context.Background(), "scratch", "/absent")
	if !errors.Is(e, ErrNotFound) {
		t.Fatal(e)
	}
}
func TestArchiveBounds(t *testing.T) {
	c := fakeClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(archive(t, "loop", nil, "loop")) })
	if _, e := c.ReadFile(context.Background(), "id", "/loop"); e == nil {
		t.Fatal("symlink loop accepted")
	}
	c = fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		_ = tw.WriteHeader(&tar.Header{Name: "huge", Typeflag: tar.TypeReg, Mode: 0644, Size: 9 << 20})
		_, _ = w.Write(b.Bytes())
	})
	if _, e := c.ReadFile(context.Background(), "id", "/huge"); e == nil {
		t.Fatal("oversized file accepted")
	}
}
func TestEnvironmentAllowlist(t *testing.T) {
	c := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"Config": map[string]any{"Env": []string{"SECRET_TOKEN=do-not-report", "SSL_CERT_FILE=/public/ca.pem"}}})
	})
	env, e := c.CAEnvironment(context.Background(), "id")
	if e != nil || len(env) != 1 || env["SSL_CERT_FILE"] != "/public/ca.pem" {
		t.Fatal(env, e)
	}
}
func TestExecFramingAndFailure(t *testing.T) {
	c := fakeClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/start"):
			msg := []byte("CTA1 ERROR dns\n")
			h := make([]byte, 8)
			h[0] = 1
			binary.BigEndian.PutUint32(h[4:], uint32(len(msg)))
			_, _ = w.Write(append(h, msg...))
		case strings.HasSuffix(r.URL.Path, "/exec"):
			_, _ = w.Write([]byte(`{"Id":"execid"}`))
		default:
			_, _ = w.Write([]byte(`{"ExitCode":0,"Running":false}`))
		}
	})
	b, e := (Runner{Client: c, ID: "id"}).Run(context.Background(), "python3", "-B", "-c", "print('x')")
	if e != nil || string(b) != "CTA1 ERROR dns\n" {
		t.Fatal(string(b), e)
	}
}
func TestEndpointSelection(t *testing.T) {
	t.Setenv("DOCKER_CONTEXT", "")
	t.Setenv("DOCKER_HOST", "ssh://host.example")
	if _, e := New(context.Background()); e == nil {
		t.Fatal("unsupported SSH transport silently accepted")
	}
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:2376")
	t.Setenv("DOCKER_TLS_VERIFY", "1")
	t.Setenv("DOCKER_CERT_PATH", t.TempDir())
	if _, e := New(context.Background()); e == nil {
		t.Fatal("missing TLS identity silently ignored")
	}
}

// TestEngineArchive is an explicit opt-in integration test. No privileged mode,
// shell, image pull, or filesystem write in an existing container is used.
func TestEngineArchive(t *testing.T) {
	if os.Getenv("CA_TRUST_AUDIT_DOCKER_TESTS") != "1" {
		t.Skip("set CA_TRUST_AUDIT_DOCKER_TESTS=1 and CA_TRUST_AUDIT_TEST_CONTAINER to test a running container")
	}
	id := os.Getenv("CA_TRUST_AUDIT_TEST_CONTAINER")
	if id == "" {
		t.Fatal("CA_TRUST_AUDIT_TEST_CONTAINER required")
	}
	c, e := New(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	b, e := c.ReadFile(context.Background(), id, "/etc/ssl/certs/ca-certificates.crt")
	if e != nil || len(b) == 0 {
		t.Fatal("archive read", e)
	}
}

func TestMissingDockerInstallation(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("DOCKER_HOST", "")
	t.Setenv("DOCKER_CONTEXT", "")
	_, e := newWithSocket(context.Background(), t.TempDir()+"/absent-docker.sock")
	if !errors.Is(e, ErrUnavailable) {
		t.Fatalf("missing Docker should yield a distinct availability result, got %v", e)
	}
}
