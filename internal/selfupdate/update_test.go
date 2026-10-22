package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T, asset http.HandlerFunc) (updater, string, *atomic.Int32) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca-trust-audit")
	if err := os.WriteFile(path, []byte("previous executable"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	var downloads atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases/latest":
			http.Redirect(w, r, "/releases/tag/v0.2.0", http.StatusFound)
		case "/releases/tag/v0.2.0":
			w.WriteHeader(http.StatusOK)
		case "/releases/download/v0.2.0/ca-trust-audit-linux-amd64", "/releases/download/v0.2.0/ca-trust-audit-linux-arm64":
			downloads.Add(1)
			asset(w, r)
		default:
			t.Errorf("unexpected release request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	client := s.Client()
	client.CheckRedirect = secureRedirect
	u := updater{client: client, repository: s.URL, goos: "linux", goarch: "amd64", executable: func() (string, error) { return path, nil }, validate: func(p, arch string) error {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if string(b) != "verified fixture executable" {
			return errors.New("invalid fixture executable")
		}
		return nil
	}}
	return u, path, &downloads
}

func assertPreserved(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "previous executable" {
		t.Fatalf("old executable was not preserved: %q %v", b, err)
	}
	staged, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".ca-trust-audit-update-*"))
	if err != nil || len(staged) != 0 {
		t.Fatalf("staged update was not cleaned: %v %v", staged, err)
	}
}

func TestAtomicUpdateAndSymlink(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			var originalPath string
			u, path, downloads := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "linux-"+arch) {
					t.Error("incorrect platform download")
				}
				if b, err := os.ReadFile(originalPath); err != nil || string(b) != "previous executable" {
					t.Error("existing executable changed before download completed")
				}
				fmt.Fprint(w, "verified fixture executable")
			})
			originalPath = path
			u.goarch = arch
			link := filepath.Join(t.TempDir(), "linked-command")
			if err := os.Symlink(path, link); err != nil {
				t.Fatal(err)
			}
			u.executable = func() (string, error) { return link, nil }
			r, err := u.run(context.Background(), Options{CurrentVersion: "v0.1.1"})
			if err != nil || !r.Updated || r.Latest != "v0.2.0" || r.Path != path || downloads.Load() != 1 {
				t.Fatalf("update: %+v %v", r, err)
			}
			b, err := os.ReadFile(link)
			if err != nil || string(b) != "verified fixture executable" {
				t.Fatalf("symlink target was not updated: %q %v", b, err)
			}
			stat, err := os.Lstat(link)
			if err != nil || stat.Mode()&os.ModeSymlink == 0 {
				t.Fatal("symlink itself was replaced", err)
			}
			stat, err = os.Stat(path)
			if err != nil || stat.Mode().Perm() != 0755 {
				t.Fatal("executable permissions changed", err)
			}
		})
	}
}

func TestForceAndCancellationBeforeReplace(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		u, path, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "verified fixture executable") })
		ctx, cancel := context.WithCancel(context.Background())
		if interrupted {
			u.validate = func(string, string) error { cancel(); return nil }
		}
		r, err := u.run(ctx, Options{CurrentVersion: "v0.2.0", Force: true})
		cancel()
		if interrupted {
			if !errors.Is(err, context.Canceled) || r.Updated {
				t.Fatalf("canceled update was installed: %+v %v", r, err)
			}
			assertPreserved(t, path)
		} else if err != nil || !r.Updated {
			t.Fatalf("forced reinstall failed: %+v %v", r, err)
		}
	}
}

func TestChecksDoNotDownloadOrWrite(t *testing.T) {
	for _, o := range []Options{{CurrentVersion: "v0.1.1", CheckOnly: true}, {CurrentVersion: "v0.2.0"}, {CurrentVersion: "v1.0.0"}} {
		u, path, downloads := fixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected download") })
		r, err := u.run(context.Background(), o)
		if err != nil || r.Updated || r.Latest != "v0.2.0" || downloads.Load() != 0 {
			t.Fatalf("check unexpectedly updated: %+v %v", r, err)
		}
		assertPreserved(t, path)
	}
}

func TestFailedUpdatesPreserveExecutable(t *testing.T) {
	for _, tc := range []struct {
		name  string
		asset http.HandlerFunc
	}{
		{"missing asset", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }},
		{"empty asset", func(w http.ResponseWriter, r *http.Request) {}},
		{"HTML instead of binary", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "<html>error</html>") }},
		{"truncated asset", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "1000")
			fmt.Fprint(w, "partial")
		}},
		{"oversized asset", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprint(maxDownload+1))
		}},
		{"timeout", func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, path, _ := fixture(t, tc.asset)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			r, err := u.run(ctx, Options{CurrentVersion: "v0.1.1"})
			if err == nil || r.Updated {
				t.Fatalf("failed asset was installed: %+v %v", r, err)
			}
			assertPreserved(t, path)
		})
	}
}

func TestRefuseInsecureRedirectAndWrongReleasePage(t *testing.T) {
	for _, target := range []string{"http://example.invalid/asset", "https://user:password@example.invalid/asset"} {
		parsed, _ := url.Parse(target)
		if err := secureRedirect(&http.Request{URL: parsed}, nil); err == nil {
			t.Fatal("insecure redirect accepted")
		}
	}
	u, path, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {})
	u.repository += "/wrong-repository"
	// A generic HTTPS page is not sufficient evidence of a latest release.
	u.client.Transport = responseTransport{}
	if _, err := u.run(context.Background(), Options{}); err == nil {
		t.Fatal("unresolved release page accepted")
	}
	assertPreserved(t, path)
}

type responseTransport struct{}

func (responseTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: http.NoBody, Request: r}, nil
}

func TestUnsupportedPlatformDoesNotContactNetwork(t *testing.T) {
	for _, platform := range [][2]string{{"darwin", "arm64"}, {"linux", "386"}} {
		u := updater{goos: platform[0], goarch: platform[1]}
		if _, err := u.run(context.Background(), Options{}); err == nil {
			t.Fatal("unsupported platform accepted")
		}
	}
}

func TestNetworkErrorsDoNotExposeSignedURLs(t *testing.T) {
	u := updater{client: &http.Client{Transport: failingTransport{}}}
	_, err := u.request(context.Background(), http.MethodGet, "https://example.invalid/asset?signature=private-marker")
	if err == nil || strings.Contains(err.Error(), "private-marker") || strings.Contains(err.Error(), "signature") {
		t.Fatalf("network error exposed a signed URL: %v", err)
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("connection failed for %s", r.URL)
}

func TestReleaseVersionComparison(t *testing.T) {
	for _, tc := range []struct {
		current, latest string
		ahead           bool
	}{
		{"v0.2.0", "v0.1.10", true}, {"v1.0.0", "v0.99.9", true},
		{"v0.1.9", "v0.1.10", false}, {"v0.2.0", "v0.2.0", false},
		{"dev", "v0.2.0", false}, {"v0.3.0-rc.1", "v0.2.0", false},
	} {
		if newerStable(tc.current, tc.latest) != tc.ahead {
			t.Fatal(tc)
		}
	}
}

func TestBinaryValidationRejectsUnrelatedAssets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-binary")
	if err := os.WriteFile(path, []byte("not an ELF"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateBinary(path, "amd64"); err == nil {
		t.Fatal("non-ELF asset accepted")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateBinary(executable, runtime.GOARCH); err == nil {
		t.Fatal("unrelated Go program accepted as ca-trust-audit")
	}
	other := "arm64"
	if runtime.GOARCH == other {
		other = "amd64"
	}
	if err := validateBinary(executable, other); err == nil {
		t.Fatal("wrong architecture accepted")
	}
}
