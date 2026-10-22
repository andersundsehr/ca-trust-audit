// Package selfupdate installs a GitHub release only when explicitly requested.
// It is independent of the read-only audit engine.
package selfupdate

import (
	"context"
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const repository = "https://github.com/andersundsehr/ca-trust-audit"
const modulePath = "github.com/andersundsehr/ca-trust-audit"
const maxDownload = 64 << 20

var releaseVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

type Options struct {
	CurrentVersion string
	CheckOnly      bool
	Force          bool
	Progress       func(string)
}

type Result struct {
	Current, Latest, Path string
	Updated, Ahead        bool
}

// Run resolves the latest release and, unless checking only or already current,
// atomically replaces the resolved executable. It never elevates privileges.
func Run(ctx context.Context, o Options) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	client := &http.Client{CheckRedirect: secureRedirect}
	defer client.CloseIdleConnections()
	u := updater{client: client, repository: repository, goos: runtime.GOOS, goarch: runtime.GOARCH, executable: os.Executable, validate: validateBinary}
	return u.run(ctx, o)
}

type updater struct {
	client       *http.Client
	repository   string
	goos, goarch string
	executable   func() (string, error)
	validate     func(string, string) error
}

func secureRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("too many release redirects")
	}
	if req.URL.Scheme != "https" || req.URL.User != nil {
		return errors.New("release redirects must use verified HTTPS without credentials")
	}
	return nil
}

func (u updater) run(ctx context.Context, o Options) (Result, error) {
	r := Result{Current: o.CurrentVersion}
	if u.goos != "linux" || (u.goarch != "amd64" && u.goarch != "arm64") {
		return r, errors.New("self-update supports Linux AMD64 and ARM64 only")
	}
	if o.CheckOnly && o.Force {
		return r, errors.New("check and force are mutually exclusive")
	}
	notify := func(s string) {
		if o.Progress != nil {
			o.Progress(s)
		}
	}
	notify("Checking the latest GitHub release")
	resp, err := u.request(ctx, http.MethodHead, u.repository+"/releases/latest")
	if err != nil {
		return r, err
	}
	resp.Body.Close()
	base, _ := url.Parse(u.repository)
	prefix := base.Path + "/releases/tag/"
	final := resp.Request.URL
	if resp.StatusCode != http.StatusOK || final.Host != base.Host || !strings.HasPrefix(final.Path, prefix) {
		return r, errors.New("latest release did not resolve to the expected GitHub release page")
	}
	r.Latest = strings.TrimPrefix(final.Path, prefix)
	if !releaseVersion.MatchString(r.Latest) {
		return r, errors.New("latest release has an unsupported version tag")
	}
	r.Ahead = newerStable(r.Current, r.Latest)
	if o.CheckOnly || (!o.Force && (r.Current == r.Latest || r.Ahead)) {
		return r, nil
	}
	executable, err := u.executable()
	if err != nil {
		return r, fmt.Errorf("locate current executable: %w", err)
	}
	r.Path, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return r, fmt.Errorf("resolve current executable: %w", err)
	}
	stat, err := os.Stat(r.Path)
	if err != nil {
		return r, fmt.Errorf("inspect current executable: %w", err)
	}
	if !stat.Mode().IsRegular() || stat.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return r, errors.New("self-update requires a regular executable without setuid/setgid permissions")
	}
	stage, err := os.CreateTemp(filepath.Dir(r.Path), ".ca-trust-audit-update-*")
	if err != nil {
		return r, errors.New("cannot write beside the executable; run sudo ca-trust-audit self-update or use the installer with a writable --install-dir")
	}
	defer os.Remove(stage.Name())
	defer stage.Close()
	notify("Downloading " + r.Latest + " for linux/" + u.goarch)
	resp, err = u.request(ctx, http.MethodGet, u.repository+"/releases/download/"+r.Latest+"/ca-trust-audit-linux-"+u.goarch)
	if err != nil {
		return r, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return r, fmt.Errorf("download release asset: HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxDownload {
		return r, errors.New("release asset exceeds the 64 MiB download limit")
	}
	n, err := io.Copy(stage, io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return r, errors.New("release download interrupted; executable unchanged")
	}
	if n == 0 || n > maxDownload || (resp.ContentLength >= 0 && n != resp.ContentLength) {
		return r, errors.New("release download empty, incomplete or too large; executable unchanged")
	}
	if err = stage.Chmod(stat.Mode().Perm()); err != nil {
		return r, fmt.Errorf("set update permissions: %w", err)
	}
	if err = stage.Sync(); err != nil {
		return r, fmt.Errorf("sync update: %w", err)
	}
	if err = stage.Close(); err != nil {
		return r, fmt.Errorf("close update: %w", err)
	}
	notify("Validating the standalone Go executable")
	if err = u.validate(stage.Name(), u.goarch); err != nil {
		return r, fmt.Errorf("invalid release asset; executable unchanged: %w", err)
	}
	if err = ctx.Err(); err != nil {
		return r, err
	}
	if err = os.Rename(stage.Name(), r.Path); err != nil {
		return r, fmt.Errorf("replace executable atomically: %w", err)
	}
	r.Updated = true
	return r, nil
}

func (u updater) request(ctx context.Context, method, endpoint string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return nil, errors.New("invalid release URL")
	}
	req.Header.Set("User-Agent", "ca-trust-audit self-update")
	resp, err := u.client.Do(req)
	if err == nil {
		return resp, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// Do not print URL errors: redirected asset URLs can contain signed credentials.
	return nil, errors.New("verified HTTPS release request failed; check network, proxy and TLS access")
}

func validateBinary(path, arch string) error {
	f, err := elf.Open(path)
	if err != nil {
		return errors.New("not an ELF executable")
	}
	defer f.Close()
	machine := elf.EM_X86_64
	if arch == "arm64" {
		machine = elf.EM_AARCH64
	}
	if f.Class != elf.ELFCLASS64 || f.Machine != machine || (f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN) {
		return errors.New("ELF executable architecture does not match this system")
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return errors.New("release executable requires a dynamic loader")
		}
	}
	b, err := buildinfo.ReadFile(path)
	if err != nil || b.Path != modulePath+"/cmd/ca-trust-audit" || b.Main.Path != modulePath {
		return errors.New("Go build metadata does not identify ca-trust-audit")
	}
	settings := map[string]string{}
	for _, s := range b.Settings {
		settings[s.Key] = s.Value
	}
	if settings["GOOS"] != "linux" || settings["GOARCH"] != arch || settings["CGO_ENABLED"] != "0" {
		return errors.New("Go build settings do not identify a standalone Linux release")
	}
	return nil
}

// Only compare ordinary stable tags. Unknown/development or prerelease versions
// can still explicitly install the latest release; --force permits downgrades.
func newerStable(current, latest string) bool {
	parse := func(s string) ([]uint64, bool) {
		if !releaseVersion.MatchString(s) || strings.Contains(s, "-") {
			return nil, false
		}
		s, _, _ = strings.Cut(strings.TrimPrefix(s, "v"), "+")
		parts := strings.Split(s, ".")
		numbers := make([]uint64, 3)
		for i, part := range parts {
			n, err := strconv.ParseUint(part, 10, 64)
			if err != nil {
				return nil, false
			}
			numbers[i] = n
		}
		return numbers, true
	}
	a, aok := parse(current)
	b, bok := parse(latest)
	if !aok || !bok {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}
