// Package docker provides read-only discovery, bounded archive reads and runtime
// exec through the Docker Engine API. No container files are created or changed.
package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/andersundsehr/ca-trust-audit/pkg/probes"
)

var ErrUnavailable = errors.New("Docker is not installed and no local Docker socket is available")
var ErrNotFound = errors.New("container path not found")

const maxResponse = 16 << 20

// Client uses the selected endpoint; SSH contexts require a Docker CLI transport
// and are explicitly unsupported here rather than silently using another daemon.
type Client struct {
	http *http.Client
	base string
}
type Container struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	Image string   `json:"Image"`
}

func New(ctx context.Context) (*Client, error) { return newWithSocket(ctx, "/var/run/docker.sock") }

func newWithSocket(ctx context.Context, defaultSocket string) (*Client, error) {
	endpoint := os.Getenv("DOCKER_HOST")
	selected := os.Getenv("DOCKER_CONTEXT")
	if selected != "" || endpoint == "" {
		if _, err := exec.LookPath("docker"); err == nil {
			args := []string{"context", "inspect", "--format", "{{json .Endpoints.docker}}"}
			if selected != "" {
				args = append(args, selected)
			}
			out, err := (probes.HostRunner{}).Run(ctx, "docker", args...)
			if err != nil {
				return nil, errors.New("Docker context resolution failed")
			}
			var v struct {
				Host          string
				SkipTLSVerify bool
			}
			if json.Unmarshal(bytes.TrimSpace(out), &v) != nil {
				return nil, errors.New("invalid Docker context response")
			}
			if selected != "" || endpoint == "" {
				endpoint = v.Host
			}
			if v.SkipTLSVerify && !strings.HasPrefix(endpoint, "unix://") {
				return nil, errors.New("Docker context disables TLS verification; refused")
			}
			if !strings.HasPrefix(endpoint, "unix://") && os.Getenv("DOCKER_CERT_PATH") == "" && strings.HasPrefix(endpoint, "tcp://") {
				return nil, errors.New("remote Docker context: set DOCKER_HOST and DOCKER_CERT_PATH explicitly for verified TLS")
			}
		} else if selected != "" {
			return nil, errors.New("DOCKER_CONTEXT needs Docker CLI for context resolution")
		}
	}
	if endpoint == "" {
		endpoint = "unix://" + defaultSocket
		if _, err := os.Stat(defaultSocket); err != nil {
			return nil, ErrUnavailable
		}
	}
	tr := &http.Transport{ResponseHeaderTimeout: 10 * time.Second}
	base := "http://docker"
	switch {
	case strings.HasPrefix(endpoint, "unix://"):
		socket := strings.TrimPrefix(endpoint, "unix://")
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}
	case strings.HasPrefix(endpoint, "tcp://"), strings.HasPrefix(endpoint, "https://"), strings.HasPrefix(endpoint, "http://"):
		base = strings.Replace(endpoint, "tcp://", "http://", 1)
		if os.Getenv("DOCKER_TLS_VERIFY") != "" || strings.HasPrefix(endpoint, "https://") || os.Getenv("DOCKER_TLS") != "" || os.Getenv("DOCKER_CERT_PATH") != "" {
			base = strings.Replace(base, "http://", "https://", 1)
			dir := os.Getenv("DOCKER_CERT_PATH")
			if dir == "" {
				return nil, errors.New("verified Docker TLS requires DOCKER_CERT_PATH")
			}
			ca, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
			if err != nil {
				return nil, errors.New("cannot read Docker TLS CA")
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(ca) {
				return nil, errors.New("invalid Docker TLS CA")
			}
			cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
			if err != nil {
				return nil, errors.New("cannot load Docker TLS client identity")
			}
			tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{cert}}
		}
		u, err := url.Parse(base)
		if err != nil || u.User != nil || u.RawQuery != "" || u.Path != "" {
			return nil, errors.New("invalid Docker endpoint")
		}
	default:
		return nil, errors.New("unsupported Docker endpoint transport (SSH and npipe are not supported)")
	}
	return &Client{http: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, base: base}, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) request(ctx context.Context, method, p string, body any) ([]byte, error) {
	var input io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		input = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+"/v1.41"+p, input)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("Docker API connection failed (check endpoint, permissions and daemon availability)")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("Docker API HTTP %d (check permissions and daemon)", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if len(b) > maxResponse {
		return nil, errors.New("Docker response exceeds 16 MiB")
	}
	return b, err
}
func (c *Client) Running(ctx context.Context) ([]Container, error) {
	b, e := c.request(ctx, "GET", "/containers/json?all=false", nil)
	if e != nil {
		return nil, e
	}
	var out []Container
	e = json.Unmarshal(b, &out)
	return out, e
}

// CAEnvironment returns only a narrow allowlist of trust configuration, never
// other environment values, mounts or application configuration data.
func (c *Client) CAEnvironment(ctx context.Context, id string) (map[string]string, error) {
	b, e := c.request(ctx, "GET", "/containers/"+url.PathEscape(id)+"/json", nil)
	if e != nil {
		return nil, e
	}
	var v struct{ Config struct{ Env []string } }
	if e = json.Unmarshal(b, &v); e != nil {
		return nil, e
	}
	out := map[string]string{}
	for _, line := range v.Config.Env {
		k, val, ok := strings.Cut(line, "=")
		if ok && CAKeys[k] {
			out[k] = val
		}
	}
	return out, nil
}

var CAKeys = map[string]bool{"SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "CURL_CA_BUNDLE": true, "REQUESTS_CA_BUNDLE": true, "NODE_EXTRA_CA_CERTS": true, "COMPOSER_CAFILE": true, "JAVA_HOME": true, "JAVA_TOOL_OPTIONS": true, "JDK_JAVA_OPTIONS": true, "_JAVA_OPTIONS": true}

// ReadFile follows at most eight symlinks inside the container via archive API.
// It never extracts archive entries onto the host filesystem.
func (c *Client) ReadFile(ctx context.Context, id, p string) ([]byte, error) {
	for links := 0; links < 8; links++ {
		b, e := c.request(ctx, "GET", "/containers/"+url.PathEscape(id)+"/archive?path="+url.QueryEscape(p), nil)
		if e != nil {
			return nil, e
		}
		tr := tar.NewReader(bytes.NewReader(b))
		h, e := tr.Next()
		if e != nil {
			return nil, e
		}
		if h.Typeflag == tar.TypeSymlink {
			if path.IsAbs(h.Linkname) {
				p = path.Clean(h.Linkname)
			} else {
				p = path.Join(path.Dir(p), h.Linkname)
			}
			continue
		}
		if h.Typeflag != tar.TypeReg || h.Size > 8<<20 {
			return nil, errors.New("not a regular file or exceeds 8 MiB")
		}
		return io.ReadAll(io.LimitReader(tr, 8<<20))
	}
	return nil, errors.New("container symlink limit exceeded")
}

type Runner struct {
	Client *Client
	ID     string
}

func (r Runner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	argv := append([]string{name}, args...)
	b, e := r.Client.request(ctx, "POST", "/containers/"+url.PathEscape(r.ID)+"/exec", map[string]any{"AttachStdout": true, "AttachStderr": true, "Cmd": argv})
	if e != nil {
		return nil, e
	}
	var v struct{ ID string }
	if json.Unmarshal(b, &v) != nil || v.ID == "" {
		return nil, errors.New("invalid exec response")
	}
	b, e = r.Client.request(ctx, "POST", "/exec/"+url.PathEscape(v.ID)+"/start", map[string]any{"Detach": false, "Tty": false})
	if e != nil {
		return nil, e
	}
	var out bytes.Buffer
	for len(b) > 0 {
		if len(b) < 8 {
			return nil, errors.New("invalid Docker exec framing")
		}
		size := int(binary.BigEndian.Uint32(b[4:8]))
		b = b[8:]
		if size > len(b) || size > probes.MaxOutput-out.Len() {
			return nil, errors.New("Docker exec output limit or framing error")
		}
		out.Write(b[:size])
		b = b[size:]
	}
	b, e = r.Client.request(ctx, "GET", "/exec/"+url.PathEscape(v.ID)+"/json", nil)
	if e != nil {
		return nil, e
	}
	var status struct {
		ExitCode int
		Running  bool
	}
	if json.Unmarshal(b, &status) != nil || status.Running || status.ExitCode != 0 {
		return out.Bytes(), errors.New("container command failed")
	}
	return out.Bytes(), nil
}

// CAFiles enumerates only public-certificate filenames in a known trust directory.
// Total archive bytes and entries are bounded; no archive entry is extracted.
func (c *Client) CAFiles(ctx context.Context, id, p string) ([]string, error) {
	b, e := c.request(ctx, "GET", "/containers/"+url.PathEscape(id)+"/archive?path="+url.QueryEscape(p), nil)
	if e != nil {
		return nil, e
	}
	tr := tar.NewReader(bytes.NewReader(b))
	var out []string
	count := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		count++
		if count > 2048 {
			return nil, errors.New("trust directory exceeds entry limit")
		}
		clean := path.Clean(h.Name)
		parts := strings.Split(clean, "/")
		if len(parts) < 2 || clean == ".." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
			continue
		}
		rel := strings.Join(parts[1:], "/")
		name := path.Base(rel)
		if h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeSymlink {
			if strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".0") {
				out = append(out, path.Join(p, rel))
			}
		}
	}
	return out, nil
}
