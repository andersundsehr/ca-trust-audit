package audit

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/andersundsehr/ca-trust-audit/pkg/certificates"
	"github.com/andersundsehr/ca-trust-audit/pkg/docker"
)

// Files is the read-only target filesystem extension point. Implementations must
// return fs.ErrNotExist for absent paths and bound reads and directory traversal.
type Files interface {
	ReadFile(context.Context, string) ([]byte, error)
	CAFiles(context.Context, string) ([]string, error)
}
type HostFiles struct{}

func (HostFiles) ReadFile(ctx context.Context, p string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() {
		return nil, errors.New("CA path is not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, certificates.MaxBundleBytes+1))
	if len(b) > certificates.MaxBundleBytes {
		return nil, errors.New("CA bundle exceeds 8 MiB")
	}
	return b, err
}
func (HostFiles) CAFiles(ctx context.Context, p string) ([]string, error) {
	var out []string
	count := 0
	err := filepath.WalkDir(p, func(name string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			return err
		}
		count++
		if count > 2048 {
			return errors.New("CA directory exceeds 2048 entries")
		}
		if d.IsDir() {
			if strings.Count(strings.TrimPrefix(name, p), string(filepath.Separator)) > 4 {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".0") {
			out = append(out, name)
		}
		return nil
	})
	return out, err
}

type containerFiles struct {
	client *docker.Client
	id     string
}

func (f containerFiles) ReadFile(ctx context.Context, p string) ([]byte, error) {
	b, e := f.client.ReadFile(ctx, f.id, p)
	if errors.Is(e, docker.ErrNotFound) {
		e = fs.ErrNotExist
	}
	return b, e
}
func (f containerFiles) CAFiles(ctx context.Context, p string) ([]string, error) {
	b, e := f.client.CAFiles(ctx, f.id, p)
	if errors.Is(e, docker.ErrNotFound) {
		e = fs.ErrNotExist
	}
	return b, e
}
