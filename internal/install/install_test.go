package install_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The installer is tested without network access or administrator privileges.
// curl and uname are replaced; the actual atomic installation runs. The test
// PATH intentionally contains neither sha256sum nor awk.
func TestInstaller(t *testing.T) {
	cases := []struct {
		name, machine, system         string
		latest, brokenDownload, empty bool
		args                          []string
		want                          bool
	}{
		{name: "AMD64 latest", machine: "x86_64", system: "Linux", latest: true, want: true},
		{name: "ARM64 latest", machine: "aarch64", system: "Linux", latest: true, want: true},
		{name: "ARM64 alias pinned", machine: "arm64", system: "Linux", want: true},
		{name: "unsupported architecture", machine: "i686", system: "Linux"},
		{name: "unsupported OS", machine: "x86_64", system: "Darwin"},
		{name: "download failure", machine: "x86_64", system: "Linux", brokenDownload: true},
		{name: "empty download", machine: "x86_64", system: "Linux", empty: true},
		{name: "relative directory", machine: "x86_64", system: "Linux", args: []string{"--install-dir", "relative"}},
		{name: "invalid version", machine: "x86_64", system: "Linux", args: []string{"--version", "v1.0.0/../../elsewhere"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			stubDir := filepath.Join(dir, "tools")
			assets := filepath.Join(dir, "assets")
			dest := filepath.Join(dir, "bin")
			for _, p := range []string{stubDir, assets, dest} {
				if e := os.Mkdir(p, 0700); e != nil {
					t.Fatal(e)
				}
			}
			write := func(p, data string, mode os.FileMode) {
				t.Helper()
				if e := os.WriteFile(p, []byte(data), mode); e != nil {
					t.Fatal(e)
				}
			}
			write(filepath.Join(stubDir, "uname"), "#!/bin/sh\ncase \"$1\" in -s) echo \"$TEST_SYSTEM\" ;; -m) echo \"$TEST_MACHINE\" ;; esac\n", 0755)
			write(filepath.Join(stubDir, "curl"), `#!/bin/sh
output=
url=
head=0
for arg do
 case "$arg" in --head) head=1 ;; esac
done
while [ "$#" -gt 0 ]; do
 case "$1" in
  --output) shift; output=$1 ;;
  https://*) url=$1 ;;
 esac
 shift
done
printf '%s\n' "$url" >> "$TEST_REQUESTS"
if [ "$head" -eq 1 ]; then printf '%s' 'https://github.com/andersundsehr/ca-trust-audit/releases/tag/v1.2.3'; exit 0; fi
[ "$TEST_BROKEN_DOWNLOAD" != 1 ] || exit 22
case "$url" in
 https://github.com/andersundsehr/ca-trust-audit/releases/download/v1.2.3/*) cp "$TEST_ASSETS/${url##*/}" "$output" ;;
 *) exit 22 ;;
esac
`, 0755)
			for _, tool := range []string{"mktemp", "mkdir", "install", "mv", "rm", "cp"} {
				source, e := exec.LookPath(tool)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.Symlink(source, filepath.Join(stubDir, tool)); e != nil {
					t.Fatal(e)
				}
			}
			for _, arch := range []string{"amd64", "arm64"} {
				binary := "standalone test executable for " + arch
				if tc.empty {
					binary = ""
				}
				write(filepath.Join(assets, "ca-trust-audit-linux-"+arch), binary, 0600)
			}

			existing := filepath.Join(dest, "ca-trust-audit")
			write(existing, "existing installation", 0755)
			args := []string{"../../install.sh", "--install-dir", dest}
			if !tc.latest {
				args = append(args, "--version", "v1.2.3")
			}
			args = append(args, tc.args...)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "sh", args...)
			broken := "0"
			if tc.brokenDownload {
				broken = "1"
			}
			requests := filepath.Join(dir, "requests.txt")
			cmd.Env = append(os.Environ(), "PATH="+stubDir, "TEST_SYSTEM="+tc.system, "TEST_MACHINE="+tc.machine, "TEST_ASSETS="+assets, "TEST_REQUESTS="+requests, "TEST_BROKEN_DOWNLOAD="+broken)
			out, e := cmd.CombinedOutput()
			if (e == nil) != tc.want {
				t.Fatalf("success=%v want=%v output=%s", e == nil, tc.want, out)
			}
			content, e := os.ReadFile(existing)
			if e != nil {
				t.Fatal(e)
			}
			if !tc.want {
				if string(content) != "existing installation" {
					t.Fatal("failed installation modified the existing executable")
				}
				return
			}
			arch := "amd64"
			if tc.machine == "aarch64" || tc.machine == "arm64" {
				arch = "arm64"
			}
			if string(content) != "standalone test executable for "+arch {
				t.Fatalf("wrong architecture: %s", content)
			}
			stat, e := os.Stat(existing)
			if e != nil || stat.Mode().Perm() != 0755 {
				t.Fatalf("executable mode: %v %v", stat, e)
			}
			calls, e := os.ReadFile(requests)
			if e != nil {
				t.Fatal(e)
			}
			if strings.Contains(string(calls), "checksums") {
				t.Fatal("installer requested a checksum file", string(calls))
			}
			if !strings.Contains(string(calls), "/download/v1.2.3/ca-trust-audit-linux-"+arch) {
				t.Fatal("release was not pinned before downloading", string(calls))
			}
			leftovers, e := filepath.Glob(filepath.Join(dest, ".ca-trust-audit.*"))
			if e != nil || len(leftovers) != 0 {
				t.Fatal("staging files left behind", leftovers, e)
			}
		})
	}
}
