#!/bin/sh
# Install a standalone Linux release over HTTPS. Scanner execution needs none of
# these installer tools and does not depend on Go, OpenSSL or a language runtime.
main() {
set -eu
umask 077

repository=https://github.com/andersundsehr/ca-trust-audit
version=latest
install_dir=/usr/local/bin
work_dir=
staged=
use_sudo=0

fail() { printf 'Installation failed: %s\n' "$*" >&2; exit 1; }
as_root() {
    if [ "$use_sudo" -eq 1 ]; then sudo "$@"; else "$@"; fi
}
cleanup() {
    if [ -n "$staged" ]; then as_root rm -f -- "$staged" || :; fi
    if [ -n "$work_dir" ]; then rm -rf -- "$work_dir"; fi
}
trap cleanup 0
trap 'exit 1' 1 2 15

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version|--install-dir)
            [ "$#" -ge 2 ] || fail "$1 requires a value"
            option=$1
            shift
            if [ "$option" = --version ]; then version=$1; else install_dir=$1; fi
            ;;
        --help|-h)
            printf '%s\n' 'Usage: sh install.sh [--version vX.Y.Z] [--install-dir /absolute/path]' \
                'Default: latest release; auto-detect Linux AMD64/ARM64; install to /usr/local/bin.' \
                'Requires curl and common POSIX tools. Uses sudo only if the destination needs it.'
            exit 0
            ;;
        *) fail "unknown argument: $1" ;;
    esac
    shift
done
case "$install_dir" in /*) ;; *) fail '--install-dir must be an absolute path' ;; esac
case "$install_dir" in *'
'*) fail '--install-dir must not contain newlines' ;; esac
[ "$(uname -s)" = Linux ] || fail 'only Linux (including WSL) is supported'
case "$(uname -m)" in
    x86_64|amd64|AMD64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) fail 'unsupported architecture; supported: AMD64 and ARM64' ;;
esac
for tool in curl mktemp mkdir install mv rm; do
    command -v "$tool" >/dev/null 2>&1 || fail "required installer tool is missing: $tool"
done
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/ca-trust-audit-install.XXXXXX")

# Resolve latest once and download the binary from that release tag.
if [ "$version" = latest ]; then
    resolved=$(curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error \
        --location --head --connect-timeout 15 --max-time 60 --output /dev/null \
        --write-out '%{url_effective}' "$repository/releases/latest") || fail 'cannot resolve latest release'
    case "$resolved" in
        "$repository/releases/tag/"*) version=${resolved#"$repository/releases/tag/"} ;;
        *) fail 'no published release is available yet; a maintainer must publish a version tag first' ;;
    esac
fi
case "$version" in v[0-9]*) ;; *) fail 'version must start with v followed by a number' ;; esac
case "$version" in *[!A-Za-z0-9.+-]*) fail 'invalid release version' ;; esac
asset=ca-trust-audit-linux-$arch
base=$repository/releases/download/$version
fetch() {
    curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error \
        --location --retry 2 --connect-timeout 15 --max-time 180 --max-filesize "$3" \
        --output "$2" "$1" || fail "could not download $version release asset; check that the release is published"
}
printf 'Downloading ca-trust-audit %s for Linux %s...\n' "$version" "$arch"
fetch "$base/$asset" "$work_dir/$asset" 67108864
[ -s "$work_dir/$asset" ] || fail 'downloaded executable is empty'

# Do not touch an existing installation until the download has completed.
[ ! -d "$install_dir/ca-trust-audit" ] || fail 'destination executable path is a directory'
if mkdir -p -- "$install_dir" 2>/dev/null && [ -w "$install_dir" ]; then
    :
elif command -v sudo >/dev/null 2>&1; then
    use_sudo=1
    as_root mkdir -p -- "$install_dir"
else
    fail 'destination needs administrator permissions; run as root or choose --install-dir "$HOME/.local/bin"'
fi
staged=$(as_root mktemp "$install_dir/.ca-trust-audit.XXXXXX")
as_root install -m 0755 -- "$work_dir/$asset" "$staged"
as_root mv -f -- "$staged" "$install_dir/ca-trust-audit"
staged=
printf 'Installed ca-trust-audit %s (%s) to %s/ca-trust-audit\n' "$version" "$arch" "$install_dir"
case ":$PATH:" in
    *":$install_dir:"*) printf 'Run: ca-trust-audit\n' ;;
    *) printf 'Run: %s/ca-trust-audit\n' "$install_dir"
       printf 'To use the command by name, add %s to your PATH.\n' "$install_dir" ;;
esac

}

# A piped download must contain the full function before installation can start.
main "$@"
