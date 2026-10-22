# ca-trust-audit

A read-only Linux certificate-trust incident scanner: one Go executable, a reusable
Go API, host and running-Docker-container coverage, and separate live-client and
explicit trust-store evidence. Linux AMD64 and ARM64, including Linux under WSL.
No Go, Python, OpenSSL, curl or Java installation is required to **run** the scanner.
The offline verifier uses `github.com/google/certificate-transparency-go/x509`
(pinned v1.4.0) and its `golang.org/x/crypto` dependency (v0.58.0). This small
compiled dependency set lets explicit PEM evaluation remain independent of the
scanner Go runtime’s incident denylist, while retaining real signature, validity,
constraint and hostname checks. No verification checks are disabled. Optional installed clients provide
additional evidence about their own TLS behavior.

The bundled incident is **eMudhra / CVE-2026-111943 (October 2026)**. Six compromised
TLS intermediate keys are represented under both eMudhra and Sectigo signatures,
with all twelve regular published endpoints and PEM chains. Two additional
upstream no-CT endpoints are included. Two compromised code-signing keys (four
certificate identities) are identified separately; code-signing policy validation
is **NOT_SUPPORTED**, and TLS rejection never establishes code-signing safety.

## Install

Install the latest release with one command (Linux and WSL):

```sh
curl -qfsSL https://github.com/andersundsehr/ca-trust-audit/releases/latest/download/install.sh | sh
```

The installer automatically detects AMD64 (`x86_64`) or ARM64 (`aarch64`/`arm64`),
resolves the latest published release, downloads the matching standalone binary
over HTTPS, and installs `ca-trust-audit` to `/usr/local/bin`. It uses `sudo` only for installation
when administrator permissions are needed; root can run it directly. Unsupported
systems, failed downloads and empty downloads stop installation and preserve an
existing executable. Updates replace the executable atomically.

The installer needs `curl` and common POSIX utilities. The installed
scanner needs none of the download/build tools. A non-root installation without
sudo, or a specific release, can also be selected in a single command:

```sh
curl -qfsSL https://github.com/andersundsehr/ca-trust-audit/releases/latest/download/install.sh | sh -s -- --install-dir "$HOME/.local/bin"
curl -qfsSL https://github.com/andersundsehr/ca-trust-audit/releases/latest/download/install.sh | sh -s -- --version v0.1.0
```

For a user-local installation, `$HOME/.local/bin` must be on `PATH`; otherwise the
installer prints the executable's full path. For manual inspection/download, see
[install.sh](install.sh) and [GitHub Releases](https://github.com/andersundsehr/ca-trust-audit/releases).
Release changes are recorded in [CHANGELOG.md](CHANGELOG.md).
The installer does not download or check checksum files. Downloads always use
verified HTTPS.

Update an installed scanner directly, without curl or other external programs:

```sh
ca-trust-audit self-update --check              # only check for a newer release
ca-trust-audit self-update                      # install the latest matching release
sudo ca-trust-audit self-update                 # if the installation directory requires root
```

`selfupdate` is an alias for `self-update`. This explicit command is the only
scanner operation that replaces its executable; ordinary scans remain read-only.
It selects Linux AMD64/ARM64, follows verified HTTPS redirects, bounds the download
to 64 MiB, and checks ELF architecture and standalone Go build metadata before an
atomic replacement in the same directory. A symlinked command updates its resolved
target. Failed downloads, invalid binaries and cancellation before replacement
preserve the old executable. No checksum file is downloaded. HTTPS and the GitHub
release account are the download trust boundary; build metadata is a format check,
not an independent signature. Progress goes to stderr; the result goes to stdout.
The command exits 0 on success/check (including an available update), 2 on failure.
`--timeout` bounds the whole update (default 2m, range 1s–10m). No privileges are
elevated automatically. Matching or newer stable versions remain unchanged unless
`--force` explicitly requests a reinstall/downgrade to the latest release.

A default run scans the current local filesystem, discovers Docker, and scans each
**running** container independently. Inside a container, the current filesystem is
the primary host target. Stopped containers are excluded. A missing Docker endpoint
leaves the host result available; an inaccessible daemon is an explicit coverage
warning. No Docker socket access is needed for host-only scanning.

## CLI

```sh
ca-trust-audit                                 # host + all running Docker containers
ca-trust-audit --host-only
ca-trust-audit --containers-only
ca-trust-audit --container webapp               # exact name or unique ID prefix
ca-trust-audit --offline                        # no live endpoint requests
ca-trust-audit --ca-file /opt/app/ca.pem         # repeat for extra PEM files
ca-trust-audit --ca-dir /opt/app/public-cas      # bounded, certificate-only traversal
ca-trust-audit --json report.json               # terminal + new mode-0600 JSON file
ca-trust-audit --json -                         # JSON only, on stdout
ca-trust-audit --verbose --timeout 10s --workers 4
ca-trust-audit --progress always                # stage updates on stderr, including CI
ca-trust-audit --color never                    # disable terminal colors
ca-trust-audit --strict
ca-trust-audit --version
```

Existing JSON files are never overwritten. Scan mode accepts no positional arguments;
`self-update` is a separate command and does not run a scan.
`--host-only` conflicts with `--containers-only` and `--container`.
`--container` selects only that container and must match one running container.
Additional CA paths apply **inside each selected target**; they are not host bind
mount instructions. Directory traversal examines `.crt`, `.pem` and `.0` entries
in explicitly designated trust directories, not unrelated application files.

`--timeout` is a per-operation deadline (default 10 seconds, range 1ms–5m), not a
whole-scan budget. Built-in runtime requests also impose a ten-second network
limit. `--workers` bounds concurrent **container targets** (default 4, range
1–64); chains and clients within a target are sequential. Signals propagate
cancellation; canceled scans return exit 2. Library callers can set an overall
context deadline. On a remote Docker daemon, canceled exec attachment may leave
the narrowly scoped client running until its own timeout; the scanner never kills
or restarts target processes to enforce a deadline.

| Exit | Exact meaning |
| --- | --- |
| 0 | No confirmed vulnerable client or store found; warnings/partial coverage may remain. |
| 1 | At least one `VULNERABLE_CLIENT` or `VULNERABLE_STORE`; takes precedence over strict coverage. |
| 2 | Invalid options, incident integrity failure, cancellation, report I/O error, or no selected targets could be scanned due to discovery/setup failure. |
| 3 | `--strict` only: no confirmed vulnerability, but supported TLS coverage is incomplete or Docker coverage has warnings. |

No running containers on an accessible daemon is a valid empty container scan.
Offline scans intentionally have incomplete live coverage, so `--strict --offline`
returns 3 unless there is a confirmed store vulnerability (1).

Terminal results use **PASSED** (the evaluated check rejected the compromised
chains), **PROBLEM** (confirmed acceptance), **NOT VERIFIED** (missing or incomplete
evidence), **REVIEW** (potential finding), and **UNSUPPORTED**. A passed CA-file
check does not imply that live client checks passed. JSON retains the precise
status codes documented below; exit codes are unchanged.

The final summary repeats each host/container with a confirmed problem, its name
and short container ID, and the affected clients/CA-file paths. Repeated chains
are grouped once per client or path; large lists show three entries plus the
remaining count (full paths/results remain in target details and JSON).
Incomplete coverage and potential findings
are highlighted separately, including when no confirmed problems were detected.

Interactive terminals use green **PASSED**, red **PROBLEM**, yellow **NOT VERIFIED**
and **REVIEW**, and gray **UNSUPPORTED** / **UNAVAILABLE**. Incomplete coverage is
yellow; complete coverage is cyan, not a claim of application safety. Labels remain
readable without color. `--color auto|always|never` defaults to `auto`: redirected
output, `TERM=dumb`, and a nonempty `NO_COLOR` disable automatic colors. `always`
explicitly overrides detection. JSON never contains presentation escape sequences.

Progress appears on **stderr** in interactive terminals. It shows the active
target/client or CA-file stage, elapsed time, and targets processed. The target
total becomes known after Docker discovery; this is a work counter, not a count
of passed security checks. A heartbeat updates elapsed time during slow requests.
`--progress auto|always|never` defaults to `auto`. Use `always` for plain stage logs
in CI or `never` for silent progress. Redirected output has no progress by default.
`--json -` keeps stdout exclusively JSON, even with progress explicitly enabled.

```text
[progress] container webapp: HTTPS positive control for PHP cURL | 1/4 targets processed | elapsed 8s
[progress] Scan finished | 4/4 targets processed | elapsed 21s
```

## Evidence and threat model

The scanner answers narrowly scoped questions about incident-related trust.

| Status | Evidence |
| --- | --- |
| `VULNERABLE_CLIENT` | A validating client accepted the exact pinned published test leaf; that leaf's signature is tied to the compromised intermediate key. |
| `VULNERABLE_STORE` | The explicit PEM/CT Go X.509 model accepted the full published chain, DNS name, validity and serverAuth EKU under that bundle. This is a model result, not every application's effective policy. |
| `POTENTIAL` | Related certificate/key material exists, but effective trust behavior is unestablished. Presence alone is never a confirmed vulnerability. |
| `REJECTED` | A certificate validation operation explicitly rejected the endpoint or the explicit PEM model rejected the chain. The reason can be expiry, hostname, unknown issuer, or another policy, not necessarily incident-specific distrust. |
| `INCONCLUSIVE` | DNS, timeout, connection/proxy failure, failed positive control, inaccessible file, unexpected peer, malformed output or another unresolved condition. |
| `NOT_SUPPORTED` | A relevant runtime/format cannot be evaluated reliably (for example Java JSSE, JKS, PKCS#12, NSS databases or OpenSSL AUX trusted PEM). |

Live and static findings never merge. A DNS error cannot count as rejection.
Every discovered live client gets its own positive-control request to
`https://example.com/`. If that fails, its incident requests are not attempted; results remain inconclusive
with `evidence.attempted:false`. This avoids repeated timeouts on broken connectivity.
An accepted live peer must have the exact published leaf SHA-256; a TLS-inspecting
proxy or endpoint certificate rotation produces `INCONCLUSIVE`, never a false
confirmed incident acceptance. Certificate rejection cannot authenticate the
rejected peer: interception can also cause rejection. Positive controls do not
rule out destination-specific filtering. Review proxy policy and detailed categories.

The published chain names/issuers identify the expected chain. Go's live probe
and successful offline validation include the actual selected root name/hash.
Other clients expose a pinned leaf but do not reliably expose the selected trust
anchor: their `root` field describes the **published issuer**, not a claimed
observed root. A changed server chain using the same compromised key can still
produce a real vulnerable-client finding without proving a particular cross-sign.

**Go 1.27.3 / 1.26.10 contain built-in eMudhra key distrust.** This is appropriate
for the live Go probe but would hide still-trusting PEM bundles from an offline
scanner. Static validation therefore uses Google's CT Go X.509 verifier against
the original unmodified certificates and the explicit PEM anchors. Its full
signature, time, hostname, basic/path/name constraints and serverAuth EKU checks
remain enabled. Tests require all fourteen actual published incident chains to
be accepted under deliberately trusting public roots and rejected under an empty
store, independently of the scanner's patched Go version.

The offline model does not implement every runtime's certificate-policy mapping,
CT rules, platform distrust or revocation defaults. It does not automatically
fetch CRLs/OCSP or read NSS/p11-kit/application policy. A `VULNERABLE_STORE` is a
confirmed acceptance under this explicitly documented model; a live application
may reject it through additional policy. A `REJECTED` store is not a global
assurance about other bundles or applications.
The library accepts explicit certificate/SPKI deny maps and signed current CRLs;
these apply only to the caller's supplied policy, not implicitly to every runtime.
Supplied expired CRLs make policy evaluation inconclusive. Raw PEM extraction
cannot express OpenSSL AUX trust attributes; those files are unsupported.

## Runtime coverage

| Client | Implementation and limitations |
| --- | --- |
| Go TLS | Native validating HTTP/TLS, local filesystem only. Measures the scanner's Go version, **not arbitrary Go applications**, including applications in containers. Honors Go system roots and `SSL_CERT_FILE` / `SSL_CERT_DIR`. |
| curl | Installed curl with peer certificate output (`%{certs}`, generally curl 7.88+). Old/missing introspection is unsupported. `-q` disables curlrc because it can contain insecure flags or file-writing commands; inherited CA environment and proxies remain in use. |
| PHP streams | PHP 8+ CLI with OpenSSL; verified TLS stream and captured peer certificate; php.ini CA settings remain applicable. This is a TLS stream check, not an HTTP body check. |
| PHP cURL | PHP CLI cURL extension; verification enabled, certificate info requested, response body discarded. Uses php.ini `curl.cainfo` and the extension's normal trust selection. |
| Python ssl/urllib | Python 3, default verified urllib configuration, peer DER fingerprint; no bytecode writes (`-B`). |
| Python requests/certifi | Both imports must succeed. Normal requests trust selection, including requests/curl bundle overrides; unsupported internal peer introspection is inconclusive. No package installation occurs. |
| Node.js HTTPS | In-memory `https` request and peer certificate fingerprint, normal roots plus `NODE_EXTRA_CA_CERTS`. `NODE_TLS_REJECT_UNAUTHORIZED=0` is refused as unsafe configuration. Proxy support depends on the installed Node version/configuration. |
| Ruby HTTPS | In-memory Net::HTTP/OpenSSL request with peer verification and peer DER fingerprint; unsupported peer introspection/warnings remain inconclusive. |
| Java JSSE | Executable presence detected; live execution explicitly unsupported because portable read-only inline JSSE execution is unavailable. No source/class files are written into targets. |

Discovery uses ordinary harmless version/import checks. A discovery failure is
reported as unavailable or failed discovery, never counted as a completed probe.
The tool cannot enumerate every embedded runtime, virtual environment, worker
user, JVM process option, language dependency or running process's custom policy.
Invoked CLI clients may differ from the long-running application in the same image.

## Trust-store discovery

Known Debian/Ubuntu/Alpine bundles, RHEL/Fedora bundles and extracted PEM stores,
`/etc/ssl/certs`, `/usr/local/share/ca-certificates`, and RHEL anchor directories
are inspected. Other distributions receive this same best-effort discovery.
Each checked file has an exact path in JSON; symlinks/duplicate bundles can yield
multiple path results. No broad filesystem, `/proc`, application-data or private-key
search occurs. Explicit directory flags support relevant mounted public CA directories.

The scanner reads only selected CA configuration:

- `SSL_CERT_FILE`, colon-separated `SSL_CERT_DIR`, `CURL_CA_BUNDLE`,
  `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `COMPOSER_CAFILE`;
- Python ssl default file/directory and installed certifi bundle location;
- PHP `openssl.cafile`, `openssl.capath` and `curl.cainfo` through narrowly scoped
  CLI ini queries (never `phpinfo`);
- common Java `cacerts`, `JAVA_HOME/lib/security/cacerts`, and absolute
  `-Djavax.net.ssl.trustStore=...` paths from `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`
  and `_JAVA_OPTIONS`. Complex quoted/relative JVM options or live process flags
  are not resolved; JKS/PKCS#12 are reported unsupported;
- common NSS `cert9.db` locations are reported unsupported.

Client `ca_paths` lists candidate environment overrides relevant to that client;
it does not prove actual consumption. Metadata-discovered PHP/Python paths are
analyzed separately. Composer JSON configuration, custom application configuration
files and per-process environments are not broadly read. Use `--ca-file` for
known overrides. There is no claim of exhaustive application coverage.

## Docker and minimal containers

Docker access uses the native Engine HTTP API (v1.41-compatible). Unix sockets and
explicit TCP/verified TLS endpoints are supported. `DOCKER_HOST` is respected.
When available, Docker CLI context metadata resolves the selected/default context;
`DOCKER_CONTEXT` takes precedence. Without the CLI, the default local socket or
explicit `DOCKER_HOST` still works. Remote TLS contexts require explicit
`DOCKER_HOST`, `DOCKER_CERT_PATH` and `DOCKER_TLS_VERIFY=1`; insecure context TLS
settings are refused. SSH and Windows named-pipe transports are unsupported.
No silent fallback to another daemon occurs after a context/endpoint error.

Read-only archive API requests retrieve known CA files and enumerate bounded
trust directories; archives are never extracted onto the host filesystem.
Symlinks are followed inside the target through at most eight archive requests.
A shell-less distroless or scratch target can be statically analyzed if it has a
supported public CA bundle. A scratch target with no bundle yields incomplete
coverage, not a claim of safety. Runtime probes use Docker exec with direct argv,
without a shell, installing software or writing helper files into the target.

To run the executable inside an existing container, place it there as part of
**your deployment/build process**, then execute it. The scanner itself never
copies itself into scanned targets. Host-only operation needs no socket:

```sh
/opt/ca-trust-audit --host-only --offline
```

For cross-container discovery from a container, provide an accessible Docker
endpoint. Mounting `/var/run/docker.sock` grants powerful daemon access even when
the bind mount is marked read-only: Docker API permissions, not filesystem mount
flags, authorize operations. Use a suitable daemon/API authorization policy. The
scanner only lists/inspects, reads archives and executes its narrowly scoped probes.

## Security, privacy and bounds

The scanner does not install software, modify trust stores, update certificates,
restart containers, change container configuration or disable TLS verification.
It never dumps environment variables, private keys or Docker credential config.
Container inspection necessarily receives Docker's configuration response in
memory; only the narrow CA configuration allowlist is retained. Raw subprocess
output and remote exception text are not included in reports. CA file paths,
container names/images, certificate identities and public endpoint names are
intentionally reported and may themselves be operationally sensitive.

File reads are limited to 8 MiB; Docker responses to 16 MiB; runtime output to
1 MiB. Directory enumeration is limited to 2,048 entries and target file lists
to 2,048 paths. Local directory traversal is depth-limited. Path reads must resolve
to regular files (nonblocking open prevents FIFO hangs). Local filesystem calls
on a hung kernel/network mount cannot always be interrupted by Go contexts.
Larger stores, unreadable directories and unsupported formats reduce coverage.
A Docker archive directory request may transfer non-certificate entries in that
**designated trust directory**, but those entries are neither extracted nor
analyzed; choose additional directories narrowly.

Live verification contacts third-party endpoints and may disclose the requesting
IP, client user-agent and connection metadata to their operators. It depends on
the continued availability and identity of those services. TLS proxies, network
policy and endpoint rotation may prevent conclusive live results. Offline mode
uses only the bundled verified snapshot and makes no intentional network requests.

Executing installed runtimes can execute runtime initialization, import hooks,
user configuration or plugins with client-specific side effects outside the
scanner's direct control (including unexpected network access). `-B` prevents
Python bytecode writes, not arbitrary import-hook behavior. Use a trusted target
and `--offline` if endpoint traffic is inappropriate; use the library with a nil
runner for static-only analysis without invoking any installed runtime.

## Go API

Build with Go 1.26+; CI/release pin the patched Go 1.27.3 toolchain. The exported
packages are `pkg/audit`, `pkg/certificates`, `pkg/docker`, `pkg/probes` and
`pkg/report`. GoDoc is part of the public API.

```go
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
defer cancel()
r, err := audit.Scan(ctx, audit.Options{
    IncludeHost: true,
    IncludeContainers: true,
    Online: true,
    Timeout: 10*time.Second,
    Workers: 4,
})
if err != nil { /* fatal error; r may contain partial results */ }
code := r.ExitCode(true)
_ = code
```

Zero options select both host and Docker with online checks. Once either
`IncludeHost` or `IncludeContainers` is true, those two booleans explicitly select
targets. `HostOnly`, `ContainersOnly` and `Container` are convenient overrides;
`Offline` always disables live probing (`Online` is a descriptive compatibility
field; its false zero value does not request offline mode).

For a custom filesystem or static-only embedded use:

```go
incident, err := audit.DefaultIncident()
if err != nil { /* bundled data failed integrity validation */ }
t := audit.ScanTarget(ctx, report.Target{Kind: "host", Name: "local"},
    audit.HostFiles{}, nil, nil, incident,
    audit.Options{Offline: true}) // nil runner: no external runtime execution
_ = t
```

`certificates.Evaluate(chain, roots, certificates.Policy{...})` evaluates an
explicit supplied root set; it never silently consults host system roots.
Public `Identity`, `Chain`, `Incident`, `Policy`, `Target`, `Finding`, `Evidence`,
`ClientCoverage`, `Coverage`, `TargetReport`, and `Report` types define the API.
The `Files` and `probes.Runner` interfaces permit bounded in-memory/custom targets.

Set `Options.Progress func(audit.Progress)` for optional stage notifications. `Scan`
serializes callbacks across its container workers; keep callbacks short. Events
describe work, not findings, and never modify report/JSON data. `Completed`/`Total`
refer to the event's phase; `PhaseTargetsDiscovered` supplies the selected target
count. Independent concurrent `Scan`/`ScanTarget` calls need caller synchronization.
Library rendering stays plain with `report.Terminal`; use
`report.TerminalWithOptions` and `report.TerminalOptions{Color: true}` to request
human colors explicitly.

### Representative PHP/Apache image

The optional repeatable test for `webdevops/php-apache:8.5-alpine` checks the image's
standard bundle against all fourteen actual incident chains, then tests PHP
OpenSSL streams and PHP cURL with a locally generated trusted/untrusted chain.
It uses an isolated read-only fixture container and read-only public CA mount.
It does not change an existing container or trust store.

```sh
docker pull webdevops/php-apache:8.5-alpine
CA_TRUST_AUDIT_PHP_IMAGE_TESTS=1 go test -v ./pkg/probes -run TestPHP85Image
CA_TRUST_AUDIT_PHP_IMAGE_TESTS=1 go test -v ./cmd/ca-trust-audit -run TestPHP85CLI
```

The image tag is mutable. Recorded validation for the tested digest and clear
store-versus-live results is in [docs/php85-test.md](docs/php85-test.md). Custom
CA mounts and runtime configuration in your deployed containers need scanning
as deployed, rather than assuming that a test of the base image covers them.

### Add an incident or runtime

Supply `Options.Incident` containing immutable public certificate identities and
leaf-first `Chains`, or add another reviewed embedded incident loader like
`internal/incidents/emudhra`. Pin upstream provenance and file digests, verify DER
and SPKI identities, signature relationships and hostnames, then add synthetic
positive/negative and actual-fixture tests. Do not download mutable data during
scans. Current CLI selects the bundled eMudhra incident; library callers can
supply another definition without rewriting the engine.

Implement `probes.Probe`: `Name`, bounded `Discover`, and `Check`. Pass probes in
`Options.Probes` (nil selects defaults; an empty slice disables external probes).
Return normalized `Result` categories and an observed leaf SHA-256 on acceptance.
The engine performs positive controls and pinned-identity checks. Never convert
transport errors to certificate rejection or infer another runtime's policy from
Go. Use direct argv and no target files. Add local TLS and malformed-output tests.

## JSON and CI

Schema version `1.0` is documented in [docs/json-schema.md](docs/json-schema.md).
The report records all per-chain outcomes, including successes suppressed in the
compact terminal view. No credentials or raw runtime responses are serialized.

```sh
# CI: 1 confirms a vulnerability, 3 rejects insufficient coverage.
ca-trust-audit --host-only --strict --json ca-report.json
```

The unit-test CI job requires no Docker daemon or public endpoint access.
`ci.yml` checks formatting, vet, unit tests, race detection, available runtime
probes on loopback HTTPS, and static Linux AMD64/ARM64 builds. A separate Docker integration job tests
shell-less containers and `webdevops/php-apache:8.5-alpine`, including its actual
incident-chain rejection and positive/negative PHP probes. The same job also
executes the standalone CLI against the PHP image, checking English labels,
JSON-only stdout, protected report files, and normal/strict/error exit codes. It uses the hosted
runner’s Docker Engine and pulls the representative image; no privileged test
containers or public incident endpoints are required. `release.yml`
validates/tests tags, builds both executables with version/commit/commit-time
metadata, emits SHA-256 checksums, and attaches them to a GitHub Release using
the standard token. Only the publishing job has `contents: write` permission.

## Build and test

```sh
go test ./...
go vet ./...
go test -race ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/ca-trust-audit-linux-amd64 ./cmd/ca-trust-audit
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o dist/ca-trust-audit-linux-arm64 ./cmd/ca-trust-audit

# Explicitly enable installed-runtime loopback integration (no public endpoints):
CA_TRUST_AUDIT_RUNTIME_TESTS=1 go test -v ./pkg/probes -run TestInstalledRuntimeTLS

# Disposable real Docker scratch fixtures: no registry pulls, no network/privileged containers:
CA_TRUST_AUDIT_DOCKER_TESTS=1 go test -v ./pkg/audit -run TestRealDockerShellless

# Read-only check of an existing running container with a known bundle:
CA_TRUST_AUDIT_DOCKER_TESTS=1 CA_TRUST_AUDIT_TEST_CONTAINER=webapp go test -v ./pkg/docker -run TestEngineArchive

# Third-party endpoint suite; requires Internet access and discloses connection metadata:
CA_TRUST_AUDIT_NETWORK_TESTS=1 go test -v ./pkg/probes -run TestPublishedEndpoints
```

Optional suites explicitly skip when not enabled; installed-runtime subtests
explicitly skip missing runtimes/modules. Enabled network checks fail on
inconclusive results. Synthetic cryptographic tests, Engine API fixtures,
conflicting container stores, errors, cancellation, serialization and exit
classification run without Docker or external network access.

See [fixture provenance](internal/incidents/emudhra/PROVENANCE.md) for source,
upstream limitations and integrity details. Project source is [MIT](LICENSE).
