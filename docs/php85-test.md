# PHP/Apache 8.5 Alpine validation

Tested on 2026-10-22, Linux AMD64:

- Image: `webdevops/php-apache:8.5-alpine`
- Registry digest: `sha256:661d98b805ce04ade3e30a1107ec341348ad5b74ef7f2e30d08ea8fd619f3ea5`
- Local image ID: `sha256:859817bd312c28f313dbd75abcce60ca611dc0d8e378759fc5b3e61753e53aac`
- PHP: `8.5.12`; OpenSSL and cURL extensions present.

**The tested image's standard CA bundle rejects all 14 published eMudhra test
chains because their issuers are untrusted.** The image's standard files contain
no matched incident-related CA keys. This is a confirmed result under the
explicit offline PEM validation model, independent of the scanner Go runtime's
eMudhra denylist. It applies to these files in this exact image state.

The actual deployed application can use another bundle, another image digest or
custom runtime settings. Scan that running container to inspect those paths.
This base-image result is not a blanket assurance about arbitrary deployments.

The public-endpoint live scan in this onboarding environment was **inconclusive**:
client positive controls could not establish usable verified HTTPS connectivity.
This does not mean the image is vulnerable. It means the online portion could
not verify actual PHP behavior against the remote incident servers. The required
hostnames were saved in the environment configuration draft; that draft must be
applied/published before network availability can be revalidated.

The ordinary scanner output now explicitly separates these conclusions:

```text
CA FILES: PASSED — the checked CA files rejected all incident test chains under the documented PEM validation model.
LIVE CLIENTS: NOT VERIFIED — offline mode; live checks were not run.
Store /etc/ssl/cert.pem: PASSED (14/14 chains rejected; accepted=0; unresolved=0)
Store /etc/ssl/certs/ca-certificates.crt: PASSED (14/14 chains rejected; accepted=0; unresolved=0)
```

An independently repeatable local TLS integration test uses the same image and
checks both directions for both PHP APIs, without depending on Internet access:

```text
=== RUN   TestPHP85Image
    image standard CA bundle: REJECTED 14/14 actual published eMudhra chains (untrusted issuer)
=== RUN   TestPHP85Image/PHP_OpenSSL_streams
    trusted synthetic compromised chain: VULNERABLE_CLIENT; pinned leaf matched
    unmodified system store rejecting synthetic chain: REJECTED (certificate_validation)
=== RUN   TestPHP85Image/PHP_cURL
    trusted synthetic compromised chain: VULNERABLE_CLIENT; pinned leaf matched
    unmodified system store rejecting synthetic chain: REJECTED (certificate_validation)
--- PASS: TestPHP85Image
```

Here `VULNERABLE_CLIENT` is the **expected positive-test outcome**: the test creates
its own synthetic CA, configures only an ephemeral PHP process to trust it, and
requires the probe to recognize the accepted synthetic incident certificate.
That line does not report a real eMudhra vulnerability in the image. The negative
test uses the image's unmodified system roots and must reject the same synthetic
certificate. Both checks pass for PHP streams and PHP cURL.

The test exposed and fixed PHP 8.5's deprecated `curl_close()` warning interfering
with structured probe output. The streams probe also now captures certificate
verification warnings separately from connection errors. No certificate
verification is disabled. Test fixture CA files are mounted read-only; the test
containers use read-only filesystems and no extra capabilities. Default webserver
startup is replaced by a PHP sleep process because this test concerns CA trust,
not Apache application startup. No existing application container is changed.

Repeat the controlled test:

```sh
docker pull webdevops/php-apache:8.5-alpine
CA_TRUST_AUDIT_PHP_IMAGE_TESTS=1 go test -v ./pkg/probes -run TestPHP85Image -count=1
```

Run the scanner against your real running container:

```sh
ca-trust-audit --container YOUR_CONTAINER --offline
ca-trust-audit --container YOUR_CONTAINER --timeout 10s --json YOUR_NEW_REPORT.json
```

The opt-in image integration expects the tested image line to keep rejecting the
published chains. If a future tag regresses its CA data, that assertion fails.
Pin the digest to reproduce the recorded image state. ARM64 binaries are built;
this image integration was executed on AMD64 only.

The CI workflow runs this test in its separate `docker-integration` job after
pulling the requested image. The unit-test job remains independent of Docker.

The `TestPHP85CLI` integration builds a standalone executable and scans a separate
network-disabled PHP fixture. It checks `PASSED`/`NOT VERIFIED` terminal wording,
JSON-only stdout, the exact container and CA-file identities, mode-0600 report
files, refusal to overwrite reports, and exits 0 (normal), 3 (strict incomplete)
and 2 (existing report). A separate read-only public-root test bundle, explicitly
selected with `--ca-file`, must accept all fourteen incident chains, produce
`CA FILES: PROBLEM`, and exit 1 even with `--strict`. The image’s original bundles
remain unchanged and continue to pass. It also checks that a dummy non-CA environment secret
never appears in terminal, stderr or JSON. This runs in the Docker CI job.
