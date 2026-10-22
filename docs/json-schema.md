# JSON report schema 1.0

`--json -` writes exactly one UTF-8 JSON document. `--json PATH` creates a new
mode-0600 file and retains terminal output. JSON field names and status meanings
are stable within major version 1; consumers should ignore unknown added fields
and handle unknown future enum values conservatively. Empty arrays can be `[]`
or `null`; optional fields can be absent. Counts are nonnegative integers.

| Object | Fields |
| --- | --- |
| Report | `schema_version` ("1.0"), `incident` (string), `generated_at` (RFC3339 UTC), `targets` (TargetReport array), `warnings` (string array), `summary` (Summary) |
| TargetReport | `target` (Target), `findings` (Finding array), `coverage` (Coverage), `trust_stores` (TrustStore array) |
| Target | `kind` ("host" or "container"), `name`, optional `id` (full Docker ID) and `image` |
| Finding | `status`, `method` ("live", "store", "material"), `usage` ("tls", "code-signing", "ca-material"), optional `client`, `path`, `chain`, `intermediate`, `root`, `endpoint`, `remediation`; `evidence` (Evidence) |
| TrustStore | `path`, `format`, `model`, `status`, `expected`, `accepted`, `rejected`, `other` (counts per explicit store) |
| Evidence | `model`, `detail`, optional `attempted` (boolean for live chain requests), `category`, `leaf_sha256`, `intermediate_sha256`, `spki_sha256`, `root_sha256` (lowercase hexadecimal SHA-256 without colons) |
| Coverage | `complete` (boolean), `stores` (parsed/evaluated explicit PEM file count), `clients` (ClientCoverage array), `limitations` (string array) |
| ClientCoverage | `name`, `discovered` (boolean), `tested`, `expected`, optional `reason`, `ca_paths` (candidate client-relevant override paths, **not verified consumption**) |
| Summary | `targets`, `hosts`, `containers`, `vulnerable_clients`, `vulnerable_stores`, `incomplete_targets` |

Statuses: `VULNERABLE_CLIENT`, `VULNERABLE_STORE`, `POTENTIAL`, `REJECTED`,
`INCONCLUSIVE`, `NOT_SUPPORTED`. See the README for evidence requirements.

`tested` counts only conclusive rejected or pinned-accepted live chains with a
working client-specific positive control. It excludes unsupported, offline,
unexpected-peer, failed-control, timeout and transport results. `expected` is 14
for active probes in the bundled snapshot (twelve regular and two no-CT endpoints).
`stores` does not assert independent runtime policy coverage. `complete` is scoped
to supported TLS checks on the enumerated paths/clients; it never means all
applications are safe or code-signing trust is validated. Explicit Java presence,
unsupported store formats and live failures
reduce coverage. Missing optional runtimes are not automatically failures.

Summary vulnerability counts deduplicate by target/client or target/path, not by
chain. A single client accepting fourteen chains counts as one vulnerable client.
Paths referring to the same file via different symlinks are distinct reported
paths. `incomplete_targets` counts target reports with `complete:false`.
Global Docker warnings also trigger strict exit 3 even if no target was discovered.

For a live external-client finding, `root` is the **published chain issuer** when
an actual verified trust anchor was not exposed. `root_sha256`, when present,
identifies the actual selected anchor (native Go or explicit store evaluation).
`intermediate_sha256` normally identifies the pinned published intermediate;
Go live acceptance records its actual verified intermediate. The observed leaf
hash establishes compromise-key linkage, but does not alone establish which
cross-sign an external client selected. `chain` is the fixture/endpoint ID.

Categories are diagnostic strings; consumers must use `status` for classification.
Examples include `certificate_validation`, `dns`, `timeout`, `connection_or_proxy`,
`positive_control_failed`, `unexpected_peer_or_proxy`, `file_unavailable`,
`untrusted_issuer`, `expired_or_not_yet_valid`, `verifier_policy`, and
`policy_unavailable`. Raw exceptions/subprocess output are excluded to prevent
credential disclosure. `detail` is concise human-readable evidence, not a stable
machine enum.

Example excerpt (not a complete report):

```json
{
  "status": "INCONCLUSIVE",
  "method": "live",
  "client": "curl",
  "usage": "tls",
  "chain": "dv-g3b-aaa-emudhra.we-have-a-problem.com",
  "intermediate": "EM DV TLS CA - G3B",
  "root": "AAA Certificate Services",
  "evidence": {
    "model": "runtime TLS validation",
    "category": "positive_control_failed",
    "detail": "positive control failed: dns; incident result cannot establish working validation"
  }
}
```

When a client’s positive control fails, incident endpoint requests are not attempted.
Each affected finding is `INCONCLUSIVE`, with `evidence.attempted:false` and
`category:positive_control_failed`. An attempted but inconclusive request has
`attempted:true`; static evidence omits this field.
