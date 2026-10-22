# Changelog

## v0.2.2

- Add `self` as an alias for `self-update`, including all existing update options.
- Highlight command suggestions in self-update permission errors in cyan, with
  automatic terminal detection, `NO_COLOR` and `--color auto|always|never`.
- Use conservative ETAs with twice the slowest completed container duration,
  generous initial budgets and a 10-second buffer. Slow targets expand the numeric
  estimate rather than getting stuck at one second or losing the estimate.
- Parallelize per-client TLS chain requests, with a global `--workers` limit shared
  by all targets and positive controls; retain deterministic evidence and progress.
- Add a minimal SVG trust diagram and restructure the README with navigation,
  command/result tables and a complete linked technical reference.

## v0.2.1

- Explain the incident, urgency, remediation and CVE-2026-111943 at the top of the
  README, with relevant certificate-trust and runtime search keywords.
- Default container workers to the available logical CPU count (`nproc` equivalent)
  in both the CLI and Go API; keep explicit positive `--workers` overrides.
- Add `--host` as an alias for `--host-only`, with the same selection conflicts.
- Stabilize parallel scan progress: counters/times first, target last, a shared
  four-per-second redraw limit, terminal-width fitting and an estimated time to
  finish based on completed container timings and worker concurrency.

## v0.2.0

- Add terminal progress with elapsed time, target counts and per-client stages.
  Redirected progress is opt-in; JSON stdout remains clean.
- Color human results by meaning, with `--color` and `NO_COLOR` support.
- Repeat affected containers/hosts and their clients/CA paths in the final summary.
  Keep confirmed problems, potential findings and incomplete coverage separate.
- Add `self-update` (`selfupdate` alias), `--check` and `--force`. Updates select
  AMD64/ARM64, use verified HTTPS, check standalone Go/ELF metadata, and replace
  the executable atomically. No external tools or checksum downloads are required.
- Extend race, stream-separation and PHP 8.5 CLI integration coverage.

## v0.1.1

- Remove checksum downloads/checks from the automatic architecture-aware installer.

## v0.1.0

- Initial Go library and standalone Linux AMD64/ARM64 CLI for eMudhra trust audits.
- Add verified incident fixtures, separate live/runtime and PEM-store evidence,
  Docker archive analysis, JSON reporting, tests and GitHub release workflows.
