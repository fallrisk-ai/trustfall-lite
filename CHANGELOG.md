# Changelog

All notable changes to Trustfall Lite are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

When a release is tagged, the `## [Unreleased]` section is renamed
to `## [VERSION] - YYYY-MM-DD` and a new empty `## [Unreleased]`
section is added at the top.

---

## [Unreleased]

### Added

### Changed

### Fixed

### Deprecated

### Removed

### Security

---

## [0.3.0] - 2026-05-03

### Added

- `trustfall diff` command for comparing two scan-output JSON
  reports. Detects six change classes: `group_added`,
  `group_removed`, `artifact_added`, `artifact_removed`,
  `artifact_changed`, `status_changed`. Identity is the
  `(source, group_id)` tuple per `DIFF_SPEC.md` §3.
- `trustfall diff` supports two invocation forms:
  - Explicit: `trustfall diff baseline.json current.json`
  - Implicit current: `trustfall diff baseline.json` runs a fresh
    default-scope scan and compares against the baseline.
- Implicit-current safety refusal: if the baseline used explicit
  `scan_paths`, `trustfall diff baseline.json` exits 64 with an
  actionable message rather than silently scanning a different
  scope. See `DIFF_SPEC.md` §3.5.
- `--exit-code` flag on `trustfall diff` for CI integration: exits
  1 if any change is detected.
- `--exit-code-on-status-regression` flag on `trustfall diff`:
  exits 2 only when a previously `verified` scan group moves to a
  non-verified status. Improvements (e.g., `unknown_variant` →
  `verified`) do not trigger this flag.
- `trustfall diff --json` emits a stable diff schema (schema
  version 0.3.0) suitable for consumption by downstream tooling.
  Schema documented in `DIFF_SPEC.md` §7.
- Forbidden-phrases enforcement on diff text output: the rendered
  text never includes "compromised", "tampered", "fake",
  "malicious", or "trojan", regardless of what changed.
- New documentation files:
  - `TRUST_MODEL.md` — what the cryptographic claims are
  - `LIMITATIONS.md` — what the tool does not claim
  - `PRIVACY.md` — what data is and is not sent
  - `SECURITY.md` — how to report security issues
  - `CONTRIBUTING.md` — contribution guidelines and DCO
  - `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1
  - `DIFF_SPEC.md` — frozen specification for the diff command

### Changed

- Bumped Python package version to 0.3.0.
- README example output now reflects the actual formatter
  rendering, matching what the v0.3.0 binary actually produces.
  Earlier mockups showed a fabricated banner format that the tool
  does not emit.
- Status counts in the rendered text summary now use human-prose
  labels ("verified artifact", "unknown variant", "not enrolled",
  "pilot enrollment available") to match the formatter source.
  Machine-readable values (`verified`, `unknown_variant`,
  `not_enrolled`, `pilot_available`) remain unchanged in JSON
  output.

### Fixed

- Doc/code drift: INSTALL.md previously claimed a verification
  date that could not be re-attested; now cites the verification
  chain explicitly per the runbook hash discipline rule.

### Deprecated

- (none)

### Removed

- (none)

### Security

- (none in this release)

### Release process

<!--
The lines below are filled in only after Block C release-chain
rehearsal confirms each one is actually true for this release.
A line should not appear here if its underlying mechanism has
not yet been verified end-to-end.

To be added once Block C completes:

- Released via PyPI Trusted Publishing (no long-lived API tokens).
- GitHub Actions build provenance attached to wheel and sdist artifacts.
- SHA256SUMS published alongside wheel + sdist on the GitHub Release.
- CycloneDX SBOM (sbom.cdx.json) attached to the GitHub Release.
- Reproducible builds where the source tree supports it.
-->
