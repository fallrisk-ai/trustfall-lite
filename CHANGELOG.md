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

## [0.4.0] - 2026-05-18

### Added

- `trustfall scan` now prints the scan roots it inspected (the
  Hugging Face cache, Ollama, LM Studio detection, and any explicit
  paths), with honesty markers distinguishing absent, configured-but-
  broken, and detected-not-scanned roots, so it is always visible what
  was and was not scanned.
- `trustfall scan --export PATH` writes a flat inventory of the scan
  result to a local CSV or JSONL file. Format is chosen from the
  `.csv` / `.jsonl` extension. The export writer itself adds no
  upload, network, or daemon; the scan it consumes still follows the
  selected mode (a default scan may query the verification API;
  `--local-only` performs no per-scan network lookup).
- `--export-include-paths` flag: opt in to two additional filesystem
  path columns (`cache_root_path`, `artifact_paths`) in the export.
  This is a separate, distinct flag from the existing network-side
  `--include-paths`; neither implies the other.
- New module `roots.py`: the single `resolve_scan_roots()` source of
  truth for scan-root resolution and display.
- New module `export.py`: the pure CSV/JSONL export sink (no network
  imports; enforced by an import-allowlist test).
- New documentation file `docs/INVENTORY_EXPORT.md`: the authoritative
  export schema (every column, type, null rule, derivation, per-lane
  bound-digest rule, provenance rules, and the display-vs-export path
  asymmetry), reachable from the test suite so doc/output drift fails.
- Export columns `tokenizer_surface_coverage` (an artifact-identity
  coverage signal, not a tokenizer security verdict),
  `registry_manifest_digest` (the signed snapshot's manifest digest,
  copied verbatim, never recomputed), and `trustfall_version` (the
  running version, injected by the caller).

### Changed

- `trustfall scan --json` gains an additive `scan_roots` key
  describing the roots inspected. Existing JSON keys are unchanged;
  this is purely additive.
- Hugging Face and Ollama scan-root resolution refactored behind the
  shared `resolve_scan_roots()` so the displayed roots cannot disagree
  with the adapters that actually run. No behavior change to discovery;
  the existing adapter test suites pass byte-unchanged.

### Fixed

### Deprecated

### Removed

### Security

### Notes
- The signed model registry is updated frequently and independently of
  tool releases. Run `trustfall registry --refresh` after install or
  upgrade to fetch the latest signed snapshot. `trustfall registry`
  commands operate against the last fetched snapshot; `--local-only`
  verification uses that cached snapshot and does not contact the
  registry. A stale local snapshot can report a model as "not enrolled"
  that is in fact present in a newer registry — `--refresh` resolves this.

---

## [0.3.2] - 2026-05-03

### Fixed

- `trustfall version` now correctly reports the installed package version.
  Previously the version string was hardcoded in `__init__.py` and not
  bumped in 0.3.1, causing the command to print "0.3.0" against a 0.3.1
  install. The version is now read dynamically via `importlib.metadata`,
  preventing this synchronization bug class permanently.

---

## [0.3.1] - 2026-05-03

### Added

- `readme = "README.md"` field in `pyproject.toml` so the PyPI project page
  renders the project's README.md. Previously the page showed "no description."
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
