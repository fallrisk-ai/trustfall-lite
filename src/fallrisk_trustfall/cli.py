"""
Trustfall Lite CLI.

Per spec §4 the v0.1 commands are:
    trustfall scan [PATH...] [--local-only] [--include-paths] [--json] [--quiet]
    trustfall verify HASH [--json]
    trustfall registry [--refresh] [--info] [--fingerprint]
    trustfall version

Wiring:
    adapters → hashing → scanner → formatter (default text)
                                  → JSON renderer (--json)

The CLI is the only module that touches I/O, sys.exit, and argv.
Everything below it is library code.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import click
import httpx

from . import __version__
from .adapters import HFCacheAdapter, OllamaAdapter, PathAdapter
from .api import TrustfallAPI, DEFAULT_BASE_URL
from .diff import (
    diff_scans,
    render_diff_as_dict,
    render_diff_as_text,
)
from .formatter import (
    FileResult,
    Status,
    render_file_line,
    render_results_as_dict,
    render_summary,
    status_icon,
    status_label,
)
from .hashing import (
    hash_groups,
    total_artifacts,
    total_bytes,
    unique_artifacts,
    unique_bytes,
    was_filename_trusted,
)
from .models import ModelGroup
from .export import ExportError, export_inventory
from .roots import ScanRoot, resolve_scan_roots
from .registry import (
    DEFAULT_REGISTRY_URL,
    LoadedSnapshot,
    SnapshotError,
    ensure_snapshot_dir,
    load_bundled_jwks,
    load_snapshot,
    snapshot_path,
)
from .scanner import (
    APIHashLookup,
    HashLookup,
    LocalHashLookup,
    GroupScanResult,
    verify_groups,
)


# ════════════════════════════════════════════════════════════════════
# Root group
# ════════════════════════════════════════════════════════════════════


@click.group(
    help=(
        "Trustfall Lite — local artifact verifier for the Fall Risk "
        "model identity registry."
    )
)
@click.version_option(version=__version__, prog_name="trustfall")
def main() -> None:
    pass


# ════════════════════════════════════════════════════════════════════
# trustfall scan
# ════════════════════════════════════════════════════════════════════


@main.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=False, path_type=Path))
@click.option(
    "--local-only",
    is_flag=True,
    help="Verify against the local cached snapshot. No network traffic.",
)
@click.option(
    "--include-paths",
    is_flag=True,
    help="Send relative path hints to the API (off by default for privacy).",
)
@click.option(
    "--export",
    "export_path",
    type=click.Path(exists=False, path_type=Path),
    default=None,
    help=(
        "Write a flat inventory audit file. Extension selects the format: "
        ".csv or .jsonl (any other extension exits 70 before scanning). "
        "Overwrites an existing file. Never contains filesystem paths "
        "unless --export-include-paths is also passed."
    ),
)
@click.option(
    "--export-include-paths",
    is_flag=True,
    help=(
        "Include local filesystem paths in the --export file "
        "(off by default for privacy). Independent of --include-paths, "
        "which only governs API path hints."
    ),
)
@click.option("--json", "output_json", is_flag=True, help="Emit JSON output.")
@click.option("--quiet", is_flag=True, help="Suppress progress output.")
@click.option(
    "--trust-ollama-filenames",
    is_flag=True,
    help=(
        "For Ollama blobs only: trust the SHA-256 embedded in the on-disk filename "
        "instead of hashing each blob. Faster but assumes the local filesystem is "
        "honest about filename↔content. Default: hash every blob."
    ),
)
@click.option(
    "--api-base",
    default=DEFAULT_BASE_URL,
    show_default=True,
    help="Override the API base URL (advanced).",
)
def scan(
    paths: tuple[Path, ...],
    local_only: bool,
    include_paths: bool,
    export_path: Path | None,
    export_include_paths: bool,
    output_json: bool,
    quiet: bool,
    trust_ollama_filenames: bool,
    api_base: str,
) -> None:
    """Scan paths for model artifacts and verify against the registry."""

    # --- 0. Validate --export options BEFORE any scanning ----------
    # Spec §5 / T-PRIV-4: --export-include-paths without --export is a
    # usage error (exit 70). Catch it first — it is meaningless without
    # an export target and must not silently no-op after a full scan.
    if export_include_paths and export_path is None:
        _eprint(
            "error: --export-include-paths requires --export "
            "(it controls what the export file contains). Nothing was "
            "scanned."
        )
        sys.exit(70)

    # Spec §3.7 / §7: a bad export extension is an export-config error
    # (exit 70) that must fail fast — before discovery, hashing, or any
    # network — so the user is not made to wait for a scan that cannot
    # produce the file they asked for. Empty/garbled extension included.
    export_fmt: str | None = None
    if export_path is not None:
        ext = export_path.suffix.lower()
        if ext == ".csv":
            export_fmt = "csv"
        elif ext == ".jsonl":
            export_fmt = "jsonl"
        else:
            _eprint(
                f"error: --export path must end in .csv or .jsonl "
                f"(got {export_path.name!r}). Nothing was scanned."
            )
            sys.exit(70)

    # --- 1. Build the adapter chain ---------------------------------
    groups = list(_discover_groups(paths))

    # --- 1a. Resolve scan roots (F1, spec §2) — BEFORE no-groups ----
    # GPT Step-3 blocking patch 3: roots transparency is needed MOST
    # when the scan finds nothing ("what did we even look at?"). The
    # roots view must therefore be resolved before the no-groups exit,
    # not after. Invocation-aware (GPT Step-3 blocking patch 1): when
    # the user supplied explicit paths, report THOSE; otherwise the
    # default/env roots. Pure: no network, no hashing, no .discover().
    scan_roots = _resolve_scan_roots_for_invocation(paths)

    if not groups:
        # F1 transparency on the empty scan. Roots view first (the
        # answer to "what did we look at?"), then the existing
        # no-artifacts message / JSON error. --export still produces a
        # well-formed 0-row inventory so empty scans are pipeline-safe.
        if not output_json:
            if not quiet:
                _eprint_scan_roots(scan_roots)
            _eprint("No model artifacts found in the scanned paths.")
            _eprint("Hint: pass a path explicitly, e.g.  trustfall scan ~/.cache/huggingface/hub/")
        else:
            click.echo(json.dumps({
                "error": "no model artifacts found",
                "scan_roots": _scan_roots_as_json(scan_roots),
            }, indent=2))

        if export_path is not None:
            assert export_fmt in ("csv", "jsonl")  # §0 guaranteed this
            scanned_at = _utc_now_iso8601()
            manifest_digest = _resolve_manifest_digest_for_export()
            try:
                n_rows = export_inventory(
                    [],            # zero groups → header-only CSV / empty JSONL
                    scan_roots,
                    fmt=export_fmt,  # type: ignore[arg-type]
                    out_path=export_path,
                    include_paths=export_include_paths,
                    scanned_at=scanned_at,
                    trustfall_version=__version__,
                    registry_manifest_digest=manifest_digest,
                )
            except ExportError as exc:
                _eprint(f"error: export failed: {exc}")
                sys.exit(70)
            if not quiet:
                msg = f"Wrote {n_rows} rows to {export_path} ({export_fmt})."
                if export_include_paths:
                    msg += (
                        " [paths INCLUDED — file contains absolute "
                        "filesystem paths]"
                    )
                _eprint(msg)

        sys.exit(0)

    # --- 1a. Print discovery banner per source ----------------------
    # Ollama detection notice (verify-by-default UX): if Ollama groups were
    # found and the user did NOT pass --trust-ollama-filenames, surface the
    # mode choice up front so they understand what's happening before the
    # hashing wait. Per Anthony + GPT (April 27 2026): default is verify.
    ollama_groups = [g for g in groups if g.source == "ollama"]
    if not output_json and not quiet:
        if ollama_groups and not trust_ollama_filenames:
            ollama_bytes = sum(a.size_bytes for g in ollama_groups for a in g.artifacts)
            if ollama_bytes >= 30 * 10**9:  # 30 GB threshold for the notice
                click.echo(
                    f"Ollama store detected: {_format_bytes(ollama_bytes)} of model blobs."
                )
                click.echo(
                    "Trustfall verifies blob digests by default. "
                    "This may take several minutes."
                )
                click.echo(
                    "Use --trust-ollama-filenames to skip full hashing and "
                    "trust Ollama's on-disk digest names."
                )
                click.echo("")

        click.echo(
            f"Discovered {len(groups)} model group(s) ({total_artifacts(groups)} artifacts, "
            f"{_format_bytes(total_bytes(groups))}). Hashing..."
        )

    # --- 2. Hash all artifacts --------------------------------------
    hashed_groups = hash_groups(
        groups,
        progress=None,  # progress UI deferred to a future release
        trust_ollama_filenames=trust_ollama_filenames,
    )

    # --- 3. Build the lookup (API or local) -------------------------
    if local_only:
        lookup = _build_local_lookup_or_die()
    else:
        lookup = _build_api_lookup(
            hashed_groups, include_paths=include_paths, api_base=api_base, quiet=quiet
        )
        if lookup is None:
            # Couldn't reach API; fall back to local snapshot per spec §6.2
            if not quiet and not output_json:
                _eprint("API unreachable; falling back to local snapshot.")
            lookup = _build_local_lookup_or_die()

    # --- 4. Verify groups -------------------------------------------
    results = verify_groups(hashed_groups, lookup)

    # --- 4a. Roots block → stderr (spec §2.6) -----------------------
    # scan_roots was resolved BEFORE the no-groups branch (§1a) so the
    # empty-scan path can also report it (GPT Step-3 patch 3). It is
    # invocation-aware (GPT Step-3 patch 1): explicit paths report
    # what was actually scanned, not the default/env roots. Do NOT
    # re-resolve here — a second resolve_scan_roots() would (a) be
    # redundant and (b) silently DROP invocation awareness, the exact
    # disagreement patch 1 fixes.
    #
    # stderr so it never contaminates --json stdout or a piped export.
    # Suppressed by --quiet *and* --json, exactly like the existing
    # discovery banner above (`if not output_json and not quiet`).
    # Under --json the scan-roots data is delivered structurally via
    # the additive §2.7 `scan_roots` key, not as a stderr side-channel.
    if not output_json and not quiet:
        _eprint_scan_roots(scan_roots)

    # --- 4c. Export (spec §3/§4) ------------------------------------
    # Run scalars are injected HERE (the I/O layer), never read inside
    # export.py: scanned_at from the clock, trustfall_version from the
    # package, registry_manifest_digest verbatim from the resolved
    # snapshot (Authority Doctrine — never recomputed; empty if no
    # snapshot, never fabricated). export.py stays a pure sink.
    if export_path is not None:
        assert export_fmt in ("csv", "jsonl")  # §0 guaranteed this
        scanned_at = _utc_now_iso8601()
        manifest_digest = _resolve_manifest_digest_for_export()
        try:
            n_rows = export_inventory(
                results,
                scan_roots,
                fmt=export_fmt,  # type: ignore[arg-type]
                out_path=export_path,
                include_paths=export_include_paths,
                scanned_at=scanned_at,
                trustfall_version=__version__,
                registry_manifest_digest=manifest_digest,
            )
        except ExportError as exc:
            _eprint(f"error: export failed: {exc}")
            sys.exit(70)
        # Confirmation → stderr. Spec §5: gated by --quiet ONLY (NOT
        # --json — line 430 explicitly supports `scan --json --export
        # inv.csv` simultaneously: JSON on stdout, CSV file, stderr
        # confirmation). Exact spec wording; path-bearing exports carry
        # an explicit warning so the user knows before attaching to a
        # ticket.
        if not quiet:
            msg = f"Wrote {n_rows} rows to {export_path} ({export_fmt})."
            if export_include_paths:
                msg += (
                    " [paths INCLUDED — file contains absolute "
                    "filesystem paths]"
                )
            _eprint(msg)

    # --- 5. Render output -------------------------------------------
    if output_json:
        _render_json_scan(
            results,
            scan_paths=paths,
            include_paths=include_paths,
            trust_ollama_filenames=trust_ollama_filenames,
            scan_roots=scan_roots,
        )
    else:
        _render_text_scan(results, quiet=quiet)


# ════════════════════════════════════════════════════════════════════
# trustfall verify HASH
# ════════════════════════════════════════════════════════════════════


@main.command()
@click.argument("sha256")
@click.option("--json", "output_json", is_flag=True, help="Emit JSON output.")
@click.option("--api-base", default=DEFAULT_BASE_URL, show_default=True)
def verify(sha256: str, output_json: bool, api_base: str) -> None:
    """Look up a single SHA-256 in the registry."""
    sha256 = sha256.lower().strip()
    jwks = load_bundled_jwks()

    with TrustfallAPI(jwks=jwks, base_url=api_base) as api:
        result = api.verify_hash(sha256)

    if output_json:
        if result.status == "verified" and result.record:
            click.echo(json.dumps({
                "sha256": result.sha256,
                "status": "verified",
                "record_jws": result.record.record_jws,
                "claims": result.record.claims,
                "registry_kid": result.record.registry_kid,
                "registry_snapshot_at": result.record.registry_snapshot_at,
            }, indent=2))
        elif result.status == "not_enrolled":
            click.echo(json.dumps({"sha256": sha256, "status": "not_enrolled"}, indent=2))
        else:
            click.echo(json.dumps({
                "sha256": sha256, "status": "error",
                "error_message": result.error_message or "",
            }, indent=2))
            sys.exit(2)
        return

    # Text mode
    if result.status == "verified" and result.record:
        c = result.record.claims
        click.echo(f"\u2713 verified")
        click.echo(f"  sha256: {sha256}")
        click.echo(f"  model_id: {c.get('model_id', '?')}")
        if c.get("publisher"):
            click.echo(f"  publisher: {c['publisher']}")
        if c.get("license"):
            click.echo(f"  license: {c['license']}")
        click.echo(f"  enrollment_id: {c.get('enrollment_id', '?')}")
        click.echo(f"  enrollment_date: {c.get('enrollment_date', '?')}")
        click.echo(f"  registry_kid: {result.record.registry_kid or '?'}")
    elif result.status == "not_enrolled":
        click.echo(f"? not enrolled")
        click.echo(f"  sha256: {sha256}")
    else:
        _eprint(f"error: {result.error_message or 'unknown error'}")
        sys.exit(2)


# ════════════════════════════════════════════════════════════════════
# trustfall registry
# ════════════════════════════════════════════════════════════════════


@main.command()
@click.option("--refresh", is_flag=True, help="Fetch the latest signed registry snapshot.")
@click.option("--info", is_flag=True, help="Print snapshot metadata.")
@click.option("--fingerprint", is_flag=True, help="Print the issuer key fingerprint.")
@click.option(
    "--registry-url",
    default=DEFAULT_REGISTRY_URL,
    show_default=True,
    help="Override the registry source URL (advanced).",
)
def registry(refresh: bool, info: bool, fingerprint: bool, registry_url: str) -> None:
    """Inspect and manage the local registry snapshot."""

    if fingerprint:
        _print_fingerprint()
        return

    if refresh:
        _refresh_snapshot(registry_url)
        return

    # Default behavior: --info
    _print_snapshot_info()


# ════════════════════════════════════════════════════════════════════
# trustfall version
# ════════════════════════════════════════════════════════════════════


@main.command()
def version() -> None:
    """Print version, snapshot version, and issuer kid."""
    jwks = load_bundled_jwks()
    kid = jwks["keys"][0]["kid"]

    click.echo(f"trustfall-lite {__version__}")

    sp = snapshot_path()
    if sp.is_file():
        try:
            snap = load_snapshot()
            click.echo(f"snapshot: {snap.snapshot_at} ({snap.record_count} records)")
            click.echo(f"path: {snap.path}")
        except SnapshotError as exc:
            click.echo(f"snapshot: <invalid: {exc}>")
    else:
        click.echo("snapshot: (none — run 'trustfall registry --refresh')")

    click.echo(f"issuer_kid: {kid}")


# ════════════════════════════════════════════════════════════════════
# trustfall diff
# ════════════════════════════════════════════════════════════════════
#
# Compare two scan-output JSON files and report the changes between
# them. Per DIFF_SPEC §6 + §exit-codes, this command:
#
#   - Loads both files (errors out 64 on I/O failure or malformed JSON)
#   - Validates each is a Trustfall Lite scan JSON (errors out 65 if not)
#   - Validates major-version compatibility (errors out 66 on mismatch)
#   - Computes the diff via the pure core diff_scans()
#   - Renders to text (default) or JSON (--json)
#   - Exits with the right code per the precedence rule:
#       errors (64-66) > regression (2) > generic change (1) > clean (0)
#
# Implicit-current-scan form (`trustfall diff baseline.json` with no
# CURRENT) is reserved for Block 7. Block 6 implements the explicit
# two-file form only, and errors out 64 if CURRENT is missing.


# Schema fields a scan output MUST have to be considered a valid
# Trustfall Lite scan JSON. Missing any of these triggers exit 65.
_REQUIRED_SCAN_FIELDS: tuple[str, ...] = ("groups", "summary")


# Major version of this CLI's diff schema. A baseline or current
# scan from a different major version triggers exit 66.
# Per DIFF_SPEC §exit-codes: only major-version mismatch is an
# error; minor and patch differences are tolerated as forward/
# backward compatible.
_DIFF_TOOL_MAJOR_VERSION: str = __version__.split(".")[0]


def _parse_major(version_str: str | None) -> str | None:
    """Extract the major-version string from a SemVer-ish version.

    Returns None if version_str is None or unparseable. The diff tool
    treats unparseable versions as an absent version (no compatibility
    check possible) rather than as a mismatch.
    """
    if not version_str:
        return None
    parts = version_str.split(".")
    if not parts or not parts[0]:
        return None
    return parts[0]


def _load_scan_or_die(path: Path, label: str) -> dict[str, Any]:
    """Load a scan JSON file with full DIFF_SPEC error handling.

    Per DIFF_SPEC §exit-codes:
      - File not readable / not found / malformed JSON → exit 64
      - Parseable JSON but missing required scan fields → exit 65
      - Parseable scan JSON but incompatible major version → exit 66

    `label` is "baseline" or "current"; used in error messages so
    the user knows which side failed.
    """
    # exit 64: I/O / parse errors
    if not path.exists():
        _eprint(f"trustfall diff: {label} file not found: {path}")
        raise click.exceptions.Exit(64)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        _eprint(f"trustfall diff: cannot read {label} file: {exc}")
        raise click.exceptions.Exit(64)

    try:
        scan = json.loads(text)
    except json.JSONDecodeError as exc:
        _eprint(
            f"trustfall diff: {label} file is not valid JSON "
            f"({path}: line {exc.lineno}, col {exc.colno})"
        )
        raise click.exceptions.Exit(64)

    # exit 65: parseable JSON, but not a Trustfall Lite scan JSON
    if not isinstance(scan, dict):
        _eprint(
            f"trustfall diff: {label} file is JSON but not an object "
            f"(expected a Trustfall Lite scan JSON, got {type(scan).__name__})"
        )
        raise click.exceptions.Exit(65)
    missing = [f for f in _REQUIRED_SCAN_FIELDS if f not in scan]
    if missing:
        _eprint(
            f"trustfall diff: {label} file is not a Trustfall Lite scan JSON "
            f"(missing required field(s): {', '.join(missing)})"
        )
        raise click.exceptions.Exit(65)

    # exit 66: major-version incompatibility
    scan_version = scan.get("trustfall_lite_version")
    scan_major = _parse_major(scan_version)
    if scan_major is not None and scan_major != _DIFF_TOOL_MAJOR_VERSION:
        _eprint(
            f"trustfall diff: {label} file has incompatible major version "
            f"(file: {scan_version}, tool: {__version__})"
        )
        raise click.exceptions.Exit(66)

    return scan


def _baseline_uses_default_scope(baseline_scan: dict[str, Any]) -> bool:
    """Return True iff the baseline was taken with default-scope scan.

    Per DIFF_SPEC §3.5, implicit-current-scan is safe ONLY when the
    baseline was a default-scope scan (no explicit paths). The
    safety check inspects the baseline's `scan_paths` field:

      - `scan_paths` absent: legacy v0.2.x scan, cannot prove safety
        → return False (refuse implicit-current)
      - `scan_paths == []`: explicit "default scope" marker
        → return True (safe to run implicit-current)
      - `scan_paths == [...non-empty...]`: baseline used explicit
        paths, implicit-current would scan a different scope
        → return False (refuse)

    The third case includes both:
      - `scan_paths == ["/abs/path/..."]`: literal paths
        (--include-paths was set on the baseline scan)
      - `scan_paths == ["<3 path(s) — pass --include-paths to surface>"]`:
        privacy-redacted placeholder (paths were given but hidden)

    Either way, the user gave explicit paths to the baseline, and
    we cannot prove the current host's defaults match.
    """
    if "scan_paths" not in baseline_scan:
        return False
    scan_paths = baseline_scan["scan_paths"]
    # Empty list is the canonical default-scope marker
    return scan_paths == []


def _refuse_implicit_current(reason: str) -> None:
    """Print the actionable refusal message and exit 64.

    Per DIFF_SPEC §3.5, the refusal must tell the user how to
    proceed. The format is:

        Reason line.
        Provide an explicit current scan:
          trustfall scan <same-paths> --json > current.json
          trustfall diff baseline.json current.json
    """
    _eprint(f"trustfall diff: {reason}")
    _eprint("Provide an explicit current scan:")
    _eprint("  trustfall scan <same-paths> --json > current.json")
    _eprint("  trustfall diff baseline.json current.json")
    raise click.exceptions.Exit(64)


def _run_implicit_current_scan_or_die() -> dict[str, Any]:
    """Run a fresh default-scope scan and return the JSON-shape dict.

    Per Block 7 policy + DIFF_SPEC §3.5:

      - Default cache locations only (no explicit paths)
      - include_paths=False (privacy default)
      - trust_ollama_filenames=False (verify by default)
      - Network behavior matches `trustfall scan --json`: API first,
        fall back to local snapshot if API unreachable

    Returns the same dict shape `trustfall scan --json` would emit,
    suitable for passing to `diff_scans()` directly. Exits with the
    appropriate code on failure.

    Test seam: this function is the single in-process entry point
    for implicit-current orchestration. Tests can monkeypatch it to
    return a deterministic scan dict, avoiding any dependency on
    the developer machine's actual HF/Ollama caches.
    """
    # Step 1: Discover groups in the default scope (no paths given).
    # Per _discover_groups, empty paths runs HFCacheAdapter +
    # OllamaAdapter and yields the union; missing installs
    # contribute nothing.
    groups = list(_discover_groups(()))

    # Step 2: Hash all artifacts. trust_ollama_filenames=False per
    # the implicit-current default policy.
    hashed_groups = hash_groups(
        groups,
        progress=None,
        trust_ollama_filenames=False,
    )

    # Step 3: Build the registry lookup. Same fallback semantics as
    # `trustfall scan --json`: API first, local snapshot on failure.
    lookup = _build_api_lookup(
        hashed_groups,
        include_paths=False,
        api_base=DEFAULT_BASE_URL,
        quiet=True,  # implicit-current is silent during diff orchestration
    )
    if lookup is None:
        # API unreachable; fall back to local snapshot. If the local
        # snapshot is also missing, _build_local_lookup_or_die exits
        # with a clear error.
        lookup = _build_local_lookup_or_die()

    # Step 4: Verify and build the report dict
    results = verify_groups(hashed_groups, lookup)
    return _build_scan_report_dict(
        results,
        scan_paths=(),  # default scope → empty scan_paths in output
        include_paths=False,
        trust_ollama_filenames=False,
    )


@main.command(name="diff")
@click.argument(
    "baseline",
    type=click.Path(path_type=Path),
    # NB: we do NOT set exists=True here because Click would emit
    # exit code 2 (Click's UsageError default) on missing file. Per
    # DIFF_SPEC, missing baseline is exit 64. _load_scan_or_die
    # handles existence checking with the correct exit code.
)
@click.argument(
    "current",
    type=click.Path(path_type=Path),
    required=False,  # Reserved for Block 7 (implicit-current scan)
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    help="Emit JSON output instead of human-readable text.",
)
@click.option(
    "--quiet",
    is_flag=True,
    help=(
        "In text mode, suppress empty change-class sections. "
        "Has no effect on --json output."
    ),
)
@click.option(
    "--exit-code",
    "exit_code_flag",
    is_flag=True,
    help="Exit nonzero (1) if any change is detected.",
)
@click.option(
    "--exit-code-on-status-regression",
    "exit_code_on_regression",
    is_flag=True,
    help=(
        "Exit nonzero (2) if any group's status regressed "
        "(verified → any non-verified status)."
    ),
)
def diff(
    baseline: Path,
    current: Path | None,
    output_json: bool,
    quiet: bool,
    exit_code_flag: bool,
    exit_code_on_regression: bool,
) -> None:
    """Compare two scan-output JSON files and report changes.

    Two invocation forms are supported:

      Explicit two-file (recommended for CI and reproducibility):
        trustfall diff BASELINE CURRENT

      Implicit current (default-scope baselines only):
        trustfall diff BASELINE

    BASELINE is the earlier scan. CURRENT is the later scan, or
    omitted to run a fresh default-scope scan in-process. Both
    must be Trustfall Lite scan JSON files (the output of
    `trustfall scan --json`).

    The implicit-current form is allowed only when the baseline
    was taken with default-scope scan (no explicit paths). If the
    baseline used explicit `scan_paths`, the diff exits 64 with
    instructions to provide an explicit current scan.

    By default, the diff is printed and the command exits 0
    regardless of what was found. Pass --exit-code to exit nonzero
    on any change, or --exit-code-on-status-regression to exit
    nonzero only when a verified group regressed.

    Exit-code precedence (errors win over flags):
      0   No changes, or changes detected but no exit-code flags set.
      1   --exit-code set and one or more changes detected.
      2   --exit-code-on-status-regression set and a regression exists.
      64  File I/O error, malformed JSON, or implicit-current refused.
      65  Parseable JSON but not a Trustfall Lite scan.
      66  Trustfall Lite scan from an incompatible major version.

    When both --exit-code-on-status-regression and --exit-code are
    set and a regression exists, exit code 2 wins (more specific).
    """
    # Load baseline first — same 64/65/66 validation regardless of
    # whether current is explicit or implicit. We need a parsed
    # baseline before we can check the implicit-current safety rule.
    baseline_scan = _load_scan_or_die(baseline, "baseline")

    if current is None:
        # Implicit-current path. Per DIFF_SPEC §3.5, this is allowed
        # ONLY for default-scope baselines. Refuse with an actionable
        # error otherwise.
        if not _baseline_uses_default_scope(baseline_scan):
            if "scan_paths" not in baseline_scan:
                _refuse_implicit_current(
                    "baseline scan predates the scan_paths field. "
                    "Cannot prove the current host's defaults match "
                    "the original scan scope."
                )
            else:
                _refuse_implicit_current(
                    "baseline scan used explicit paths. "
                    "Implicit current scan would compare against the current "
                    "host's defaults, which may not match the baseline scope."
                )
        # Safe to run an implicit-current default-scope scan
        current_scan = _run_implicit_current_scan_or_die()
    else:
        # Explicit-current path. Load and validate as in Block 6.
        current_scan = _load_scan_or_die(current, "current")

    # Pure-core computation. No I/O, no rendering.
    result = diff_scans(baseline_scan, current_scan)

    # Render. JSON wraps the dict; text uses the human renderer.
    # Quiet only affects text; JSON always emits the full schema.
    if output_json:
        rendered = render_diff_as_dict(result)
        click.echo(json.dumps(rendered, indent=2))
    else:
        click.echo(render_diff_as_text(result, quiet=quiet), nl=False)

    # Exit-code precedence per DIFF_SPEC §exit-codes:
    #   regression (2) > generic-change (1) > clean (0)
    # Errors (64-66) already returned via raise above.
    has_regression = result.summary.status_regressions > 0
    has_any_change = not result.summary.is_empty

    if exit_code_on_regression and has_regression:
        sys.exit(2)
    if exit_code_flag and has_any_change:
        sys.exit(1)
    sys.exit(0)


# ════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════


def _utc_now_iso8601() -> str:
    """
    `scanned_at` run-scalar source. Generated HERE in the I/O layer —
    never inside export.py — so the pure sink stays clock-free and
    deterministic (T-DET-1 / T-PROV-3). Second-resolution UTC Zulu.
    """
    import datetime as _dt

    return (
        _dt.datetime.now(_dt.timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def _resolve_manifest_digest_for_export() -> str:
    """
    `registry_manifest_digest` run-scalar source (spec §3.4c, v2.1.1).

    Primary symbol: `registry.LoadedSnapshot.manifest_digest`. Returned
    VERBATIM — no prefix added, none stripped, never recomputed
    (Trustfall API Authority Doctrine). export.py never imports
    registry.py; the CLI resolves the value and injects it.

    No local snapshot → empty string. The export still succeeds with an
    empty digest column. Fabricating or recomputing a digest the issuer
    did not sign is the exact failure class the Authority Doctrine
    forbids; an honest empty value is correct.
    """
    sp = snapshot_path()
    if not sp.is_file():
        return ""
    try:
        snap = load_snapshot()
    except SnapshotError:
        return ""
    return snap.manifest_digest


def _collapse_home(path: str | None) -> str | None:
    """Render-boundary home-collapse (roots.py keeps full paths)."""
    if path is None:
        return None
    home = str(Path.home())
    if path == home or path.startswith(home + os.sep):
        return "~" + path[len(home):]
    return path


def _classify_explicit_scan_path(p: Path) -> str:
    """
    THE single explicit-path classifier (GPT Step-3 re-review blocker).

    Returns "ollama" | "hf_cache" | "path". This is the ONE rule both
    the roots-transparency view (_resolve_scan_roots_for_invocation)
    and the adapter dispatch (_discover_groups) consume — so the
    displayed roots can never disagree with the adapter that actually
    ran. Duplicating this logic is the exact Step-1 failure class
    (display says one thing, discovery does another); a prior revision
    had two copies that *also* differed in crash-safety (the helper
    guarded the iterdir() probe, discovery did not — an unreadable
    explicit dir crashed the whole scan before roots transparency
    could matter). One classifier closes both holes.

    Detection order (must match historical _discover_groups order):
      1. non-existing or non-dir            → path
      2. dir + manifests/registry.ollama.ai → ollama
      3. dir + any models--* child          → hf_cache
      4. OSError/PermissionError on iterdir  → path  (crash-safe:
         a dir we cannot introspect degrades to the generic path
         walk, exactly the PathAdapter fallback this returns)
      5. otherwise                           → path
    """
    ep = p.expanduser()
    if not ep.exists() or not ep.is_dir():
        return "path"
    if (ep / "manifests" / "registry.ollama.ai").is_dir():
        return "ollama"
    try:
        has_hf = any(
            child.name.startswith("models--")
            for child in ep.iterdir()
            if child.is_dir()
        )
    except OSError:
        return "path"
    return "hf_cache" if has_hf else "path"


def _resolve_scan_roots_for_invocation(
    paths: tuple[Path, ...],
) -> list[ScanRoot]:
    """
    Invocation-aware scan-root resolution (GPT Step-3 blocking patch 1).

    `resolve_scan_roots()` enumerates the *default/env* roots only and
    deliberately has no `path` ecosystem (Step-1 doctrine: a `path`
    root is a CLI argument, not abstractly resolvable). That is correct
    for the no-paths default scan. But when the user supplies explicit
    paths, the roots block / JSON `scan_roots` must report *what was
    actually scanned*, not the unrelated default roots — otherwise the
    F1 promise ("show me what the scanner looked at") is broken.

    No paths  → delegate to resolve_scan_roots() unchanged (default
                roots; Step-1 doctrine intact, zero behavior change).
    Paths     → classify each explicit path with the SHARED classifier
                `_classify_explicit_scan_path`, the SAME function
                `_discover_groups` consumes for adapter dispatch. One
                classifier means the reported roots can never disagree
                with the adapter that actually ran (the Step-1
                display-≠-dispatch invariant). Crash-safety on an
                unreadable dir lives in that shared classifier, so the
                roots view and discovery degrade identically by
                construction — not by a duplicated, separately-hardened
                copy (the GPT Step-3 re-review blocker).
    """
    if not paths:
        return resolve_scan_roots()

    out: list[ScanRoot] = []
    for p in paths:
        ep = p.expanduser()
        exists = ep.exists()
        try:
            resolved = str(ep.resolve())
        except (OSError, RuntimeError):
            resolved = str(ep)

        ecosystem = _classify_explicit_scan_path(ep)

        out.append(
            ScanRoot(
                ecosystem=ecosystem,
                resolved_path=resolved,
                exists=exists,
                scanned=exists,
                env_override=None,
                note=(
                    "explicit path"
                    if exists
                    else "explicit path does not exist"
                ),
            )
        )
    return out


def _eprint_scan_roots(scan_roots: list[ScanRoot]) -> None:
    """
    F1 scan-roots block → stderr (spec §2.6).

    stderr, never stdout: it must not contaminate --json output or a
    piped export. Suppressed by --quiet at the call site, exactly like
    the discovery banner. Home-collapse is applied HERE at the
    rendering boundary (roots.py deliberately keeps full paths).
    """
    _eprint("Scan roots:")
    for sr in scan_roots:
        disp = _collapse_home(sr.resolved_path)
        if sr.resolved_path is None:
            state = "not found"
        elif sr.scanned:
            state = "scanned"
        elif sr.exists:
            state = "detected (not scanned)"
        else:
            state = "configured but missing"
        line = f"  {sr.ecosystem}: {disp if disp is not None else '(none)'} [{state}]"
        if sr.env_override:
            line += f" (via {sr.env_override})"
        _eprint(line)
        if sr.note:
            _eprint(f"    note: {sr.note}")


def _scan_roots_as_json(scan_roots: list[ScanRoot]) -> list[dict[str, Any]]:
    """
    Additive `scan_roots` key for `trustfall scan --json` (spec §2.7).

    Home-collapse applied at this rendering boundary, consistent with
    the stderr block and with the existing `scan_paths` privacy stance.
    Carries the full ScanRoot truth surface so JSON consumers can
    distinguish absent / configured-but-broken / detected-not-scanned.
    """
    return [
        {
            "ecosystem": sr.ecosystem,
            "resolved_path": _collapse_home(sr.resolved_path),
            "exists": sr.exists,
            "scanned": sr.scanned,
            "env_override": sr.env_override,
            "note": sr.note,
        }
        for sr in scan_roots
    ]


def _eprint(msg: str) -> None:
    click.echo(msg, err=True)


def _format_bytes(n: int) -> str:
    units = [("PB", 10**15), ("TB", 10**12), ("GB", 10**9), ("MB", 10**6), ("KB", 10**3)]
    for unit, divisor in units:
        if n >= divisor:
            return f"{n / divisor:.2f} {unit}"
    return f"{n} B"


def _discover_groups(paths: tuple[Path, ...]) -> list[ModelGroup]:
    """
    Run the appropriate adapters for the requested paths.

    No paths    → HFCacheAdapter + OllamaAdapter (whichever has installs).
                  This is the v0.2 "scan my whole machine" default. If
                  HF cache or Ollama is missing, that adapter silently
                  yields no groups; only adapters that find something
                  contribute to the output.
    Paths given → For each path, dispatch to the right adapter:
                    - if path looks like an Ollama models/ root
                      (has manifests/registry.ollama.ai/ subtree) → OllamaAdapter
                    - if path is an HF cache root (has models--*/ children)
                      → HFCacheAdapter
                    - otherwise → PathAdapter (generic file walk)

    The auto-detection at the path level lets users say
    `trustfall scan ~/.ollama/models/` explicitly; the env var
    OLLAMA_MODELS still wins for the no-paths default case.
    """
    if not paths:
        # v0.2 default: scan both ecosystems automatically. Each adapter
        # yields nothing if its install is absent, so the union is safe
        # to take unconditionally.
        groups: list[ModelGroup] = []
        groups.extend(HFCacheAdapter().discover())
        groups.extend(OllamaAdapter().discover())
        return groups

    groups = []
    for p in paths:
        p = p.expanduser()
        if not p.exists():
            _eprint(f"warning: path does not exist: {p}")
            continue

        # Single explicit-path classifier — the SAME function the
        # roots-transparency view consumes. One rule, so display can
        # never disagree with dispatch, and the unreadable-dir crash
        # (previously unguarded HERE) is handled inside the classifier
        # (degrades to the PathAdapter generic walk). GPT Step-3
        # re-review blocker.
        kind = _classify_explicit_scan_path(p)
        if kind == "ollama":
            groups.extend(OllamaAdapter(models_root=p).discover())
        elif kind == "hf_cache":
            groups.extend(HFCacheAdapter(roots=[p]).discover())
        else:
            groups.extend(PathAdapter([p]).discover())
    return groups


def _build_api_lookup(
    hashed_groups: list[ModelGroup],
    include_paths: bool,
    api_base: str,
    quiet: bool,
) -> HashLookup | None:
    """
    Build an APIHashLookup, returning None if the API is unreachable.

    For first-run users with no local snapshot, also auto-fetches the
    snapshot per spec §A1 item 3. The fetched snapshot is used only
    as a fallback if the API turns out to be unreachable.
    """
    jwks = load_bundled_jwks()
    api = TrustfallAPI(jwks=jwks, base_url=api_base)

    # Build the path/size hint dicts only if --include-paths
    path_hints: dict[str, str] = {}
    size_bytes: dict[str, int] = {}
    home = str(Path.home())
    for g in hashed_groups:
        for art in g.artifacts:
            if not art.sha256:
                continue
            size_bytes[art.sha256] = art.size_bytes
            if include_paths:
                # Strip home directory prefix per spec §6.2
                hint = art.path
                if hint.startswith(home):
                    hint = "~" + hint[len(home):]
                path_hints[art.sha256] = hint

    return APIHashLookup(api=api, path_hints=path_hints, size_bytes=size_bytes)


def _build_local_lookup_or_die() -> HashLookup:
    """
    Load the local snapshot, exit with a clear message if not present.

    Spec §A1 item 3 says first-run auto-fetches; for v0.1 the simpler
    contract for --local-only is "no snapshot → tell the user how to
    fix it". The auto-fetch path lives in the API codepath.
    """
    try:
        snap = load_snapshot()
    except SnapshotError as exc:
        _eprint(
            f"No local registry snapshot found ({exc}).\n"
            f"Run: trustfall registry --refresh"
        )
        sys.exit(2)

    if snap.is_stale:
        _eprint(
            f"warning: local snapshot is older than 30 days "
            f"(snapshot: {snap.snapshot_at}). Consider 'trustfall registry --refresh'."
        )

    return LocalHashLookup(snap)


def _refresh_snapshot(registry_url: str) -> None:
    """Fetch and save a fresh snapshot."""
    jwks = load_bundled_jwks()

    click.echo(f"Fetching signed registry snapshot from {registry_url}...")
    try:
        with httpx.Client(timeout=60.0, follow_redirects=True) as client:
            r = client.get(registry_url, headers={"User-Agent": f"trustfall-lite/{__version__}"})
            r.raise_for_status()
            content = r.content
    except httpx.HTTPError as exc:
        _eprint(f"error fetching snapshot: {exc}")
        sys.exit(2)

    # Save to canonical location
    base_dir = ensure_snapshot_dir()
    target = base_dir / "registry.json"
    tmp = target.with_suffix(".json.tmp")
    tmp.write_bytes(content)
    tmp.replace(target)

    # Now load + verify (will raise SnapshotError if signature fails)
    try:
        snap = load_snapshot(target, jwks=jwks)
    except SnapshotError as exc:
        _eprint(f"error: snapshot signature verification failed: {exc}")
        target.unlink(missing_ok=True)
        sys.exit(2)

    click.echo(f"Signature verified: kid {snap.kid}")
    click.echo(f"Snapshot: {snap.record_count} records ({snap.snapshot_at})")
    click.echo(f"Saved: {target}")


def _print_snapshot_info() -> None:
    sp = snapshot_path()
    if not sp.is_file():
        click.echo("No local snapshot.")
        click.echo("Run: trustfall registry --refresh")
        return

    try:
        snap = load_snapshot()
    except SnapshotError as exc:
        _eprint(f"error: {exc}")
        sys.exit(2)

    click.echo(f"path: {snap.path}")
    click.echo(f"snapshot_at: {snap.snapshot_at}")
    click.echo(f"manifest_digest: {snap.manifest_digest}")
    click.echo(f"records: {snap.record_count}")
    click.echo(f"issuer_kid: {snap.kid}")
    click.echo(f"signature: verified")
    if snap.is_stale:
        click.echo(f"⚠ stale: snapshot is older than 30 days")


def _print_fingerprint() -> None:
    """Print the trust boundary in machine-pinnable form per spec §4."""
    jwks = load_bundled_jwks()
    key = jwks["keys"][0]
    fingerprint = _rfc7638_thumbprint(key)

    click.echo(f"issuer: https://attest.fallrisk.ai")
    click.echo(f"kid: {key['kid']}")

    sp = snapshot_path()
    if sp.is_file():
        try:
            snap = load_snapshot()
            click.echo(f"registry snapshot: {snap.snapshot_at}")
            click.echo(f"signature: verified")
        except SnapshotError:
            click.echo("registry snapshot: (none)")
    else:
        click.echo("registry snapshot: (none)")

    click.echo(f"public key fingerprint: sha256:{fingerprint}")


def _rfc7638_thumbprint(key: dict[str, Any]) -> str:
    """Compute RFC 7638 JWK thumbprint for an RSA key."""
    canonical = json.dumps(
        {"e": key["e"], "kty": "RSA", "n": key["n"]},
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# ════════════════════════════════════════════════════════════════════
# Output rendering
# ════════════════════════════════════════════════════════════════════


def _render_text_scan(results: list[GroupScanResult], quiet: bool) -> None:
    """
    Render the human-readable scan output, grouped by source.

    v0.2 changes (per launch decision April 27, 2026):
      - Output is split by source: HF cache section, then Ollama section,
        then a global summary at the bottom that aggregates across sources.
      - Sharded sub-tags are not collapsed for HF cache cases where the
        same claimed_model_id appears more than once (e.g. safetensors +
        pytorch_model.bin pairs); each group rendered separately with a
        "(snapshot N of M)" suffix for clarity.
      - Global summary shows total bytes and unique bytes (deduplicated
        by digest), so Ollama installs where multiple tags share weight
        blobs don't double-count storage.
    """
    file_results = [r.file_result for r in results]

    # --- Split by source ---
    by_source: dict[str, list[GroupScanResult]] = {}
    for r in results:
        by_source.setdefault(r.group.source, []).append(r)

    # --- Detect HF cache duplicate model_ids for snapshot suffixing ---
    # When the same claimed_model_id appears >1 in HF cache, suffix each
    # rendered row with "(snapshot N of M)" so the user can see they're
    # different on-disk artifacts (e.g., safetensors + pytorch_model.bin).
    hf_dups: dict[str, int] = {}
    if "hf_cache" in by_source:
        for r in by_source["hf_cache"]:
            mid = r.group.claimed_model_id
            if mid:
                hf_dups[mid] = hf_dups.get(mid, 0) + 1

    # --- Render each source section in declared order ---
    section_order = ("hf_cache", "ollama", "path")
    section_labels = {
        "hf_cache": "Hugging Face cache",
        "ollama": "Ollama store",
        "path": "Files",
    }

    first_section = True
    for source_kind in section_order:
        if source_kind not in by_source:
            continue
        source_results = by_source[source_kind]
        if not first_section:
            click.echo("")  # blank line between sections
        first_section = False

        # Section header (single underline rule)
        label = section_labels[source_kind]
        click.echo(label)
        click.echo("─" * len(label))

        # Section discovery banner
        n_groups = len(source_results)
        n_artifacts = sum(r.file_result.n_artifacts for r in source_results)
        sec_bytes = sum(r.file_result.size_bytes for r in source_results)
        click.echo(
            f"Discovered {n_groups} model group(s) "
            f"({n_artifacts} artifacts, {_format_bytes(sec_bytes)})"
        )

        # Per-group rows. For HF cache, track per-model_id snapshot index
        # so we can suffix duplicates.
        hf_seen: dict[str, int] = {}
        for r in source_results:
            file_result = r.file_result
            # Compute snapshot suffix if needed
            suffix = ""
            if source_kind == "hf_cache":
                mid = r.group.claimed_model_id
                if mid and hf_dups.get(mid, 0) > 1:
                    hf_seen[mid] = hf_seen.get(mid, 0) + 1
                    suffix = f"  (snapshot {hf_seen[mid]} of {hf_dups[mid]})"

            line = render_file_line(file_result, colored=False)
            if suffix:
                # Append suffix to the first line only, preserving multi-line detail
                first_line, _, rest = line.partition("\n")
                line = first_line + suffix + ("\n" + rest if rest else "")
            click.echo(line)

    # --- Global summary ---
    click.echo("")
    click.echo("Global summary")
    click.echo("──────────────")

    total_groups = len(results)
    total_arts = sum(r.file_result.n_artifacts for r in results)
    tot_bytes = sum(r.file_result.size_bytes for r in results)

    # unique_bytes uses the underlying ModelGroup artifacts (not FileResult,
    # which only carries one representative size per group)
    all_groups = [r.group for r in results]
    uniq_bytes = unique_bytes(all_groups)
    uniq_arts = unique_artifacts(all_groups)

    if total_arts == uniq_arts:
        # No shared blobs — simple summary
        click.echo(
            f"Scanned {total_groups} model groups "
            f"({total_arts} artifacts, {_format_bytes(tot_bytes)})."
        )
    else:
        # Shared blobs detected (typically across Ollama tags) — surface dedup
        click.echo(
            f"Scanned {total_groups} model groups referencing "
            f"{total_arts} artifacts ({uniq_arts} unique, "
            f"{_format_bytes(uniq_bytes)} unique blobs)."
        )

    counts: dict[Status, int] = {s: 0 for s in Status}
    for fr in file_results:
        counts[fr.status] += 1
    for s in Status:
        n = counts[s]
        if n == 0:
            continue
        icon = status_icon(s, colored=False)
        label = status_label(s)
        click.echo(f"  {icon} {n} {label}")


def _build_scan_report_dict(
    results: list[GroupScanResult],
    *,
    scan_paths: tuple[Path, ...],
    include_paths: bool,
    trust_ollama_filenames: bool = False,
    scan_roots: list[ScanRoot] | None = None,
) -> dict[str, Any]:
    """Build the v0.2 JSON scan-output dict.

    Pure function: takes verified scan results and orchestration
    flags, returns the dict that `trustfall scan --json` would emit.
    No I/O, no printing, no side effects.

    Extracted from `_render_json_scan` so the `diff` command can
    invoke a fresh implicit-current scan and consume its dict
    directly (per DIFF_SPEC §3.5 implicit-current-scan flow). The
    `_render_json_scan` wrapper now delegates here and prints the
    result.
    """
    file_results = [r.file_result for r in results]
    total_artifacts_count = sum(r.file_result.n_artifacts for r in results)

    # Use the formatter's group-language summary (we'll override
    # summary keys below to match v0.2 schema)
    base_summary = render_results_as_dict(
        file_results, total_artifacts=total_artifacts_count
    )["scan_summary"]

    all_groups = [r.group for r in results]
    summary: dict[str, Any] = {
        "groups_scanned": base_summary["groups_scanned"],
        "artifacts_scanned": total_artifacts_count,
        "unique_artifacts_scanned": unique_artifacts(all_groups),
        "total_bytes": sum(r.file_result.size_bytes for r in results),
        "unique_bytes": unique_bytes(all_groups),
        "counts": base_summary["counts"],
    }

    # Per-source breakdown
    sources_dict: dict[str, dict[str, int]] = {}
    by_source: dict[str, list[GroupScanResult]] = {}
    for r in results:
        by_source.setdefault(r.group.source, []).append(r)
    source_label_map = {
        "hf_cache": "huggingface_cache",
        "ollama": "ollama",
        "path": "path",
    }
    for source_kind, source_results in by_source.items():
        key = source_label_map.get(source_kind, source_kind)
        sources_dict[key] = {
            "groups_scanned": len(source_results),
            "artifacts_scanned": sum(r.file_result.n_artifacts for r in source_results),
            "total_bytes": sum(r.file_result.size_bytes for r in source_results),
        }
    summary["sources"] = sources_dict

    # Per-group detail
    detailed_groups: list[dict[str, Any]] = []
    for r in results:
        # Per-group claim_source (uniform within group in v0.1/v0.2)
        claim_source = None
        if r.group.artifacts and r.group.artifacts[0].claim is not None:
            claim_source = r.group.artifacts[0].claim.claim_source

        group_obj: dict[str, Any] = {
            "group_id": r.group.group_id,
            "group_kind": r.group.group_kind,
            "source": r.group.source,
            "claimed_model_id": r.group.claimed_model_id,
            "claim_source": claim_source,
            "status": r.file_result.status.value,
            "n_artifacts": len(r.group.artifacts),
            "total_bytes": sum(a.size_bytes for a in r.group.artifacts),
            "artifacts": [],
        }

        # Ollama groups: parse name/tag from the group_id ({namespace}/{name}:{tag})
        # so JSON consumers don't need to re-parse claimed_model_id.
        if r.group.source == "ollama":
            # group_id format: {namespace}/{name}:{tag}
            try:
                ns_name, _, tag = r.group.group_id.rpartition(":")
                _, _, name = ns_name.rpartition("/")
                group_obj["ollama_namespace"] = ns_name.split("/")[0] if "/" in ns_name else ns_name
                group_obj["ollama_name"] = name
                group_obj["ollama_tag"] = tag
            except Exception:
                pass  # leave the fields off rather than crash

        if r.matched_record is not None:
            group_obj["model_id"] = r.matched_record.claims.get("model_id")
            group_obj["enrollment_id"] = r.matched_record.claims.get("enrollment_id")
            group_obj["publisher"] = r.matched_record.claims.get("publisher")
            group_obj["license"] = r.matched_record.claims.get("license")

        for art in r.group.artifacts:
            art_obj: dict[str, Any] = {
                "filename": art.filename,
                "sha256": art.sha256,
                "size_bytes": art.size_bytes,
                "format_hint": art.format_hint,
            }
            # v0.2: surface verification provenance on Ollama blobs
            if art.format_hint == "ollama_blob":
                if was_filename_trusted(art, trust_ollama_filenames):
                    art_obj["digest_verified"] = False
                    art_obj["digest_source"] = "ollama_blob_filename"
                else:
                    art_obj["digest_verified"] = True
                    art_obj["digest_source"] = "content_hash"
                # mediaType is currently always the model layer for Ollama
                # groups (we only emit the weight layer per OllamaAdapter)
                art_obj["media_type"] = "application/vnd.ollama.image.model"
            if include_paths:
                art_obj["path"] = art.path
            group_obj["artifacts"].append(art_obj)
        detailed_groups.append(group_obj)

    return {
        "trustfall_lite_version": __version__,
        # Privacy: the literal scan paths are echoed only when the user
        # explicitly opts into path exposure with --include-paths.
        # Otherwise we just say how many paths were given, so JSON
        # consumers can reason about scope without leaking home dirs
        # into bug reports.
        "scan_paths": (
            [str(p) for p in scan_paths]
            if include_paths
            else [f"<{len(scan_paths)} path(s) — pass --include-paths to surface>"]
            if scan_paths
            else []
        ),
        "include_paths": include_paths,
        "trust_ollama_filenames": trust_ollama_filenames,
        "summary": summary,
        "groups": detailed_groups,
        # Additive F1 surface (spec §2.7). Present ONLY when the caller
        # supplied scan_roots — the `diff` implicit-current path passes
        # None, so its JSON shape is byte-unaffected. Home-collapse is
        # applied at this rendering boundary (roots.py keeps full paths).
        **(
            {"scan_roots": _scan_roots_as_json(scan_roots)}
            if scan_roots is not None
            else {}
        ),
    }


def _render_json_scan(
    results: list[GroupScanResult],
    scan_paths: tuple[Path, ...],
    include_paths: bool,
    trust_ollama_filenames: bool = False,
    scan_roots: list[ScanRoot] | None = None,
) -> None:
    """Render the v0.2 JSON scan output to stdout.

    Thin wrapper around `_build_scan_report_dict`. Kept for back
    compat with the existing scan-command call site; the dict-
    building logic now lives in `_build_scan_report_dict` so the
    diff command can invoke implicit-current scans without going
    through stdout/stdin. `scan_roots` is additive (spec §2.7) —
    forwarded only when supplied.
    """
    output = _build_scan_report_dict(
        results,
        scan_paths=scan_paths,
        include_paths=include_paths,
        trust_ollama_filenames=trust_ollama_filenames,
        scan_roots=scan_roots,
    )
    click.echo(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
