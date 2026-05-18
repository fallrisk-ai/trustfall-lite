"""
Flat inventory export for Trustfall Lite (`trustfall scan --export`).

This module is a **pure sink**. It consumes an already-computed scan
result (`list[GroupScanResult]`) plus the resolved scan roots and a
small set of caller-injected run scalars, and writes one flat
inventory file (CSV or JSONL). It performs:

  - no network I/O
  - no discovery
  - no hashing
  - no registry / API access
  - no read of the package ``__version__``

The only I/O it performs is the single atomic write of the output
file. Every value it emits was already computed upstream; this module
only *re-shapes* that data into a flat per-group row.

Spec: INVENTORY_EXPORT_SPEC_v0_4 v2.1.3 §3 (schema) + §4 (architecture).

Import allowlist (pinned by T-NET-2): this module imports only
``models``, ``scanner`` (for the ``GroupScanResult`` type),
``roots`` (for ``ScanRoot``), ``formatter`` (for the ``Status``
enum — a pure value type, no I/O), and stdlib ``csv`` / ``json`` /
``os`` / ``tempfile`` / ``pathlib`` / ``typing``. It MUST NOT import
``api``, ``httpx``, ``registry``, or ``scanner.APIHashLookup``.
``registry_manifest_digest`` and ``trustfall_version`` are therefore
caller-injected run scalars — this module never reads ``registry.py``
or the package root to obtain them.
"""

from __future__ import annotations

import csv
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Literal

from .formatter import Status
from .roots import ScanRoot
from .scanner import GroupScanResult

# ════════════════════════════════════════════════════════════════════
# Column schema (spec §3.2 — exact order, exact names, fifteen columns)
# ════════════════════════════════════════════════════════════════════

# The fifteen default columns, in the exact GPT-ruled order. This list
# IS the CSV header and the JSONL key order. Any change here is a spec
# change and must move the spec + the drift test (T-SCHEMA-DOC-1)
# together.
_DEFAULT_COLUMNS: tuple[str, ...] = (
    "provider",
    "model_id",
    "model_id_source",
    "status",
    "registry_match",
    "registry_bound_digest",
    "registry_manifest_digest",
    "artifact_count",
    "license",
    "publisher",
    "deep_runtime_claim_applicable",
    "tokenizer_surface_coverage",
    "cache_root_type",
    "trustfall_version",
    "scanned_at",
)

# The two path columns, APPENDED (never inserted) only when
# include_paths is True (spec §3.5 — keeps the fifteen-column default
# a stable prefix).
_PATH_COLUMNS: tuple[str, ...] = (
    "cache_root_path",
    "artifact_paths",
)

# Provider label mapping. This MUST stay byte-identical to the live
# mapping in cli.py's JSON renderer (cli.py:1074 source_label_map) so
# the `provider` column equals what `--json` already emits for the
# same model. Reproduced here (not imported) to keep export.py's
# import surface minimal and pure — cli.py imports heavy modules.
_SOURCE_LABEL_MAP: dict[str, str] = {
    "hf_cache": "huggingface_cache",
    "ollama": "ollama",
    "path": "path",
}


class ExportError(Exception):
    """
    Raised for export-config / I/O failures (spec §7, exit code 70).

    This is distinct from scan-result conditions: an ExportError is
    always an export-config or filesystem problem (bad extension,
    unwritable directory, failed atomic replace), never a statement
    about what the scan found. The CLI maps it to exit code 70.
    """


# ════════════════════════════════════════════════════════════════════
# Centralized derivations (spec §3.3 / §3.4 / §3.4b — verbatim)
# ════════════════════════════════════════════════════════════════════
#
# These three functions are the single source of truth for the three
# derived columns. Both the CSV path and the JSONL path call the same
# `_row_for_group`, which calls these — so CSV and JSONL can never
# disagree on a derived value (the shared-producer invariant that
# prevents the silent-renderer bug class).


def _bound_digest(record_claims: dict[str, Any]) -> str:
    """
    `registry_bound_digest` (spec §3.3, verbatim).

    Lane B (`evidence_class == "artifact_identity"`) binds via a
    top-level `artifact_manifest_digest`. Lane A (structural, or a
    legacy anchor with `evidence_class` absent) binds via
    `evidence_digest`. Propagated verbatim — the export adds no
    `sha256:` prefix and strips none (Trustfall API Authority
    Doctrine: serve signed claims, never reformat them).
    """
    ec = record_claims.get("evidence_class")
    if ec == "artifact_identity":
        return record_claims.get("artifact_manifest_digest", "")
    # Lane A: itpuf_structural_identity, or absent (legacy anchor).
    return record_claims.get("evidence_digest", "")


def _deep_runtime_claim_applicable(r: GroupScanResult) -> bool:
    """
    `deep_runtime_claim_applicable` (spec §3.4).

    A boolean fact about the registry record's evidence class — NOT a
    statement about the running process. True only when the group is
    verified AND its matched record is a Lane-A structural-identity
    record: explicit `itpuf_structural_identity` (or a legacy anchor
    with `evidence_class` absent) AND carrying a structural
    `evidence_digest`. False for every non-verified group, every
    verified Lane-B (`artifact_identity`) record, every verified
    record of any other / future evidence class, and any group with
    no matched record.

    "Applicable" means: a Trustfall Deep runtime-identity claim
    *could* be made about this enrolled model if you ran Deep. It
    does NOT mean Lite checked runtime identity. Lite never does.
    """
    if r.file_result.status is not Status.VERIFIED or r.matched_record is None:
        return False
    # Conservative Lane-A predicate (GPT Step-2 blocking patch 2):
    # `!= "artifact_identity"` was too broad — it would silently label
    # a future verified evidence class (e.g. "zk_private_match") as
    # Deep-applicable. The column means Lane-A structural / legacy
    # structural specifically, not "anything that is not Lane B". This
    # is now byte-aligned with the sibling _tokenizer_surface_coverage
    # Lane-A test (explicit itpuf_structural_identity OR legacy anchor
    # with evidence_class absent, AND a structural evidence_digest).
    claims = r.matched_record.claims
    ec = claims.get("evidence_class")
    return ec in ("itpuf_structural_identity", None) and bool(
        claims.get("evidence_digest")
    )


def _tokenizer_surface_coverage(r: GroupScanResult) -> str:
    """
    `tokenizer_surface_coverage` (spec §3.4b, verbatim).

    An artifact-identity coverage signal, NOT a tokenizer security
    verdict. Total over the four-value enum:

      unknown_unverified            - no signed record matched
      covered_by_verified_container - Lane B / Ollama blob: the
                                      byte-verified container is the
                                      tokenizer surface
      opaque_structural_evidence_binding
                                    - Lane A: bound to a signed
                                      structural commitment; the Lite
                                      payload does not enumerate
                                      tokenizer files (Lite cannot
                                      assert coverage, only binding)
      not_covered                   - verified but neither identity
                                      surface Lite understands applies
                                      (defensive/future-proof; empty
                                      under the current two-lane schema)

    This function reads ONLY r.file_result.status, r.matched_record,
    and the claims keys artifact_format / evidence_class /
    evidence_digest. It reads no local file, no ArtifactCandidate.path,
    no tokenizer content (pins "coverage report, not scanner").
    """
    if r.file_result.status is not Status.VERIFIED or r.matched_record is None:
        return "unknown_unverified"
    claims = r.matched_record.claims
    if claims.get("artifact_format") == "ollama_blob":
        return "covered_by_verified_container"
    ec = claims.get("evidence_class")
    # Lane A: explicit structural class, or absent (legacy measurement
    # anchor) — both commit identity via a single opaque evidence_digest.
    if ec in ("itpuf_structural_identity", None) and claims.get("evidence_digest"):
        return "opaque_structural_evidence_binding"
    return "not_covered"


def _registry_match(status: Status) -> str:
    """
    `registry_match` (spec §3.2 col 5): a pure function of status.

    exact      <- verified
    name_only  <- unknown_variant
    none       <- not_enrolled OR pilot_available

    Total over the live four-member Status enum. (pilot_available is
    not emitted by the scanner in practice, but the enum has four
    members in formatter.py:40-46; this mapping is total so a future
    code path cannot produce an undefined cell — same totality
    discipline as _tokenizer_surface_coverage.)
    """
    if status is Status.VERIFIED:
        return "exact"
    if status is Status.UNKNOWN_VARIANT:
        return "name_only"
    # NOT_ENROLLED or PILOT_AVAILABLE
    return "none"


def _model_id_source(r: GroupScanResult) -> str:
    """
    `model_id_source` (spec §3.2 col 3): how we believe this group
    corresponds to a model_id.

    registry_record  <- matched_record is not None (verified)
    local_metadata   <- no matched_record but a claim_source is set
    none             <- no matched record and no claim_source
    """
    if r.matched_record is not None:
        return "registry_record"
    if r.file_result.claim_source:
        return "local_metadata"
    return "none"


def _model_id(r: GroupScanResult) -> str:
    """
    `model_id` (spec §3.2 col 2): the verified record's model_id when
    verified; else the group-level claimed_model_id; else empty.
    """
    if r.matched_record is not None:
        return r.matched_record.claims.get("model_id") or ""
    if r.group.claimed_model_id:
        return r.group.claimed_model_id
    return ""


# ════════════════════════════════════════════════════════════════════
# Scan-root resolution for the cache_root_path column (spec §4.3.1)
# ════════════════════════════════════════════════════════════════════


def _scan_root_for(
    source: str,
    scan_roots: list[ScanRoot],
    artifact_paths: list[str],
) -> ScanRoot | None:
    """
    Containment join (spec §4.3, GPT Step-3 blocking patch 2 —
    scoped reopen of the Step-2 identity join).

    The Step-2 join returned the FIRST ScanRoot whose `.ecosystem`
    equals the group's `source`. That is correct only when at most one
    root per ecosystem exists. Step 3 makes multiple same-ecosystem
    roots reachable (two HF caches, default HF root + an explicit HF
    path, two explicit Ollama roots …). With the first-match join, a
    group whose artifacts live under the *second* hf_cache root would
    be exported with the *first* root's path — a silent wrong-root
    bug. That is the concrete contradiction justifying the reopen; it
    is not re-litigation of a closed step.

    Selection is now by artifact-path CONTAINMENT among the
    same-ecosystem candidates: the ScanRoot whose resolved_path is a
    prefix-directory of one of the group's artifact paths wins.
    `os.path.commonpath([root, artifact]) == root` is the containment
    test (lexical, after abspath+expanduser normalization — no
    filesystem access, preserving the pure-sink + determinism
    guarantee). Fall back to the first same-ecosystem candidate only
    when containment cannot be established (e.g. resolved_path absent,
    a different drive on Windows raising ValueError, or paths not yet
    materialized) — strictly no worse than the prior Step-2 behavior.

    Returns None when no same-ecosystem candidate exists. This remains
    the NORMAL case for `path`-sourced groups (resolve_scan_roots()
    has no `path` ecosystem); the `path` branch in _row_for_group
    handles None and never reaches here.
    """
    candidates = [
        sr
        for sr in scan_roots
        if sr.ecosystem == source and sr.resolved_path
    ]
    if not candidates:
        return None

    for sr in candidates:
        root = os.path.abspath(
            os.path.expanduser(sr.resolved_path or "")
        )
        for ap in artifact_paths:
            try:
                common = os.path.commonpath(
                    [root, os.path.abspath(ap)]
                )
            except ValueError:
                # Different drives (Windows) or mixed abs/rel — cannot
                # establish containment for this pair; try the next.
                continue
            if common == root:
                return sr

    # No containment match — fall back to first same-ecosystem
    # candidate (identical to the prior Step-2 behavior; never worse).
    return candidates[0]


# ════════════════════════════════════════════════════════════════════
# The single row producer (spec §4.3 — CSV and JSONL share this)
# ════════════════════════════════════════════════════════════════════


def _row_for_group(
    r: GroupScanResult,
    scan_roots: list[ScanRoot],
    *,
    include_paths: bool,
    scanned_at: str,
    trustfall_version: str,
    registry_manifest_digest: str,
) -> dict[str, Any]:
    """
    Build one flat row dict for one ModelGroup.

    Both the CSV writer and the JSONL writer consume the row dict this
    returns. They differ only in serialization (CSV: empty-string for
    null + `;`-join for artifact_paths; JSONL: native null + array).
    Sharing this producer is what guarantees CSV and JSONL carry
    identical logical content — a divergence would be a silent-
    renderer bug (the historical claim_source JSON-drop class).

    Path-privacy gate (spec §4.6 — the load-bearing invariant):
    when include_paths is False, the two path keys
    (cache_root_path, artifact_paths) are NOT added to the dict at
    all. The path values never enter the serialization pipeline.
    This is structurally stronger than "write empty when private".

    Run scalars (registry_manifest_digest, trustfall_version,
    scanned_at) are passed in by the caller, identical for every row
    in one export — never read inside this module (pure-sink +
    determinism guarantee, T-DET-1 / T-PROV-3 / T-NET-2).
    """
    fr = r.file_result
    source = r.group.source
    claims: dict[str, Any] = (
        r.matched_record.claims if r.matched_record is not None else {}
    )

    verified = fr.status is Status.VERIFIED and r.matched_record is not None

    row: dict[str, Any] = {
        "provider": _SOURCE_LABEL_MAP.get(source, source),
        "model_id": _model_id(r),
        "model_id_source": _model_id_source(r),
        "status": fr.status.value,
        "registry_match": _registry_match(fr.status),
        "registry_bound_digest": _bound_digest(claims) if verified else "",
        "registry_manifest_digest": registry_manifest_digest,
        "artifact_count": len(r.group.artifacts),
        "license": (claims.get("license") or "") if verified else "",
        "publisher": (claims.get("publisher") or "") if verified else "",
        "deep_runtime_claim_applicable": _deep_runtime_claim_applicable(r),
        "tokenizer_surface_coverage": _tokenizer_surface_coverage(r),
        "cache_root_type": source,
        "trustfall_version": trustfall_version,
        "scanned_at": scanned_at,
    }

    # Path-privacy gate: keys added ONLY when explicitly opted in.
    if include_paths:
        artifact_paths = [a.path for a in r.group.artifacts]

        if source == "path":
            # Spec §4.3.1 (GPT 1 + GPT 2 union): path-sourced groups
            # have NO standing ScanRoot — resolve_scan_roots() never
            # enumerates `path`. Do NOT require/lookup a ScanRoot for
            # them; do NOT fail when scan_roots has no path entry.
            # cache_root_path = the common parent directory of the
            # artifact paths. GPT Step-2 blocking patch 1:
            # os.path.commonpath(["/tmp/sub/x.gguf"]) returns the file
            # path itself, not its parent dir — for a single loose
            # file that would duplicate artifact_paths into
            # cache_root_path. Single-file groups must use dirname.
            if not artifact_paths:
                cache_root_path = ""
            elif len(artifact_paths) == 1:
                cache_root_path = os.path.dirname(artifact_paths[0])
            else:
                cache_root_path = os.path.commonpath(artifact_paths)
        else:
            # hf_cache / ollama / lmstudio: containment join to the
            # ScanRoot whose resolved_path contains this group's
            # artifacts (GPT Step-3 patch 2 — handles multiple
            # same-ecosystem roots). resolved_path may be None
            # (ecosystem absent) — emit "" rather than the literal
            # "None".
            sr = _scan_root_for(source, scan_roots, artifact_paths)
            cache_root_path = (
                sr.resolved_path
                if sr is not None and sr.resolved_path is not None
                else ""
            )

        row["cache_root_path"] = cache_root_path
        row["artifact_paths"] = artifact_paths

    return row


# ════════════════════════════════════════════════════════════════════
# Deterministic ordering (spec §4.4)
# ════════════════════════════════════════════════════════════════════


def _sorted_results(
    results: list[GroupScanResult],
) -> list[GroupScanResult]:
    """
    Deterministic emission order: sorted by
    (provider, model_id, group_id). group_id is the stable adapter
    identifier (models.py:137 ModelGroup.group_id) — never a path.
    Two exports of the same unchanged machine produce byte-identical
    output modulo scanned_at (the one intentionally run-varying
    field, injected by the caller for byte-stable comparison
    testing). T-DET-1 / T-DET-2 pin this.
    """
    def key(r: GroupScanResult) -> tuple[str, str, str]:
        provider = _SOURCE_LABEL_MAP.get(r.group.source, r.group.source)
        model_id = _model_id(r)
        return (provider, model_id, r.group.group_id)

    return sorted(results, key=key)


# ════════════════════════════════════════════════════════════════════
# Serializers (CSV / JSONL — both consume _row_for_group)
# ════════════════════════════════════════════════════════════════════


def _columns(include_paths: bool) -> list[str]:
    """The active column list: fifteen default, +2 appended if opted in."""
    cols = list(_DEFAULT_COLUMNS)
    if include_paths:
        cols.extend(_PATH_COLUMNS)
    return cols


def _csv_cell(col: str, value: Any) -> str:
    """
    CSV serialization of one cell.

    - artifact_paths: list joined by ';' (',' is the CSV delimiter;
      the csv writer still quotes defensively)
    - bool: lowercase 'true' / 'false' (matches JSON/`--json`)
    - None: empty string (CSV's null representation)
    - everything else: str()
    """
    if col == "artifact_paths":
        # value is a list[str] when present.
        return ";".join(value) if value else ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)


def _write_csv(
    rows: list[dict[str, Any]], columns: list[str], fh: Any
) -> None:
    writer = csv.writer(fh, lineterminator="\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow([_csv_cell(c, row.get(c)) for c in columns])


def _jsonl_value(col: str, value: Any) -> Any:
    """
    JSONL serialization of one cell. Where CSV writes an empty
    string, JSONL writes null (key always present, value null when
    absent — the DIFF_SPEC null-not-omitted doctrine). artifact_paths
    is a native array; bool stays bool; int stays int.
    """
    if col == "artifact_paths":
        return list(value) if value else []
    if isinstance(value, bool):
        return value
    if value is None or value == "":
        return None
    return value


def _write_jsonl(
    rows: list[dict[str, Any]], columns: list[str], fh: Any
) -> None:
    for row in rows:
        obj = {c: _jsonl_value(c, row.get(c)) for c in columns}
        fh.write(json.dumps(obj, ensure_ascii=False, sort_keys=False))
        fh.write("\n")


# ════════════════════════════════════════════════════════════════════
# Public entry point (spec §4.2 signature — pure sink, atomic write)
# ════════════════════════════════════════════════════════════════════


def export_inventory(
    results: list[GroupScanResult],
    scan_roots: list[ScanRoot],
    *,
    fmt: Literal["csv", "jsonl"],
    out_path: Path,
    include_paths: bool,
    scanned_at: str,
    trustfall_version: str,
    registry_manifest_digest: str,
) -> int:
    """
    Write the flat inventory to out_path. Returns the number of rows
    written (one per ModelGroup).

    Pure sink: no network, no discovery, no hashing. The only I/O is
    the single atomic output-file write.

    Run scalars (scanned_at, trustfall_version,
    registry_manifest_digest) are caller-injected and identical for
    every row. This module never reads the clock, the package
    __version__, or registry.py to obtain them — that would break the
    pure-sink + determinism guarantees (T-DET-1 / T-PROV-3 / T-NET-2).
    registry_manifest_digest is propagated verbatim: no prefix added,
    none stripped, never recomputed (Trustfall API Authority
    Doctrine).

    Atomic write (spec §4.7): write to a temp file in the SAME
    directory as out_path (same-filesystem guarantee for os.replace),
    then os.replace(tmp, out_path). An existing out_path is
    overwritten (matches `>` / `registry --refresh` mental models; no
    --force, GPT Q8 ruling). A crash mid-write leaves either the old
    file intact or the new file complete, never a truncated file; the
    temp file is removed on any exception before re-raising.

    Raises ExportError (CLI maps to exit 70) on any filesystem
    failure. `fmt` is trusted to be "csv" | "jsonl" (the CLI validates
    the path extension at parse time per spec §3.7 before this is
    called); an unexpected value is a programming error and raises
    ValueError.
    """
    if fmt not in ("csv", "jsonl"):
        raise ValueError(f"export_inventory: unknown fmt {fmt!r}")

    columns = _columns(include_paths)
    ordered = _sorted_results(results)
    rows = [
        _row_for_group(
            r,
            scan_roots,
            include_paths=include_paths,
            scanned_at=scanned_at,
            trustfall_version=trustfall_version,
            registry_manifest_digest=registry_manifest_digest,
        )
        for r in ordered
    ]

    out_path = Path(out_path)
    parent = out_path.parent

    tmp_path: str | None = None
    try:
        # Temp file in the SAME directory → os.replace is atomic
        # (cross-directory replace is not guaranteed atomic).
        fd, tmp_path = tempfile.mkstemp(
            prefix=".trustfall-export-",
            suffix=f".{fmt}.tmp",
            dir=str(parent),
        )
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            if fmt == "csv":
                _write_csv(rows, columns, fh)
            else:
                _write_jsonl(rows, columns, fh)
        os.replace(tmp_path, out_path)
        tmp_path = None  # successfully consumed; nothing to clean up
    except OSError as exc:
        raise ExportError(
            f"failed to write export to {out_path}: {exc}"
        ) from exc
    finally:
        # Clean up the temp file on any failure path (it still exists
        # only if os.replace did not consume it).
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    return len(rows)
