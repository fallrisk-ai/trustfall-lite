"""
Trustfall Lite — diff core.

This module implements `diff_scans(baseline, current)`, the load-bearing
function behind `trustfall diff`. It is pure logic: no rendering, no
CLI, no I/O. The CLI wrapper and renderers live in `cli.py` and call
this module through `diff_scans`.

The contract is locked in DIFF_SPEC.md (FROZEN, v0.3.0). Three
invariants this module must preserve:

1. **Identity is the tuple `(source, group_id)`.** A model that
   appears under both `huggingface_cache` and `path` sources is two
   distinct logical groups, not one. Per DIFF_SPEC §3.

2. **Artifact change precedence.** When the same `filename` appears
   in baseline and current with different `sha256`, the diff emits
   exactly one `artifact_changed` entry. The same filename does NOT
   also produce `artifact_added` plus `artifact_removed`. Per
   DIFF_SPEC §3 precedence rule.

3. **Status vocabulary matches the Status enum.** Status values are
   `verified`, `unknown_variant`, `not_enrolled`, `pilot_available`.
   Status regression is exclusively `verified → any non-verified
   status`. Per DIFF_SPEC §4.

If implementation discovers a case the spec does not address, the
spec is updated first. Implementation drift from spec is treated as
a bug in either the spec or the implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional

from .formatter import (
    Status,
    _STATUS_ICONS,
    _STATUS_LABELS,
    assert_no_forbidden_phrases,
)


# ════════════════════════════════════════════════════════════════════
# Change-class constants (locked: six classes; see DIFF_SPEC §4)
# ════════════════════════════════════════════════════════════════════

ChangeType = Literal[
    "group_added",
    "group_removed",
    "artifact_added",
    "artifact_removed",
    "artifact_changed",
    "status_changed",
]

# All six change types as a tuple, for iteration / completeness checks.
CHANGE_TYPES: tuple[ChangeType, ...] = (
    "group_added",
    "group_removed",
    "artifact_added",
    "artifact_removed",
    "artifact_changed",
    "status_changed",
)


# ════════════════════════════════════════════════════════════════════
# Status direction (used by status_changed entries)
# ════════════════════════════════════════════════════════════════════

StatusDirection = Literal["regression", "improvement", "lateral"]

_VERIFIED_VALUE: str = Status.VERIFIED.value  # "verified"


def _classify_status_direction(
    baseline_status: str, current_status: str
) -> StatusDirection:
    """
    Classify a status transition per DIFF_SPEC §4.

    - regression: moved from verified to any non-verified status
    - improvement: moved to verified from any non-verified status
    - lateral: neither side is verified
    """
    if baseline_status == _VERIFIED_VALUE and current_status != _VERIFIED_VALUE:
        return "regression"
    if baseline_status != _VERIFIED_VALUE and current_status == _VERIFIED_VALUE:
        return "improvement"
    return "lateral"


# ════════════════════════════════════════════════════════════════════
# Diff dataclasses — boring core API per DIFF_SPEC.md
# ════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class DiffChange:
    """
    A single change-class entry in a diff result.

    Not every field is meaningful for every change type. The semantics:

    - group_added/removed: source, group_id, group_status, n_artifacts,
      total_bytes
    - artifact_added/removed: source, group_id, filename, sha256
    - artifact_changed: source, group_id, filename, baseline_sha256,
      current_sha256, baseline_size_bytes, current_size_bytes
    - status_changed: source, group_id, baseline_status, current_status,
      direction
    """

    type: ChangeType
    source: str
    group_id: str

    # Group-level fields (group_added, group_removed, status_changed)
    group_status: Optional[str] = None
    n_artifacts: Optional[int] = None
    total_bytes: Optional[int] = None
    claimed_model_id: Optional[str] = None

    # Artifact-level fields (artifact_added/removed/changed)
    filename: Optional[str] = None
    sha256: Optional[str] = None  # for added/removed
    baseline_sha256: Optional[str] = None  # for artifact_changed
    current_sha256: Optional[str] = None
    baseline_size_bytes: Optional[int] = None
    current_size_bytes: Optional[int] = None

    # Status-changed fields
    baseline_status: Optional[str] = None
    current_status: Optional[str] = None
    direction: Optional[StatusDirection] = None


@dataclass(frozen=True)
class DiffSummary:
    """
    Aggregate counts for a diff result. Per DIFF_SPEC §7 schema —
    one counter per change class, plus regression/improvement
    sub-counts derived from status_changed entries.
    """

    groups_added: int = 0
    groups_removed: int = 0
    artifacts_added: int = 0
    artifacts_removed: int = 0
    artifacts_changed: int = 0
    status_changed: int = 0
    status_regressions: int = 0
    status_improvements: int = 0

    @property
    def total_changes(self) -> int:
        """Sum of all six change-class counters."""
        return (
            self.groups_added
            + self.groups_removed
            + self.artifacts_added
            + self.artifacts_removed
            + self.artifacts_changed
            + self.status_changed
        )

    @property
    def is_empty(self) -> bool:
        """True if no changes of any class were detected."""
        return self.total_changes == 0


@dataclass(frozen=True)
class DiffScanMetadata:
    """
    Metadata extracted from one side of a diff (baseline or current).

    This object carries the registry snapshot and the privacy posture
    of the scan that produced it. It is audit/output metadata only:
    it does NOT affect change classification. Two scans that differ
    only in their registry snapshot digest produce zero change
    entries and two distinct DiffScanMetadata objects on the result.

    Per DIFF_SPEC §5 schema dependencies:

    - `registry_kid` is the JWS `kid` of the signed registry the scan
      was verified against. May be null for scans against an
      unverified or pinned registry.

    - `registry_manifest_digest` is the raw-hex SHA-256 of the
      registry manifest at the moment of scan. NEVER prefixed with
      "sha256:". The diff core preserves whatever the scan emitted
      verbatim — no normalization, no addition or removal of
      prefixes.

    - `include_paths` is the privacy posture of the source scan.
      Combined with the other side's `include_paths`, it determines
      whether path strings may propagate to the diff output (see
      DIFF_SPEC §7 + DiffResult.paths_allowed).
    """

    # `source` is "baseline" or "current" — used for error messages
    # and renderer disambiguation. Not a load-bearing identifier.
    source: str

    trustfall_lite_version: Optional[str] = None
    groups_scanned: Optional[int] = None
    total_bytes: Optional[int] = None
    registry_kid: Optional[str] = None
    registry_manifest_digest: Optional[str] = None
    include_paths: bool = False


@dataclass(frozen=True)
class DiffResult:
    """
    The complete output of `diff_scans(baseline, current)`.

    `summary` carries aggregate counts; `changes` is the ordered list
    of individual change entries. The order is:

    1. group_added (sorted by source, then group_id)
    2. group_removed (sorted by source, then group_id)
    3. status_changed (sorted by source, then group_id)
    4. artifact_changed (sorted by group identity, then filename)
    5. artifact_added (sorted by group identity, then filename)
    6. artifact_removed (sorted by group identity, then filename)

    This order matches the human-readable rendering order in
    DIFF_SPEC §6 and gives deterministic test output.

    `baseline` and `current` carry per-side metadata (registry
    snapshot, privacy posture, version). These do NOT affect change
    classification. They exist so the renderer can write the audit
    block in DIFF_SPEC §6.

    `paths_allowed` is the privacy gate for path-string propagation
    in renderers. Per DIFF_SPEC §7, paths may flow through to diff
    output only when BOTH baseline and current scans had
    `include_paths == True`. The diff core enforces this on the
    result; renderers must check it before emitting any path string.
    """

    summary: DiffSummary
    baseline: DiffScanMetadata
    current: DiffScanMetadata
    paths_allowed: bool
    changes: list[DiffChange] = field(default_factory=list)


# ════════════════════════════════════════════════════════════════════
# Internal helpers
# ════════════════════════════════════════════════════════════════════


def _extract_metadata(
    scan: dict[str, Any], source_label: str
) -> DiffScanMetadata:
    """
    Extract per-side metadata from a scan-output dict.

    `source_label` is "baseline" or "current" — set by `diff_scans`
    so renderers can disambiguate the two metadata objects in error
    messages without needing extra positional arguments.

    Per DIFF_SPEC §5, all metadata fields are optional in the scan
    JSON (older v0.2.x scans don't carry registry_kid /
    registry_manifest_digest; v0.3.0+ scans always do once the API
    plumbing lands). Missing fields surface as None on the
    DiffScanMetadata.

    Schema dependency: the registry digest is preserved as raw hex
    exactly as the scan emitted it. The diff core does NOT prepend
    "sha256:" or normalize case. If the scan emits a malformed
    digest, that's a scanner-side bug — the diff faithfully
    reproduces it for debugging.
    """
    summary = scan.get("summary", {}) or {}
    return DiffScanMetadata(
        source=source_label,
        trustfall_lite_version=scan.get("trustfall_lite_version"),
        groups_scanned=summary.get("groups_scanned"),
        total_bytes=summary.get("total_bytes"),
        registry_kid=scan.get("registry_kid"),
        registry_manifest_digest=scan.get("registry_manifest_digest"),
        # DIFF_SPEC §7: include_paths defaults to False if absent.
        # An older scan that predates the field is treated as
        # paths-excluded for the privacy gate.
        include_paths=bool(scan.get("include_paths", False)),
    )


def _group_identity(group: dict[str, Any]) -> tuple[str, str]:
    """
    Extract the (source, group_id) identity tuple from a scan-output
    group dict. Per DIFF_SPEC §3, this tuple is the load-bearing
    identity key for diff matching.
    """
    return (group["source"], group["group_id"])


def _index_groups_by_identity(
    scan: dict[str, Any],
) -> dict[tuple[str, str], dict[str, Any]]:
    """
    Build a (source, group_id) → group dict from a scan output.

    The scan JSON's `groups` field is a list; the diff needs random
    access by identity tuple to compute set differences.
    """
    return {_group_identity(g): g for g in scan.get("groups", [])}


def _index_artifacts_by_filename(
    artifacts: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """
    Build a filename → artifact dict for a single group's artifacts.
    Used by the artifact precedence rule (DIFF_SPEC §3): artifacts
    matching by filename across baseline and current with differing
    SHA-256 are classified as artifact_changed only.

    If two artifacts in the same group share a filename (which would
    be a malformed scan), the last one wins. The well-formed scan
    output never produces duplicate filenames within a group.
    """
    return {a["filename"]: a for a in artifacts if "filename" in a}


def _diff_artifacts_in_matched_group(
    source: str,
    group_id: str,
    baseline_artifacts: list[dict[str, Any]],
    current_artifacts: list[dict[str, Any]],
) -> list[DiffChange]:
    """
    Compute artifact-level changes for a group present in both scans.

    Implements the DIFF_SPEC §3 precedence rule:

    1. Match artifacts by filename when filename exists on both sides.
    2. Same filename + different sha256 → artifact_changed only.
       Both sides excluded from added/removed.
    3. Remaining unmatched current shas → artifact_added.
    4. Remaining unmatched baseline shas → artifact_removed.

    The rule guarantees each artifact contributes to exactly one
    change class (no double-counting).
    """
    changes: list[DiffChange] = []

    baseline_by_filename = _index_artifacts_by_filename(baseline_artifacts)
    current_by_filename = _index_artifacts_by_filename(current_artifacts)

    # Track which artifacts have been "consumed" by the precedence
    # rule (matched by filename). These are excluded from the
    # added/removed pass below.
    matched_baseline_shas: set[str] = set()
    matched_current_shas: set[str] = set()

    # Step 1+2: Match by filename. Same filename + different sha →
    # artifact_changed; same filename + same sha → unchanged (no
    # entry); both sides consumed regardless.
    for filename, baseline_art in baseline_by_filename.items():
        if filename not in current_by_filename:
            continue  # baseline-only filename; handled below as removed
        current_art = current_by_filename[filename]
        baseline_sha = baseline_art.get("sha256", "")
        current_sha = current_art.get("sha256", "")

        # Both sides consumed by the precedence rule, regardless of
        # whether the SHA changed.
        matched_baseline_shas.add(baseline_sha)
        matched_current_shas.add(current_sha)

        if baseline_sha != current_sha:
            changes.append(
                DiffChange(
                    type="artifact_changed",
                    source=source,
                    group_id=group_id,
                    filename=filename,
                    baseline_sha256=baseline_sha,
                    current_sha256=current_sha,
                    baseline_size_bytes=baseline_art.get("size_bytes"),
                    current_size_bytes=current_art.get("size_bytes"),
                )
            )
        # else: filename and sha both match → unchanged, no entry

    # Step 3: Remaining current artifacts (by sha) → artifact_added.
    for art in current_artifacts:
        sha = art.get("sha256", "")
        if sha in matched_current_shas:
            continue
        # Also skip if filename was matched but sha was missing — the
        # filename-match consumed it. Defensive against malformed input.
        filename = art.get("filename")
        if filename and filename in baseline_by_filename:
            continue
        changes.append(
            DiffChange(
                type="artifact_added",
                source=source,
                group_id=group_id,
                filename=filename,
                sha256=sha,
                current_size_bytes=art.get("size_bytes"),
            )
        )

    # Step 4: Remaining baseline artifacts (by sha) → artifact_removed.
    for art in baseline_artifacts:
        sha = art.get("sha256", "")
        if sha in matched_baseline_shas:
            continue
        filename = art.get("filename")
        if filename and filename in current_by_filename:
            continue
        changes.append(
            DiffChange(
                type="artifact_removed",
                source=source,
                group_id=group_id,
                filename=filename,
                sha256=sha,
                baseline_size_bytes=art.get("size_bytes"),
            )
        )

    return changes


def _summarize(changes: list[DiffChange]) -> DiffSummary:
    """Compute aggregate counters from a list of change entries."""
    counters: dict[str, int] = {
        "group_added": 0,
        "group_removed": 0,
        "artifact_added": 0,
        "artifact_removed": 0,
        "artifact_changed": 0,
        "status_changed": 0,
    }
    regressions = 0
    improvements = 0

    for change in changes:
        counters[change.type] += 1
        if change.type == "status_changed":
            if change.direction == "regression":
                regressions += 1
            elif change.direction == "improvement":
                improvements += 1

    return DiffSummary(
        groups_added=counters["group_added"],
        groups_removed=counters["group_removed"],
        artifacts_added=counters["artifact_added"],
        artifacts_removed=counters["artifact_removed"],
        artifacts_changed=counters["artifact_changed"],
        status_changed=counters["status_changed"],
        status_regressions=regressions,
        status_improvements=improvements,
    )


def _sort_key(change: DiffChange) -> tuple[int, str, str, str]:
    """
    Deterministic sort key per the DiffResult.changes ordering rule.

    The order is:
      1. group_added
      2. group_removed
      3. status_changed
      4. artifact_changed
      5. artifact_added
      6. artifact_removed

    Within each class, sort by source, then group_id, then filename.
    """
    type_order: dict[str, int] = {
        "group_added": 1,
        "group_removed": 2,
        "status_changed": 3,
        "artifact_changed": 4,
        "artifact_added": 5,
        "artifact_removed": 6,
    }
    return (
        type_order[change.type],
        change.source,
        change.group_id,
        change.filename or "",
    )


# ════════════════════════════════════════════════════════════════════
# Public API: diff_scans
# ════════════════════════════════════════════════════════════════════


def diff_scans(
    baseline: dict[str, Any], current: dict[str, Any]
) -> DiffResult:
    """
    Compute the diff between two scan-output dicts.

    Both arguments are expected to be the dict returned by
    `cli.py:_render_json_scan` (or its file-loaded equivalent). The
    function is pure: no I/O, no rendering, no side effects.

    See DIFF_SPEC.md for the contract this function must satisfy.

    Identity model:
        Two groups in baseline and current are the same logical group
        iff `(source, group_id)` matches. Same group_id under different
        sources are distinct logical groups (DIFF_SPEC §3).

    Change classes (DIFF_SPEC §4):
        group_added, group_removed, artifact_added, artifact_removed,
        artifact_changed, status_changed.

    Artifact precedence rule (DIFF_SPEC §3):
        Same filename + different SHA-256 across baseline and current
        emits artifact_changed exclusively. The artifacts are not
        also counted as artifact_added or artifact_removed.

    Metadata (DIFF_SPEC §5 + §7):
        baseline/current metadata is extracted and surfaced on the
        DiffResult but does NOT affect change classification. Two
        scans that differ only in their registry snapshot digest
        produce zero change entries.

    Privacy gate (DIFF_SPEC §7):
        `paths_allowed` is True iff BOTH baseline and current scans
        had `include_paths == True`. Renderers must check this gate
        before emitting any path string.
    """
    baseline_meta = _extract_metadata(baseline, source_label="baseline")
    current_meta = _extract_metadata(current, source_label="current")
    paths_allowed = baseline_meta.include_paths and current_meta.include_paths

    baseline_groups = _index_groups_by_identity(baseline)
    current_groups = _index_groups_by_identity(current)

    baseline_keys = set(baseline_groups.keys())
    current_keys = set(current_groups.keys())

    changes: list[DiffChange] = []

    # group_added: in current but not in baseline
    for key in current_keys - baseline_keys:
        source, group_id = key
        group = current_groups[key]
        changes.append(
            DiffChange(
                type="group_added",
                source=source,
                group_id=group_id,
                group_status=group.get("status"),
                n_artifacts=group.get("n_artifacts"),
                total_bytes=group.get("total_bytes"),
                claimed_model_id=group.get("claimed_model_id"),
            )
        )

    # group_removed: in baseline but not in current
    for key in baseline_keys - current_keys:
        source, group_id = key
        group = baseline_groups[key]
        changes.append(
            DiffChange(
                type="group_removed",
                source=source,
                group_id=group_id,
                group_status=group.get("status"),
                n_artifacts=group.get("n_artifacts"),
                total_bytes=group.get("total_bytes"),
                claimed_model_id=group.get("claimed_model_id"),
            )
        )

    # Matched groups: status_changed + artifact-level diff
    for key in baseline_keys & current_keys:
        source, group_id = key
        baseline_group = baseline_groups[key]
        current_group = current_groups[key]

        # status_changed
        baseline_status = baseline_group.get("status", "")
        current_status = current_group.get("status", "")
        if baseline_status != current_status:
            direction = _classify_status_direction(
                baseline_status, current_status
            )
            changes.append(
                DiffChange(
                    type="status_changed",
                    source=source,
                    group_id=group_id,
                    baseline_status=baseline_status,
                    current_status=current_status,
                    direction=direction,
                    claimed_model_id=current_group.get("claimed_model_id"),
                )
            )

        # Artifact-level changes (precedence rule applied internally)
        artifact_changes = _diff_artifacts_in_matched_group(
            source=source,
            group_id=group_id,
            baseline_artifacts=baseline_group.get("artifacts", []),
            current_artifacts=current_group.get("artifacts", []),
        )
        changes.extend(artifact_changes)

    # Deterministic ordering for testability
    changes.sort(key=_sort_key)

    return DiffResult(
        summary=_summarize(changes),
        baseline=baseline_meta,
        current=current_meta,
        paths_allowed=paths_allowed,
        changes=changes,
    )


# ════════════════════════════════════════════════════════════════════
# JSON renderer (pure function — DIFF_SPEC §6 + §7)
# ════════════════════════════════════════════════════════════════════
#
# `render_diff_as_dict` consumes a `DiffResult` and produces a
# JSON-serializable dict ready for `json.dumps`. It is the first
# user-visible serialization layer and must satisfy three contracts:
#
# 1. Schema stability. The dict shape is the public schema. Every
#    field documented in DIFF_SPEC §6 appears in every output, even
#    when the underlying value is None. Schema consumers can write
#    `output["baseline"]["registry_kid"]` and rely on the key being
#    present — they may need to handle a `null` value, but they
#    never need to handle a missing key. Missing fields are a
#    BLOOMZ-NaN-class drift the schema explicitly forbids.
#
# 2. Null-not-omitted. When `DiffScanMetadata.registry_manifest_digest
#    is None`, the JSON output emits `null`, not an empty string and
#    not a missing key. This is the renderer's hard guardrail against
#    silently coercing absent data into "valid-looking" defaults.
#
# 3. Privacy gate. When `paths_allowed=False`, no field whose name
#    contains "path" appears in any change entry. The check is by
#    field-name pattern, applied to every change before emission.
#    The current Block 3 schema has no path-bearing fields on
#    DiffChange, so the gate is forward-compatible — but the test
#    pins the structural rule today so a future field addition that
#    bypasses the gate fails loudly.
#
# Schema versioning lives at the top level. The diff tool's own
# `trustfall_lite_version` is distinct from the per-side metadata
# version (which describes the producing scan); the top-level field
# describes the renderer that produced THIS document. They may
# differ, e.g. when a v0.3.1 diff reads v0.3.0 scan files.


_DIFF_SCHEMA_VERSION: str = "0.3.0"


def _metadata_to_dict(meta: DiffScanMetadata) -> dict[str, Any]:
    """
    Convert a DiffScanMetadata to its JSON dict form.

    Field order matches the DIFF_SPEC §6 schema. Missing values
    emit as null per the null-not-omitted rule. The `source` label
    is intentionally NOT emitted — it's an internal disambiguator
    for error messages, not part of the schema (the dict is already
    keyed under "baseline" or "current").
    """
    return {
        "trustfall_lite_version": meta.trustfall_lite_version,
        "groups_scanned": meta.groups_scanned,
        "total_bytes": meta.total_bytes,
        "registry_kid": meta.registry_kid,
        "registry_manifest_digest": meta.registry_manifest_digest,
        "include_paths": meta.include_paths,
    }


def _summary_to_dict(summary: DiffSummary) -> dict[str, int]:
    """
    Convert a DiffSummary to its JSON dict form.

    All eight counters are always emitted, in the order: six
    change-class counters first (matching CHANGE_TYPES order),
    then the two derived counters (regressions / improvements).
    """
    return {
        "groups_added": summary.groups_added,
        "groups_removed": summary.groups_removed,
        "artifacts_added": summary.artifacts_added,
        "artifacts_removed": summary.artifacts_removed,
        "artifacts_changed": summary.artifacts_changed,
        "status_changed": summary.status_changed,
        "status_regressions": summary.status_regressions,
        "status_improvements": summary.status_improvements,
    }


def _change_to_dict(change: DiffChange) -> dict[str, Any]:
    """
    Convert a DiffChange to its JSON dict form.

    Each change-class shape carries only fields meaningful to that
    type. A group_added does not emit `baseline_status`; an
    artifact_added does not emit `baseline_sha256`; etc. Including
    irrelevant fields would create schema noise and confuse
    consumers about which fields are load-bearing.

    Within a class, fields are ordered:
      1. type
      2. identity (source, group_id, filename if applicable)
      3. semantic fields (sha256s, statuses, sizes, etc.)
      4. context fields (claimed_model_id, n_artifacts, etc.)
    """
    base: dict[str, Any] = {
        "type": change.type,
        "source": change.source,
        "group_id": change.group_id,
    }

    if change.type == "group_added" or change.type == "group_removed":
        base["status"] = change.group_status
        base["n_artifacts"] = change.n_artifacts
        base["total_bytes"] = change.total_bytes
        base["claimed_model_id"] = change.claimed_model_id
        return base

    if change.type == "status_changed":
        base["baseline_status"] = change.baseline_status
        base["current_status"] = change.current_status
        base["direction"] = change.direction
        base["claimed_model_id"] = change.claimed_model_id
        return base

    if change.type == "artifact_added":
        base["filename"] = change.filename
        base["sha256"] = change.sha256
        base["size_bytes"] = change.current_size_bytes
        return base

    if change.type == "artifact_removed":
        base["filename"] = change.filename
        base["sha256"] = change.sha256
        base["size_bytes"] = change.baseline_size_bytes
        return base

    if change.type == "artifact_changed":
        base["filename"] = change.filename
        base["baseline_sha256"] = change.baseline_sha256
        base["current_sha256"] = change.current_sha256
        base["baseline_size_bytes"] = change.baseline_size_bytes
        base["current_size_bytes"] = change.current_size_bytes
        return base

    # Defensive: if a future change class is added without updating
    # this function, fail loudly rather than silently emitting an
    # incomplete entry. This is the renderer-layer analog of the
    # six-change-classes-exactly test.
    raise ValueError(
        f"render_diff_as_dict: unknown change type {change.type!r}; "
        f"add a shape branch in _change_to_dict and update tests"
    )


def _strip_path_keys(d: dict[str, Any]) -> dict[str, Any]:
    """
    Privacy gate enforcement (DIFF_SPEC §7).

    Recursively remove any key whose name contains "path" (case-
    insensitive) from the dict. Used when `paths_allowed=False` on
    the diff result to ensure no path string can leak through any
    change entry, regardless of which DiffChange field it occupied.

    The check is by NAME pattern, not by VALUE. A future schema
    addition like `baseline_path` or `local_paths` is gated
    automatically. If a field happens to contain "path" in its name
    but is not actually a path string, the rule still applies — we
    prefer over-stripping to under-stripping for a privacy contract.

    Notable exception: the top-level `paths_allowed` boolean is
    never stripped because it IS the gate flag itself; stripping it
    would erase the very signal that explains why other path keys
    are absent. The caller (`render_diff_as_dict`) handles this by
    applying _strip_path_keys to nested entries only, never to the
    root dict.
    """
    return {
        k: (_strip_path_keys(v) if isinstance(v, dict) else v)
        for k, v in d.items()
        if "path" not in k.lower()
    }


def render_diff_as_dict(result: DiffResult) -> dict[str, Any]:
    """
    Render a DiffResult as a JSON-serializable dict.

    The output dict matches the v0.3.0 diff schema documented in
    DIFF_SPEC §6 + §7. It is suitable for `json.dumps` without
    additional encoding hooks — every value is a JSON primitive
    (str, int, bool, None, list, dict).

    Three guarantees:

    1. **Schema stability.** Every field in the spec appears in
       every output. Missing values emit as `null`, not as omitted
       keys. A consumer can rely on `output["baseline"]
       ["registry_kid"]` always being a valid key access.

    2. **Deterministic field order.** Fields appear in spec-defined
       order, not alphabetical. Test fixtures can compare the dict
       directly without sort_keys preprocessing.

    3. **Privacy gate.** When `result.paths_allowed=False`, no key
       whose name contains "path" appears in any nested change
       entry (the top-level `paths_allowed` flag itself is
       preserved as the audit signal).

    Pure function: no I/O, no mutation of the input. Calling this
    twice with the same DiffResult produces dicts that are equal
    under `==` and serialize byte-identical under
    `json.dumps(..., sort_keys=False)`.
    """
    # Build per-change dicts, applying the privacy gate per entry.
    change_dicts: list[dict[str, Any]] = []
    for change in result.changes:
        change_dict = _change_to_dict(change)
        if not result.paths_allowed:
            change_dict = _strip_path_keys(change_dict)
        change_dicts.append(change_dict)

    return {
        "schema_version": _DIFF_SCHEMA_VERSION,
        "baseline": _metadata_to_dict(result.baseline),
        "current": _metadata_to_dict(result.current),
        "paths_allowed": result.paths_allowed,
        "summary": _summary_to_dict(result.summary),
        "changes": change_dicts,
    }


# ════════════════════════════════════════════════════════════════════
# Text renderer (pure function — DIFF_SPEC §6)
# ════════════════════════════════════════════════════════════════════
#
# `render_diff_as_text` is the human-readable counterpart to
# `render_diff_as_dict`. It consumes a `DiffResult` and produces a
# single string suitable for terminal output.
#
# The text renderer's contract is distinct from the JSON renderer's
# in three ways:
#
# 1. Two-layer vocabulary. The JSON layer uses machine-readable
#    enum values (`pilot_available`, `unknown_variant`); the text
#    layer uses human labels (`pilot enrollment available`,
#    `unknown variant`). Both layers represent the same data; the
#    text rendering is the user-facing presentation. The mapping
#    is owned by `formatter._STATUS_LABELS`, which is the single
#    source of truth for status display strings.
#
# 2. Forbidden-phrases guard. Every text output must pass
#    `assert_no_forbidden_phrases` before leaving the function.
#    This is the load-bearing fail-loud check that prevents Lite's
#    output from drifting into runtime-verification language
#    ("compromised", "tampered", "fake") even when constructing
#    audit notes about registry drift, status regressions, or
#    metadata mismatches.
#
# 3. Paths gate (structural). Filesystem path strings must not
#    appear in text output unless `result.paths_allowed=True`.
#    The current `DiffChange` schema does not carry paths — every
#    `filename` field is a basename — so the gate is currently a
#    forward-compatible structural guarantee. The renderer does
#    not actively strip paths because there are none to strip;
#    the test guard pins the structural property so a future
#    schema addition cannot bypass the gate without an explicit
#    test failure.
#
# Determinism: same DiffResult → same string, byte-identical.
# This is what makes the text renderer suitable for diff-of-diffs
# (e.g., comparing two text outputs in a code review) and for
# golden-file testing in the CLI block (Block 6).


_SECTION_RULE: str = "═══"


def _render_metadata_line(meta: DiffScanMetadata, label: str) -> str:
    """
    Render one side's metadata as a single audit line.

    Format:
        Baseline: lite=0.3.0, groups=2, registry=fallrisk-..., digest=5f15...

    All four fields are emitted when present. Missing values render
    as the literal `-` rather than being omitted, so the line shape
    is stable across audit comparisons.
    """
    version = meta.trustfall_lite_version or "-"
    groups = meta.groups_scanned if meta.groups_scanned is not None else "-"
    kid = meta.registry_kid or "-"
    digest = meta.registry_manifest_digest
    digest_display = (digest[:16] + "...") if digest and len(digest) >= 16 else (digest or "-")
    return (
        f"{label}: lite={version}, "
        f"groups={groups}, "
        f"registry={kid}, "
        f"digest={digest_display}"
    )


def _render_registry_audit_note(
    baseline: DiffScanMetadata, current: DiffScanMetadata
) -> Optional[str]:
    """
    Render a neutral audit note when the baseline and current
    registry digests differ.

    Per DIFF_SPEC §6: registry-snapshot drift is context for
    interpreting status changes, NOT itself a local model-surface
    change. The note is informational — it tells the reader that
    status_changed entries between these two scans may reflect
    registry coverage changes as well as on-disk file changes.

    Returns None when digests match or either is missing (no note
    needed). Returns a multi-line string when both sides have
    digests and they differ.

    The note language is deliberately neutral. Words like
    "tampered", "compromised", or "mismatch" are forbidden by the
    forbidden-phrases guard. The intended tone is "here is a fact
    you should know" not "something is wrong."
    """
    if not baseline.registry_manifest_digest or not current.registry_manifest_digest:
        return None
    if baseline.registry_manifest_digest == current.registry_manifest_digest:
        return None

    baseline_short = baseline.registry_manifest_digest[:16] + "..."
    current_short = current.registry_manifest_digest[:16] + "..."
    return (
        "Registry snapshot changed between scans.\n"
        f"  Baseline digest: {baseline_short}\n"
        f"  Current digest:  {current_short}\n"
        "  Status changes may reflect registry coverage changes "
        "as well as local file changes."
    )


def _format_status_for_text(status_value: str) -> str:
    """
    Convert a JSON-layer status value into its human-readable label.

    Examples:
        "verified"          → "verified artifact"
        "unknown_variant"   → "unknown variant"
        "not_enrolled"      → "not enrolled"
        "pilot_available"   → "pilot enrollment available"

    This is THE place where the two-layer vocabulary becomes
    explicit. The JSON layer renders machine values; the text
    layer renders human labels. The mapping lives in
    `formatter._STATUS_LABELS` and is the single source of truth.

    Falls back to the raw value if the status is unrecognized,
    which should never happen but guards against silent corruption
    if a malformed scan slips through.
    """
    try:
        return _STATUS_LABELS[Status(status_value)]
    except (KeyError, ValueError):
        return status_value  # defensive fallback


def _format_change_group_added(change: DiffChange) -> str:
    """Render a group_added change. Format: '+ source:group_id (status, N artifacts, B bytes)'."""
    artifacts_str = (
        f"{change.n_artifacts} artifact"
        + ("s" if change.n_artifacts != 1 else "")
        if change.n_artifacts is not None
        else "? artifacts"
    )
    status_str = _format_status_for_text(change.group_status or "")
    return f"  + {change.source}:{change.group_id}  ({status_str}, {artifacts_str})"


def _format_change_group_removed(change: DiffChange) -> str:
    """Render a group_removed change. Format: '- source:group_id (status, N artifacts)'."""
    artifacts_str = (
        f"{change.n_artifacts} artifact"
        + ("s" if change.n_artifacts != 1 else "")
        if change.n_artifacts is not None
        else "? artifacts"
    )
    status_str = _format_status_for_text(change.group_status or "")
    return f"  - {change.source}:{change.group_id}  ({status_str}, {artifacts_str})"


def _format_change_status(change: DiffChange) -> str:
    """
    Render a status_changed entry.

    Format (two lines per entry):
        <icon> <direction>  <source>:<group_id>
                            <baseline_label> → <current_label>

    The icon reflects the CURRENT status (what state the model is
    in now), not the direction of change. So a regression to
    `unknown_variant` shows the ⚠ icon; an improvement to
    `verified` shows the ✓ icon. The direction word ("regression",
    "improvement", "lateral") gives the transition context.
    """
    direction = change.direction or "lateral"
    # Pad direction word to a fixed width so multi-entry blocks line up
    direction_padded = f"{direction:<11}"

    # Use the CURRENT status's icon — what state the model is in now
    try:
        current_icon = _STATUS_ICONS[Status(change.current_status or "")]
    except (KeyError, ValueError):
        current_icon = " "

    baseline_label = _format_status_for_text(change.baseline_status or "")
    current_label = _format_status_for_text(change.current_status or "")

    line1 = f"  {current_icon} {direction_padded} {change.source}:{change.group_id}"
    line2 = f"                {baseline_label} → {current_label}"
    return f"{line1}\n{line2}"


def _format_change_artifact_added(change: DiffChange) -> str:
    """Render an artifact_added change. Format: '+ source:group_id  filename  (sha=...)'."""
    sha_short = (change.sha256[:16] + "...") if change.sha256 else "?"
    return (
        f"  + {change.source}:{change.group_id}  "
        f"{change.filename or '?'}  (sha={sha_short})"
    )


def _format_change_artifact_removed(change: DiffChange) -> str:
    """Render an artifact_removed change. Format: '- source:group_id  filename  (sha=...)'."""
    sha_short = (change.sha256[:16] + "...") if change.sha256 else "?"
    return (
        f"  - {change.source}:{change.group_id}  "
        f"{change.filename or '?'}  (sha={sha_short})"
    )


def _format_change_artifact_changed(change: DiffChange) -> str:
    """
    Render an artifact_changed entry.

    Format:
        ~ source:group_id  filename
            sha:  aaaa... → bbbb...
    """
    baseline_short = (
        change.baseline_sha256[:16] + "..."
        if change.baseline_sha256
        else "?"
    )
    current_short = (
        change.current_sha256[:16] + "..."
        if change.current_sha256
        else "?"
    )
    line1 = (
        f"  ~ {change.source}:{change.group_id}  {change.filename or '?'}"
    )
    line2 = f"      sha:  {baseline_short} → {current_short}"
    return f"{line1}\n{line2}"


_CHANGE_FORMATTERS: dict[str, Any] = {
    "group_added": _format_change_group_added,
    "group_removed": _format_change_group_removed,
    "status_changed": _format_change_status,
    "artifact_added": _format_change_artifact_added,
    "artifact_removed": _format_change_artifact_removed,
    "artifact_changed": _format_change_artifact_changed,
}


def _render_summary_block(summary: DiffSummary) -> str:
    """
    Render the summary counter block.

    Always emits all eight counters in a fixed format. Used
    regardless of `quiet` because the summary IS the at-a-glance
    answer; suppressing it would defeat the diff's purpose.
    """
    lines = [
        "Summary",
        f"  groups added:        {summary.groups_added}",
        f"  groups removed:      {summary.groups_removed}",
        f"  artifacts added:     {summary.artifacts_added}",
        f"  artifacts removed:   {summary.artifacts_removed}",
        f"  artifacts changed:   {summary.artifacts_changed}",
        f"  status changed:      {summary.status_changed}",
        f"    regressions:       {summary.status_regressions}",
        f"    improvements:      {summary.status_improvements}",
    ]
    return "\n".join(lines)


def render_diff_as_text(
    result: DiffResult, *, quiet: bool = False
) -> str:
    """
    Render a DiffResult as a human-readable text string.

    Output layout:

        ═══ Diff: trustfall-lite v0.3.0 ═══

        Baseline: lite=..., groups=..., registry=..., digest=...
        Current:  lite=..., groups=..., registry=..., digest=...
        [optional registry-drift audit note]
        Paths:    <allowed | excluded>

        Summary
          ...eight counters...

        [Section per change class containing changes; suppressed
         when quiet=True and the section is empty]

    The renderer is pure: same input → byte-identical output.

    Args:
        result: The DiffResult to render.
        quiet: When True, suppresses empty change-class sections
            from the output. The summary block always appears even
            when all counters are zero. When False (default), every
            section header appears, with a "(none)" placeholder for
            empty classes.

    Returns:
        A multi-line string ending in a single newline. Free of
        forbidden phrases (raises ForbiddenPhraseError if any
        slipped through, which would indicate a bug in the
        renderer or its inputs).

    Privacy:
        Filesystem path strings do not appear in the output unless
        `result.paths_allowed=True`. The current schema does not
        carry path strings on DiffChange entries, so this is a
        forward-compatible structural property; tests pin the
        guarantee at the renderer level.
    """
    sections: list[str] = []

    # ─── Header ───────────────────────────────────────────────
    version = result.baseline.trustfall_lite_version or "?"
    sections.append(f"{_SECTION_RULE} Diff: trustfall-lite v{version} {_SECTION_RULE}")
    sections.append("")  # blank line after header

    # ─── Audit block ──────────────────────────────────────────
    sections.append(_render_metadata_line(result.baseline, "Baseline"))
    sections.append(_render_metadata_line(result.current, "Current "))

    registry_note = _render_registry_audit_note(
        result.baseline, result.current
    )
    if registry_note:
        sections.append("")
        sections.append(registry_note)
        sections.append("")

    paths_label = "allowed" if result.paths_allowed else "excluded"
    sections.append(f"Paths:    {paths_label}")
    sections.append("")  # blank line before summary

    # ─── Summary block (always emitted) ───────────────────────
    sections.append(_render_summary_block(result.summary))
    sections.append("")  # blank line before change sections

    # ─── Change sections ──────────────────────────────────────
    # Section grouping for the text renderer:
    #   - "Group changes" : group_added + group_removed
    #   - "Status changes": status_changed
    #   - "Artifact changes": artifact_added + artifact_removed + artifact_changed
    #
    # Each section is suppressed when quiet=True and the section
    # has no entries. When quiet=False, the section header is shown
    # with "(none)" in place of entries, so the output shape is
    # stable for diff-of-diffs review.

    group_changes = [
        c
        for c in result.changes
        if c.type in ("group_added", "group_removed")
    ]
    status_changes = [c for c in result.changes if c.type == "status_changed"]
    artifact_changes = [
        c
        for c in result.changes
        if c.type
        in ("artifact_added", "artifact_removed", "artifact_changed")
    ]

    def _emit_section(title: str, changes: list[DiffChange]) -> None:
        if quiet and not changes:
            return
        sections.append(title)
        if not changes:
            sections.append("  (none)")
        else:
            for change in changes:
                sections.append(_CHANGE_FORMATTERS[change.type](change))
        sections.append("")  # blank line after each section

    _emit_section("Group changes", group_changes)
    _emit_section("Status changes", status_changes)
    _emit_section("Artifact changes", artifact_changes)

    # ─── Assemble + verify ────────────────────────────────────
    output = "\n".join(sections).rstrip() + "\n"

    # Hard guardrail: no forbidden phrases. Raises
    # ForbiddenPhraseError if any slipped through. This is fail-
    # loud by design — a forbidden phrase in the output is a bug
    # we need to surface, not hide.
    assert_no_forbidden_phrases(output)

    return output
