"""
Scanner orchestrator.

Wires the layers together:
    adapters.discover()  → ModelGroups (with empty hashes)
    hashing.hash_groups() → ModelGroups (with hashes filled in)
    verifier.verify()    → per-group FileResult for the formatter

Per Decision 1 (sharded-model roll-up): the scanner reports ONE
FileResult per ModelGroup — even when the group has 8 shards. The
human-readable output shows the model, not the shards. Per-shard
data is preserved in the JSON output via `--json` (handled by the
CLI layer).

A sharded model is reported as `verified` only when ALL its shards
match the artifact_hashes of the same registry record. Any shard
that doesn't match downgrades the whole group to `unknown_variant`
(if there's a model_id claim) or `not_enrolled` (if there isn't).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .api import APILookupResult, TrustfallAPI, VerifiedRecord
from .formatter import FileResult, Status
from .models import ArtifactCandidate, ModelGroup
from .registry import LoadedSnapshot, lookup_hash


# ════════════════════════════════════════════════════════════════════
# Per-group scan result
# ════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class GroupScanResult:
    """
    One ModelGroup → one user-visible result.

    Holds everything needed to render the human-readable output,
    populate the JSON report, and aggregate the summary.
    """

    group: ModelGroup
    file_result: FileResult     # the formatter input (one row in default output)
    artifact_lookups: tuple[APILookupResult, ...]  # per-shard underlying lookups
    matched_record: VerifiedRecord | None = None  # populated for VERIFIED groups


# ════════════════════════════════════════════════════════════════════
# Lookup interface
# ════════════════════════════════════════════════════════════════════


class HashLookup:
    """
    Abstract interface for resolving SHA-256 → VerifiedRecord.

    Two implementations:
      - APIHashLookup     : POST /v1/verify/manifest, returns API results
      - LocalHashLookup   : local snapshot in-memory lookup

    Both return APILookupResults with the same shape so the scanner
    is implementation-agnostic.
    """

    def lookup_many(self, sha256s: list[str]) -> dict[str, APILookupResult]:
        raise NotImplementedError


class APIHashLookup(HashLookup):
    def __init__(
        self,
        api: TrustfallAPI,
        path_hints: dict[str, str] | None = None,
        size_bytes: dict[str, int] | None = None,
    ) -> None:
        self._api = api
        self._path_hints = path_hints or {}
        self._size_bytes = size_bytes or {}

    def lookup_many(self, sha256s: list[str]) -> dict[str, APILookupResult]:
        results = self._api.verify_manifest(
            sha256s,
            path_hints=self._path_hints,
            size_bytes=self._size_bytes,
        )
        return {r.sha256: r for r in results}


class LocalHashLookup(HashLookup):
    def __init__(self, snapshot: LoadedSnapshot) -> None:
        self._snapshot = snapshot

    def lookup_many(self, sha256s: list[str]) -> dict[str, APILookupResult]:
        out: dict[str, APILookupResult] = {}
        for h in sha256s:
            record = lookup_hash(self._snapshot, h)
            if record is None:
                out[h] = APILookupResult(sha256=h, status="not_enrolled")
            else:
                out[h] = APILookupResult(sha256=h, status="verified", record=record)
        return out


# ════════════════════════════════════════════════════════════════════
# Scanner
# ════════════════════════════════════════════════════════════════════


def verify_groups(
    groups: list[ModelGroup],
    lookup: HashLookup,
) -> list[GroupScanResult]:
    """
    Verify a list of hydrated ModelGroups against a HashLookup.

    Steps:
      1. Collect all unique SHA-256s across all groups.
      2. Look them up in one batch (or one local lookup).
      3. For each group, decide its status by examining the lookups
         for its artifacts.
      4. Build a FileResult for the formatter.
    """
    # Collect all hashes that need lookup. Skip empty hashes (which
    # indicate read failures during hashing).
    all_hashes: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for art in group.artifacts:
            if art.sha256 and art.sha256 not in seen:
                seen.add(art.sha256)
                all_hashes.append(art.sha256)

    lookups = lookup.lookup_many(all_hashes) if all_hashes else {}

    return [_classify_group(g, lookups) for g in groups]


def _classify_group(
    group: ModelGroup,
    lookups: dict[str, APILookupResult],
) -> GroupScanResult:
    """
    Decide the status of a group based on the lookup results for its artifacts.

    Decision tree:
      - If ANY artifact has empty sha256 (read failure):
          → status=NOT_ENROLLED with error note (best we can do without rehashing)
      - If ALL artifacts verified AND all map to the same model_id:
          → status=VERIFIED
      - If SOME but not all verified, OR mixed model_ids, AND group has claim:
          → status=UNKNOWN_VARIANT
      - If group has a claim and none verified:
          → status=UNKNOWN_VARIANT
      - Otherwise:
          → status=NOT_ENROLLED
    """
    artifact_lookups: list[APILookupResult] = []
    skipped = 0

    for art in group.artifacts:
        if not art.sha256:
            skipped += 1
            artifact_lookups.append(
                APILookupResult(
                    sha256="",
                    status="error",
                    error_message="hash computation failed",
                )
            )
            continue
        result = lookups.get(art.sha256)
        if result is None:
            artifact_lookups.append(
                APILookupResult(
                    sha256=art.sha256,
                    status="error",
                    error_message="lookup missing from response",
                )
            )
        else:
            artifact_lookups.append(result)

    # Aggregate: are all artifacts verified to the same model_id?
    verified_records: list[VerifiedRecord] = [
        r.record for r in artifact_lookups
        if r.status == "verified" and r.record is not None
    ]
    all_verified = (
        len(verified_records) == len(group.artifacts)
        and len(verified_records) > 0
    )

    # If every artifact verified, do they all reference the same model?
    same_model = False
    matched_record: VerifiedRecord | None = None
    if all_verified:
        model_ids = {r.claims.get("model_id") for r in verified_records}
        if len(model_ids) == 1 and None not in model_ids:
            same_model = True
            matched_record = verified_records[0]

    claim_model_id = group.claimed_model_id
    primary_filename = group.primary_filename()
    n_artifacts = len(group.artifacts)

    # The claim source for this group (uniform across artifacts in v0.1)
    claim_source = None
    if group.artifacts and group.artifacts[0].claim is not None:
        claim_source = group.artifacts[0].claim.claim_source

    # Total size across artifacts (used for summary aggregation)
    total_size = sum(a.size_bytes for a in group.artifacts)

    # Decision
    if same_model and matched_record is not None:
        status = Status.VERIFIED
        claims = matched_record.claims
        # For VERIFIED, lead with the verified model_id (most recognizable)
        # but only if a claim was present; loose verified files keep their filename
        display = claims.get("model_id") if claim_model_id else None
        file_result = FileResult(
            path=primary_filename,
            sha256=group.artifacts[0].sha256,  # representative; JSON has all
            size_bytes=total_size,
            status=status,
            model_id=claims.get("model_id"),
            publisher=claims.get("publisher"),
            license=claims.get("license"),
            claim_source=claim_source,
            n_artifacts=n_artifacts,
            display_name=display,
        )
        return GroupScanResult(
            group=group,
            file_result=file_result,
            artifact_lookups=tuple(artifact_lookups),
            matched_record=matched_record,
        )

    # Anything short of "all verified, same model" with a claim → unknown_variant
    if claim_model_id:
        status = Status.UNKNOWN_VARIANT
        file_result = FileResult(
            path=primary_filename,
            sha256=group.artifacts[0].sha256 if group.artifacts else "",
            size_bytes=total_size,
            status=status,
            model_id=claim_model_id,
            claim_source=claim_source,
            n_artifacts=n_artifacts,
            display_name=claim_model_id,  # lead with the claimed model_id
        )
        return GroupScanResult(
            group=group,
            file_result=file_result,
            artifact_lookups=tuple(artifact_lookups),
            matched_record=None,
        )

    # No claim, not verified → not_enrolled
    status = Status.NOT_ENROLLED
    file_result = FileResult(
        path=primary_filename,
        sha256=group.artifacts[0].sha256 if group.artifacts else "",
        size_bytes=total_size,
        status=status,
        n_artifacts=n_artifacts,
    )
    return GroupScanResult(
        group=group,
        file_result=file_result,
        artifact_lookups=tuple(artifact_lookups),
        matched_record=None,
    )
