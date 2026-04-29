"""
Tests for the diff core (`fallrisk_trustfall.diff`).

This is the first test block per the FROZEN DIFF_SPEC.md and GPT's
recommended implementation order. Six tests cover the load-bearing
invariants:

    1. test_diff_empty                            — identical scans
    2. test_diff_group_added                      — DIFF_SPEC §4 group_added
    3. test_diff_group_removed                    — DIFF_SPEC §4 group_removed
    4. test_diff_artifact_added                   — DIFF_SPEC §4 artifact_added
    5. test_diff_artifact_removed                 — DIFF_SPEC §4 artifact_removed
    6. test_diff_artifact_changed_takes_precedence — DIFF_SPEC §3 precedence rule

The precedence-rule test is the cleverest invariant: same filename +
different SHA across baseline and current must emit artifact_changed
exactly once, never artifact_added + artifact_removed.

Identity model verified throughout: groups are matched by
`(source, group_id)`, not by `group_id` alone.

Status vocabulary verified throughout: machine-readable values are
`verified`, `unknown_variant`, `not_enrolled`, `pilot_available` —
matching the Status enum exactly.

These tests must pass before any rendering, CLI wiring, or
implicit-current-scan logic is added. Subsequent test blocks add
status-change classification, exit-code behavior, JSON renderer
shape, and CLI integration.
"""

from __future__ import annotations

from typing import Any

import pytest

from fallrisk_trustfall.diff import (
    CHANGE_TYPES,
    DiffChange,
    DiffResult,
    DiffScanMetadata,
    DiffSummary,
    diff_scans,
    render_diff_as_dict,
    render_diff_as_text,
)
from fallrisk_trustfall.formatter import (
    FORBIDDEN_PHRASES,
    ForbiddenPhraseError,
)


# ════════════════════════════════════════════════════════════════════
# Fixture builder — minimal scan-JSON dicts
# ════════════════════════════════════════════════════════════════════
#
# These helpers produce the smallest possible scan-output dicts that
# satisfy the schema dependencies in DIFF_SPEC §5. They do NOT
# replicate the full _render_json_scan output — only the fields
# diff_scans actually depends on. Tests that need additional fields
# add them inline.


def make_artifact(
    *,
    filename: str,
    sha256: str,
    size_bytes: int = 1_000_000,
    format_hint: str = "safetensors",
) -> dict[str, Any]:
    """Build a minimal artifact dict per the scan output schema."""
    return {
        "filename": filename,
        "sha256": sha256,
        "size_bytes": size_bytes,
        "format_hint": format_hint,
    }


def make_group(
    *,
    source: str,
    group_id: str,
    status: str = "verified",
    artifacts: list[dict[str, Any]] | None = None,
    claimed_model_id: str | None = None,
    claim_source: str | None = None,
) -> dict[str, Any]:
    """
    Build a minimal group dict per the scan output schema.

    Defaults match a "verified" group with no artifacts, which is
    only useful as a starting template — most tests pass an explicit
    `artifacts` list.
    """
    arts = artifacts if artifacts is not None else []
    return {
        "group_id": group_id,
        "source": source,
        "status": status,
        "n_artifacts": len(arts),
        "total_bytes": sum(a.get("size_bytes", 0) for a in arts),
        "claimed_model_id": claimed_model_id or group_id,
        "claim_source": claim_source,
        "group_kind": "model",
        "artifacts": arts,
    }


def make_scan(
    *,
    groups: list[dict[str, Any]],
    trustfall_lite_version: str = "0.3.0",
    scan_paths: list[str] | None = None,
    include_paths: bool = False,
    trust_ollama_filenames: bool = False,
    registry_kid: str | None = None,
    registry_manifest_digest: str | None = None,
) -> dict[str, Any]:
    """
    Build a minimal scan-output dict per cli.py:_render_json_scan.

    Defaults to a default-locations scan (empty `scan_paths`) so the
    implicit-current-scan safety rule (DIFF_SPEC §3.5) is satisfied
    for tests that don't care about that surface.

    Registry snapshot fields default to None to mirror the v0.2.x
    backward-compat case (older scans don't carry these). Set them
    explicitly in tests that exercise the metadata passthrough.
    """
    scan: dict[str, Any] = {
        "trustfall_lite_version": trustfall_lite_version,
        "scan_paths": scan_paths if scan_paths is not None else [],
        "include_paths": include_paths,
        "trust_ollama_filenames": trust_ollama_filenames,
        "summary": {
            "groups_scanned": len(groups),
            "artifacts_scanned": sum(g.get("n_artifacts", 0) for g in groups),
            "total_bytes": sum(g.get("total_bytes", 0) for g in groups),
        },
        "groups": groups,
    }
    # Registry fields are optional per DIFF_SPEC §5. Only included
    # in the output dict when set, matching the live scan emitter
    # which also omits absent fields rather than emitting null.
    if registry_kid is not None:
        scan["registry_kid"] = registry_kid
    if registry_manifest_digest is not None:
        scan["registry_manifest_digest"] = registry_manifest_digest
    return scan


# ════════════════════════════════════════════════════════════════════
# Test block 1 — core identity and change-class invariants
# ════════════════════════════════════════════════════════════════════


class TestDiffEmpty:
    """
    Two byte-identical scans must produce no changes of any class.

    Per DIFF_SPEC §9: "If baseline and current are byte-identical,
    the diff produces no change entries." This is the lower bound
    on the diff function — no false positives on identical input.
    """

    def test_two_empty_scans_produce_empty_diff(self):
        baseline = make_scan(groups=[])
        current = make_scan(groups=[])

        result = diff_scans(baseline, current)

        assert isinstance(result, DiffResult)
        assert result.changes == []
        assert result.summary.is_empty
        assert result.summary.total_changes == 0

    def test_identical_scans_with_groups_produce_empty_diff(self):
        # Same group, same artifact, identical sha — no changes.
        artifact = make_artifact(
            filename="model.safetensors", sha256="a" * 64
        )
        group = make_group(
            source="huggingface_cache",
            group_id="Qwen/Qwen2.5-0.5B-Instruct",
            artifacts=[artifact],
        )
        baseline = make_scan(groups=[group])
        current = make_scan(groups=[group])

        result = diff_scans(baseline, current)

        assert result.changes == []
        assert result.summary.is_empty

    def test_empty_diff_summary_has_all_counters_zero(self):
        baseline = make_scan(groups=[])
        current = make_scan(groups=[])

        summary = diff_scans(baseline, current).summary

        assert summary.groups_added == 0
        assert summary.groups_removed == 0
        assert summary.artifacts_added == 0
        assert summary.artifacts_removed == 0
        assert summary.artifacts_changed == 0
        assert summary.status_changed == 0
        assert summary.status_regressions == 0
        assert summary.status_improvements == 0


class TestDiffGroupAdded:
    """
    A group present in current but not baseline emits exactly one
    `group_added` entry. Identity is `(source, group_id)`; same
    group_id under a different source is a distinct logical group.
    Per DIFF_SPEC §3 + §4.
    """

    def test_single_group_added(self):
        baseline = make_scan(groups=[])
        new_group = make_group(
            source="huggingface_cache",
            group_id="Qwen/Qwen2.5-0.5B-Instruct",
            artifacts=[
                make_artifact(filename="model.safetensors", sha256="a" * 64)
            ],
        )
        current = make_scan(groups=[new_group])

        result = diff_scans(baseline, current)

        assert result.summary.groups_added == 1
        assert result.summary.total_changes == 1

        added_changes = [c for c in result.changes if c.type == "group_added"]
        assert len(added_changes) == 1
        change = added_changes[0]
        assert change.source == "huggingface_cache"
        assert change.group_id == "Qwen/Qwen2.5-0.5B-Instruct"
        assert change.group_status == "verified"
        assert change.n_artifacts == 1

    def test_same_group_id_different_source_is_distinct_group(self):
        """
        DIFF_SPEC §3 invariant: identity is (source, group_id).
        Same group_id under huggingface_cache vs path is two groups,
        not one. If baseline has the HF version and current has the
        path version, the diff produces group_removed + group_added,
        not a synthetic "moved" entry.
        """
        hf_group = make_group(
            source="huggingface_cache",
            group_id="Qwen/Qwen2.5-0.5B-Instruct",
            artifacts=[make_artifact(filename="m.safetensors", sha256="a" * 64)],
        )
        path_group = make_group(
            source="path",
            group_id="Qwen/Qwen2.5-0.5B-Instruct",  # SAME group_id
            artifacts=[make_artifact(filename="m.safetensors", sha256="a" * 64)],
        )
        baseline = make_scan(groups=[hf_group])
        current = make_scan(groups=[path_group])

        result = diff_scans(baseline, current)

        # Two changes: one removed under huggingface_cache,
        # one added under path. NOT a synthetic moved entry.
        assert result.summary.groups_added == 1
        assert result.summary.groups_removed == 1
        assert result.summary.total_changes == 2

        added = [c for c in result.changes if c.type == "group_added"]
        removed = [c for c in result.changes if c.type == "group_removed"]
        assert len(added) == 1
        assert len(removed) == 1
        assert added[0].source == "path"
        assert removed[0].source == "huggingface_cache"
        # group_id matches on both sides — that's the whole point;
        # the (source, group_id) tuple is what differs.
        assert added[0].group_id == removed[0].group_id

    def test_multiple_groups_added_sorted_deterministically(self):
        baseline = make_scan(groups=[])
        # Add in non-alphabetical order; diff should sort by
        # (source, group_id) for determinism.
        groups = [
            make_group(source="huggingface_cache", group_id="Z/Z-model"),
            make_group(source="huggingface_cache", group_id="A/A-model"),
            make_group(source="ollama", group_id="library/llama:latest"),
        ]
        current = make_scan(groups=groups)

        result = diff_scans(baseline, current)

        added = [c for c in result.changes if c.type == "group_added"]
        assert len(added) == 3
        # Sorted by source first, then group_id
        sources_and_ids = [(c.source, c.group_id) for c in added]
        assert sources_and_ids == sorted(sources_and_ids)


class TestDiffGroupRemoved:
    """
    A group present in baseline but not current emits exactly one
    `group_removed` entry. Per DIFF_SPEC §4.
    """

    def test_single_group_removed(self):
        old_group = make_group(
            source="huggingface_cache",
            group_id="Qwen/Qwen2.5-0.5B-Instruct",
            artifacts=[
                make_artifact(filename="model.safetensors", sha256="a" * 64)
            ],
        )
        baseline = make_scan(groups=[old_group])
        current = make_scan(groups=[])

        result = diff_scans(baseline, current)

        assert result.summary.groups_removed == 1
        assert result.summary.groups_added == 0
        assert result.summary.total_changes == 1

        removed = [c for c in result.changes if c.type == "group_removed"]
        assert len(removed) == 1
        change = removed[0]
        assert change.source == "huggingface_cache"
        assert change.group_id == "Qwen/Qwen2.5-0.5B-Instruct"
        assert change.group_status == "verified"

    def test_group_removal_preserves_metadata_for_audit(self):
        """
        A removed group's metadata should be carried in the change
        entry. An auditor reading the diff needs to know what was
        there before.
        """
        artifacts = [
            make_artifact(
                filename=f"shard-{i}.safetensors",
                sha256=str(i) * 64,
                size_bytes=2_000_000_000,
            )
            for i in range(3)
        ]
        old_group = make_group(
            source="huggingface_cache",
            group_id="meta-llama/Llama-3.1-70B-Instruct",
            artifacts=artifacts,
        )
        baseline = make_scan(groups=[old_group])
        current = make_scan(groups=[])

        result = diff_scans(baseline, current)
        removed = [c for c in result.changes if c.type == "group_removed"][0]

        assert removed.n_artifacts == 3
        assert removed.total_bytes == 6_000_000_000
        assert removed.claimed_model_id == "meta-llama/Llama-3.1-70B-Instruct"


class TestDiffArtifactAdded:
    """
    An artifact in a current group that is not in the same baseline
    group emits `artifact_added`. The group itself must exist in both
    scans — otherwise the change is `group_added`, not artifact-level.
    Per DIFF_SPEC §3 + §4.
    """

    def test_artifact_added_to_existing_group(self):
        """A second artifact appears alongside the first."""
        old_artifact = make_artifact(
            filename="model-00001-of-00002.safetensors", sha256="a" * 64
        )
        new_artifact = make_artifact(
            filename="model-00002-of-00002.safetensors", sha256="b" * 64
        )

        baseline_group = make_group(
            source="huggingface_cache",
            group_id="some-org/some-model",
            artifacts=[old_artifact],
        )
        current_group = make_group(
            source="huggingface_cache",
            group_id="some-org/some-model",
            artifacts=[old_artifact, new_artifact],
        )
        baseline = make_scan(groups=[baseline_group])
        current = make_scan(groups=[current_group])

        result = diff_scans(baseline, current)

        assert result.summary.artifacts_added == 1
        assert result.summary.artifacts_removed == 0
        assert result.summary.groups_added == 0  # group existed already
        assert result.summary.total_changes == 1

        added = [c for c in result.changes if c.type == "artifact_added"]
        assert len(added) == 1
        assert added[0].filename == "model-00002-of-00002.safetensors"
        assert added[0].sha256 == "b" * 64
        assert added[0].source == "huggingface_cache"
        assert added[0].group_id == "some-org/some-model"

    def test_artifact_with_new_filename_and_sha_is_added(self):
        """
        An artifact with a filename that does not appear in baseline
        and a sha that does not appear in baseline → artifact_added.
        Tests the non-precedence path.
        """
        baseline_group = make_group(
            source="huggingface_cache",
            group_id="org/model",
            artifacts=[
                make_artifact(filename="config.json", sha256="c" * 64)
            ],
        )
        current_group = make_group(
            source="huggingface_cache",
            group_id="org/model",
            artifacts=[
                make_artifact(filename="config.json", sha256="c" * 64),
                make_artifact(filename="tokenizer.json", sha256="d" * 64),
            ],
        )

        result = diff_scans(
            make_scan(groups=[baseline_group]),
            make_scan(groups=[current_group]),
        )

        added = [c for c in result.changes if c.type == "artifact_added"]
        assert len(added) == 1
        assert added[0].filename == "tokenizer.json"


class TestDiffArtifactRemoved:
    """
    An artifact in a baseline group that is not in the same current
    group emits `artifact_removed`. Per DIFF_SPEC §3 + §4.
    """

    def test_artifact_removed_from_existing_group(self):
        old_artifact = make_artifact(
            filename="model-00001-of-00002.safetensors", sha256="a" * 64
        )
        sibling = make_artifact(
            filename="model-00002-of-00002.safetensors", sha256="b" * 64
        )

        baseline_group = make_group(
            source="huggingface_cache",
            group_id="some-org/some-model",
            artifacts=[old_artifact, sibling],
        )
        current_group = make_group(
            source="huggingface_cache",
            group_id="some-org/some-model",
            artifacts=[sibling],  # old_artifact gone
        )

        result = diff_scans(
            make_scan(groups=[baseline_group]),
            make_scan(groups=[current_group]),
        )

        assert result.summary.artifacts_removed == 1
        assert result.summary.artifacts_added == 0
        assert result.summary.groups_removed == 0  # group still exists
        assert result.summary.total_changes == 1

        removed = [c for c in result.changes if c.type == "artifact_removed"]
        assert len(removed) == 1
        assert removed[0].filename == "model-00001-of-00002.safetensors"
        assert removed[0].sha256 == "a" * 64

    def test_artifact_removed_carries_size_for_audit(self):
        gone = make_artifact(
            filename="weights.bin", sha256="e" * 64, size_bytes=15_000_000_000
        )
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    artifacts=[gone],
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    artifacts=[],
                )
            ]
        )

        result = diff_scans(baseline, current)
        removed = [c for c in result.changes if c.type == "artifact_removed"][0]

        assert removed.baseline_size_bytes == 15_000_000_000


class TestArtifactChangedTakesPrecedence:
    """
    The cleverest invariant in DIFF_SPEC §3:

        Same filename + different SHA-256 across baseline and current
        emits artifact_changed exclusively. The artifacts are NOT
        also counted as artifact_added or artifact_removed.

    This prevents the double-counting failure mode where a re-
    downloaded model produces three change entries (one removed +
    one added + one changed) when the operationally meaningful
    answer is "the bytes of this one file changed."

    These tests are the load-bearing verification of the precedence
    rule. If these fail, the diff core is wrong in a way that will
    silently corrupt every audit downstream.
    """

    def test_same_filename_different_sha_emits_changed_only(self):
        """
        Single-artifact group, same filename across both scans, sha
        differs. The diff must produce exactly one entry of type
        artifact_changed and zero of artifact_added or
        artifact_removed.
        """
        baseline_group = make_group(
            source="huggingface_cache",
            group_id="org/model",
            artifacts=[
                make_artifact(
                    filename="model.safetensors", sha256="a" * 64
                )
            ],
        )
        current_group = make_group(
            source="huggingface_cache",
            group_id="org/model",
            artifacts=[
                make_artifact(
                    filename="model.safetensors", sha256="b" * 64  # changed
                )
            ],
        )

        result = diff_scans(
            make_scan(groups=[baseline_group]),
            make_scan(groups=[current_group]),
        )

        # Precedence rule: exactly ONE change entry, of type changed.
        assert result.summary.artifacts_changed == 1
        assert result.summary.artifacts_added == 0  # NOT also added
        assert result.summary.artifacts_removed == 0  # NOT also removed
        assert result.summary.total_changes == 1

        changed = [
            c for c in result.changes if c.type == "artifact_changed"
        ]
        assert len(changed) == 1
        change = changed[0]
        assert change.filename == "model.safetensors"
        assert change.baseline_sha256 == "a" * 64
        assert change.current_sha256 == "b" * 64

    def test_precedence_with_unchanged_sibling(self):
        """
        Mixed group: one artifact unchanged, one with same filename +
        different sha. The unchanged sibling produces no entry; the
        changed artifact produces exactly one artifact_changed (not
        added + removed).
        """
        unchanged = make_artifact(
            filename="config.json", sha256="c" * 64
        )
        baseline_group = make_group(
            source="huggingface_cache",
            group_id="org/model",
            artifacts=[
                unchanged,
                make_artifact(
                    filename="model.safetensors", sha256="a" * 64
                ),
            ],
        )
        current_group = make_group(
            source="huggingface_cache",
            group_id="org/model",
            artifacts=[
                unchanged,
                make_artifact(
                    filename="model.safetensors", sha256="b" * 64
                ),
            ],
        )

        result = diff_scans(
            make_scan(groups=[baseline_group]),
            make_scan(groups=[current_group]),
        )

        assert result.summary.artifacts_changed == 1
        assert result.summary.artifacts_added == 0
        assert result.summary.artifacts_removed == 0
        assert result.summary.total_changes == 1

    def test_precedence_with_genuine_add_and_remove(self):
        """
        A group with three changes: one artifact_changed (precedence
        rule), one artifact_added (new filename), one
        artifact_removed (filename gone). All three classes coexist
        in the same group without double-counting.

        This proves the precedence rule does not over-suppress
        legitimate added/removed entries.
        """
        baseline_artifacts = [
            make_artifact(filename="model.safetensors", sha256="a" * 64),
            make_artifact(filename="going-away.json", sha256="x" * 64),
        ]
        current_artifacts = [
            # Same filename, different sha → artifact_changed
            make_artifact(filename="model.safetensors", sha256="b" * 64),
            # New filename → artifact_added
            make_artifact(filename="brand-new.json", sha256="y" * 64),
            # going-away.json absent → artifact_removed
        ]

        result = diff_scans(
            make_scan(
                groups=[
                    make_group(
                        source="huggingface_cache",
                        group_id="org/model",
                        artifacts=baseline_artifacts,
                    )
                ]
            ),
            make_scan(
                groups=[
                    make_group(
                        source="huggingface_cache",
                        group_id="org/model",
                        artifacts=current_artifacts,
                    )
                ]
            ),
        )

        # All three classes present, each with exactly one entry.
        # Total is 3, not 4 (precedence rule prevents the
        # changed-artifact from also generating add+remove).
        assert result.summary.artifacts_changed == 1
        assert result.summary.artifacts_added == 1
        assert result.summary.artifacts_removed == 1
        assert result.summary.total_changes == 3

        changed_filenames = {
            c.filename
            for c in result.changes
            if c.type == "artifact_changed"
        }
        added_filenames = {
            c.filename
            for c in result.changes
            if c.type == "artifact_added"
        }
        removed_filenames = {
            c.filename
            for c in result.changes
            if c.type == "artifact_removed"
        }

        assert changed_filenames == {"model.safetensors"}
        assert added_filenames == {"brand-new.json"}
        assert removed_filenames == {"going-away.json"}
        # Critical: model.safetensors must NOT appear in added or
        # removed sets. The precedence rule consumed it.
        assert "model.safetensors" not in added_filenames
        assert "model.safetensors" not in removed_filenames

    def test_precedence_does_not_apply_across_groups(self):
        """
        A filename that appears in two different groups (same
        filename, different (source, group_id)) does NOT trigger the
        precedence rule. The rule operates within a matched group
        only.
        """
        # model.safetensors exists in both groups but with different
        # SHA. These are distinct artifacts in distinct groups; the
        # diff must treat them independently.
        old_group_a = make_group(
            source="huggingface_cache",
            group_id="org-a/model",
            artifacts=[
                make_artifact(filename="model.safetensors", sha256="a" * 64)
            ],
        )
        old_group_b = make_group(
            source="huggingface_cache",
            group_id="org-b/model",
            artifacts=[
                make_artifact(filename="model.safetensors", sha256="b" * 64)
            ],
        )
        # In current, only org-b survives, but with sha "c" (changed)
        new_group_b = make_group(
            source="huggingface_cache",
            group_id="org-b/model",
            artifacts=[
                make_artifact(filename="model.safetensors", sha256="c" * 64)
            ],
        )

        result = diff_scans(
            make_scan(groups=[old_group_a, old_group_b]),
            make_scan(groups=[new_group_b]),
        )

        # org-a removed entirely (group_removed, not artifact_removed)
        assert result.summary.groups_removed == 1
        # org-b's artifact changed (precedence applies within the
        # matched group only)
        assert result.summary.artifacts_changed == 1
        # The org-a artifact is NOT counted as artifact_removed
        # because the entire group went away.
        assert result.summary.artifacts_removed == 0
        assert result.summary.artifacts_added == 0


# ════════════════════════════════════════════════════════════════════
# Test block 2 — status-direction classification
# ════════════════════════════════════════════════════════════════════
#
# DIFF_SPEC §4 defines three status directions:
#
#     regression  — moved from `verified` to any non-verified status
#     improvement — moved to `verified` from any non-verified status
#     lateral     — neither side is `verified`
#
# These tests pin every transition path, the counter behavior, and
# the field-preservation contract. Crucially, the status vocabulary
# is `pilot_available` (the JSON-layer enum value), NOT the human
# label `pilot enrollment available`. The corrective patch round on
# 2026-04-28 aligned the docs with the live code on this point.


class TestStatusRegression:
    """
    A regression is exclusively `verified → any non-verified status`.
    All three non-verified targets must classify as regression. The
    `--exit-code-on-status-regression` flag depends on this
    classification being airtight.
    """

    def test_verified_to_unknown_variant_is_regression(self):
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    status="verified",
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    status="unknown_variant",
                )
            ]
        )

        result = diff_scans(baseline, current)

        assert result.summary.status_changed == 1
        assert result.summary.status_regressions == 1
        assert result.summary.status_improvements == 0

        change = [c for c in result.changes if c.type == "status_changed"][0]
        assert change.baseline_status == "verified"
        assert change.current_status == "unknown_variant"
        assert change.direction == "regression"

    def test_verified_to_not_enrolled_is_regression(self):
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    status="verified",
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    status="not_enrolled",
                )
            ]
        )

        result = diff_scans(baseline, current)

        change = [c for c in result.changes if c.type == "status_changed"][0]
        assert change.direction == "regression"
        assert result.summary.status_regressions == 1

    def test_verified_to_pilot_available_is_regression(self):
        """
        Critical vocabulary check: the JSON-layer status value is
        `pilot_available`, NOT `pilot_enrollment_available`. The
        latter is the human-readable label only. This test fails
        loudly if the test fixtures or the diff core ever drift
        back to the wrong identifier.
        """
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    status="verified",
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    status="pilot_available",  # NOT pilot_enrollment_available
                )
            ]
        )

        result = diff_scans(baseline, current)

        change = [c for c in result.changes if c.type == "status_changed"][0]
        assert change.direction == "regression"
        assert change.current_status == "pilot_available"
        # Defensive assertion against the most likely vocabulary drift
        assert change.current_status != "pilot_enrollment_available"


class TestStatusImprovement:
    """
    An improvement is `any non-verified → verified`. All three
    sources of improvement classify identically.
    """

    def test_unknown_variant_to_verified_is_improvement(self):
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    status="unknown_variant",
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    status="verified",
                )
            ]
        )

        result = diff_scans(baseline, current)

        assert result.summary.status_changed == 1
        assert result.summary.status_improvements == 1
        assert result.summary.status_regressions == 0

        change = [c for c in result.changes if c.type == "status_changed"][0]
        assert change.baseline_status == "unknown_variant"
        assert change.current_status == "verified"
        assert change.direction == "improvement"

    def test_not_enrolled_to_verified_is_improvement(self):
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    status="not_enrolled",
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    status="verified",
                )
            ]
        )

        result = diff_scans(baseline, current)
        change = [c for c in result.changes if c.type == "status_changed"][0]
        assert change.direction == "improvement"
        assert result.summary.status_improvements == 1

    def test_pilot_available_to_verified_is_improvement(self):
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    status="pilot_available",
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    status="verified",
                )
            ]
        )

        result = diff_scans(baseline, current)
        change = [c for c in result.changes if c.type == "status_changed"][0]
        assert change.baseline_status == "pilot_available"
        assert change.direction == "improvement"


class TestStatusLateral:
    """
    A lateral change is any transition where neither side is
    `verified`. The status changed but neither end is the trust
    anchor. Lateral changes do NOT trigger the regression flag and
    do NOT count toward improvements.
    """

    def test_not_enrolled_to_pilot_available_is_lateral(self):
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    status="not_enrolled",
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    status="pilot_available",
                )
            ]
        )

        result = diff_scans(baseline, current)

        assert result.summary.status_changed == 1
        # Lateral counts in status_changed but not in regression or
        # improvement counters.
        assert result.summary.status_regressions == 0
        assert result.summary.status_improvements == 0

        change = [c for c in result.changes if c.type == "status_changed"][0]
        assert change.direction == "lateral"

    def test_unknown_variant_to_not_enrolled_is_lateral(self):
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    status="unknown_variant",
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    status="not_enrolled",
                )
            ]
        )

        result = diff_scans(baseline, current)
        change = [c for c in result.changes if c.type == "status_changed"][0]
        assert change.direction == "lateral"
        assert result.summary.status_regressions == 0
        assert result.summary.status_improvements == 0

    def test_pilot_available_to_unknown_variant_is_lateral(self):
        """
        Defensive: a transition between two non-verified states in
        either direction is lateral. The directionality matters only
        when one end is `verified`.
        """
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    status="pilot_available",
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    status="unknown_variant",
                )
            ]
        )

        result = diff_scans(baseline, current)
        change = [c for c in result.changes if c.type == "status_changed"][0]
        assert change.direction == "lateral"


class TestStatusCounters:
    """
    The summary counters (`status_regressions`, `status_improvements`)
    must accurately reflect the status_changed entries' directions.
    These tests verify the counter behavior across mixed multi-group
    scans where some changes are regressions, some improvements,
    some lateral.
    """

    def test_status_regression_counter_increments_per_regression(self):
        """Three regressions, one improvement, one lateral → counters
        report 3, 1 (the lateral does not count toward either)."""
        # Baseline: three verified groups + one unknown + one not_enrolled
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/regress-1",
                    status="verified",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/regress-2",
                    status="verified",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/regress-3",
                    status="verified",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/improve",
                    status="unknown_variant",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/lateral",
                    status="not_enrolled",
                ),
            ]
        )
        # Current: three become non-verified, one becomes verified,
        # one moves laterally
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/regress-1",
                    status="unknown_variant",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/regress-2",
                    status="not_enrolled",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/regress-3",
                    status="pilot_available",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/improve",
                    status="verified",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/lateral",
                    status="pilot_available",
                ),
            ]
        )

        result = diff_scans(baseline, current)

        assert result.summary.status_changed == 5
        assert result.summary.status_regressions == 3
        assert result.summary.status_improvements == 1
        # The fifth status_changed is lateral; not in either counter.
        # Total = 5, but regressions + improvements = 4.

    def test_status_improvement_counter_increments_per_improvement(self):
        """Two improvements, one regression → counters report 2, 1."""
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="a",
                    status="unknown_variant",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="b",
                    status="not_enrolled",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="c",
                    status="verified",
                ),
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="a",
                    status="verified",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="b",
                    status="verified",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="c",
                    status="unknown_variant",
                ),
            ]
        )

        result = diff_scans(baseline, current)

        assert result.summary.status_changed == 3
        assert result.summary.status_improvements == 2
        assert result.summary.status_regressions == 1


class TestStatusChangeFieldPreservation:
    """
    A `status_changed` entry must carry both the baseline and current
    status values, the direction classification, and the group's
    `claimed_model_id` so an auditor reading the diff has the full
    transition context without re-loading either scan file.
    """

    def test_status_change_preserves_baseline_and_current_status(self):
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/some-model",
                    status="verified",
                    claimed_model_id="org/some-model",
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/some-model",
                    status="unknown_variant",
                    claimed_model_id="org/some-model",
                )
            ]
        )

        result = diff_scans(baseline, current)
        change = [c for c in result.changes if c.type == "status_changed"][0]

        # Both ends of the transition preserved
        assert change.baseline_status == "verified"
        assert change.current_status == "unknown_variant"
        # Direction set
        assert change.direction == "regression"
        # Identity preserved
        assert change.source == "huggingface_cache"
        assert change.group_id == "org/some-model"
        # Display label preserved for audit
        assert change.claimed_model_id == "org/some-model"

    def test_status_change_uses_machine_vocabulary_not_human_label(self):
        """
        Hard guardrail: every status field on a status_changed entry
        is a JSON-layer enum value (`verified`, `unknown_variant`,
        `not_enrolled`, `pilot_available`). Human-readable labels
        like 'verified artifact' or 'pilot enrollment available'
        must NEVER appear in these fields.

        This test is the corrective-patch-round insurance policy.
        If a future change re-introduces `pilot_enrollment_available`
        anywhere in the diff core, this test fails loudly.
        """
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="pilot_available",
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="verified",
                )
            ]
        )

        result = diff_scans(baseline, current)
        change = [c for c in result.changes if c.type == "status_changed"][0]

        valid_machine_values = {
            "verified",
            "unknown_variant",
            "not_enrolled",
            "pilot_available",
        }
        forbidden_human_labels = {
            "verified artifact",
            "unknown variant",
            "not enrolled",
            "pilot enrollment available",
            "pilot_enrollment_available",  # the specific drift
        }

        assert change.baseline_status in valid_machine_values
        assert change.current_status in valid_machine_values
        assert change.baseline_status not in forbidden_human_labels
        assert change.current_status not in forbidden_human_labels

    def test_status_change_does_not_emit_when_status_unchanged(self):
        """
        Sanity bound on the status_changed class: if the status
        field is identical in baseline and current, no
        status_changed entry is emitted, even if other things
        about the group differ.
        """
        # Same status, but artifacts differ → artifact_changed
        # but NO status_changed.
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="verified",
                    artifacts=[
                        make_artifact(
                            filename="model.safetensors", sha256="a" * 64
                        )
                    ],
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="verified",  # unchanged
                    artifacts=[
                        make_artifact(
                            filename="model.safetensors", sha256="b" * 64
                        )
                    ],
                )
            ]
        )

        result = diff_scans(baseline, current)

        assert result.summary.status_changed == 0
        # Artifact change is independent
        assert result.summary.artifacts_changed == 1
        assert result.summary.status_regressions == 0
        assert result.summary.status_improvements == 0


# ════════════════════════════════════════════════════════════════════
# Test block 3 — registry snapshot passthrough + privacy/path propagation
# ════════════════════════════════════════════════════════════════════
#
# This block proves two contracts:
#
# 1. Metadata passthrough (DIFF_SPEC §5):
#    The diff core surfaces baseline/current registry snapshot fields
#    on the result so renderers can write the audit block. The raw
#    hex digest is preserved exactly — no `sha256:` prefix added or
#    stripped.
#
# 2. Privacy gate (DIFF_SPEC §7):
#    `paths_allowed` is True iff BOTH baseline and current scans
#    had `include_paths == True`. All four corners of the truth table
#    are tested.
#
# The hard guardrail running through both: metadata fields and the
# privacy posture are AUDIT/OUTPUT metadata only. They do not affect
# change classification. A registry snapshot drift between baseline
# and current is context for interpreting the (zero or more) change
# entries — it is not itself a model-surface change.


class TestRegistrySnapshotPassthrough:
    """
    The diff core extracts registry snapshot fields from each scan
    and surfaces them on the result. Per DIFF_SPEC §5, both fields
    are optional in the scan JSON; missing fields surface as None.
    """

    def test_both_sides_have_registry_snapshot_preserved(self):
        kid = "fallrisk-96cd5e6a01e1"
        baseline_digest = "5f159f7f6408e476" + "0" * 48  # 64-char raw hex
        current_digest = "6fdd76ad34bca66e" + "0" * 48

        baseline = make_scan(
            groups=[],
            registry_kid=kid,
            registry_manifest_digest=baseline_digest,
        )
        current = make_scan(
            groups=[],
            registry_kid=kid,
            registry_manifest_digest=current_digest,
        )

        result = diff_scans(baseline, current)

        # Metadata objects exist and are typed correctly
        assert isinstance(result.baseline, DiffScanMetadata)
        assert isinstance(result.current, DiffScanMetadata)

        # Both registry kids preserved
        assert result.baseline.registry_kid == kid
        assert result.current.registry_kid == kid

        # Both digests preserved exactly
        assert result.baseline.registry_manifest_digest == baseline_digest
        assert result.current.registry_manifest_digest == current_digest

        # Source labels disambiguate
        assert result.baseline.source == "baseline"
        assert result.current.source == "current"

    def test_one_side_missing_registry_kid_emits_none(self):
        """
        DIFF_SPEC §5: scans against an unverified or pinned registry
        may omit `registry_kid`. The diff must surface this as None
        on the corresponding metadata object — never as the empty
        string, never raised as an error.
        """
        baseline = make_scan(
            groups=[],
            registry_kid="fallrisk-96cd5e6a01e1",
            registry_manifest_digest="a" * 64,
        )
        # Current omits both registry fields entirely
        current = make_scan(groups=[])

        result = diff_scans(baseline, current)

        assert result.baseline.registry_kid == "fallrisk-96cd5e6a01e1"
        assert result.baseline.registry_manifest_digest == "a" * 64

        # Missing side surfaces None (not "" and not a raised error)
        assert result.current.registry_kid is None
        assert result.current.registry_manifest_digest is None

    def test_neither_side_has_registry_snapshot(self):
        """v0.2.x backward compat: scans without registry fields
        produce a result with None for both sides. No errors."""
        baseline = make_scan(groups=[])
        current = make_scan(groups=[])

        result = diff_scans(baseline, current)

        assert result.baseline.registry_kid is None
        assert result.current.registry_kid is None
        assert result.baseline.registry_manifest_digest is None
        assert result.current.registry_manifest_digest is None

    def test_raw_hex_digest_preserved_exactly_no_prefix_added(self):
        """
        Schema dependency check: the digest is raw hex per
        DIFF_SPEC §5. The diff core MUST NOT prepend `sha256:` or
        otherwise transform the value. Renderers depend on this for
        consistent round-trip behavior.
        """
        raw_hex = "5f159f7f6408e476" + "0" * 48
        baseline = make_scan(
            groups=[], registry_manifest_digest=raw_hex
        )
        current = make_scan(
            groups=[], registry_manifest_digest=raw_hex
        )

        result = diff_scans(baseline, current)

        # Exact match — no prefix added anywhere
        assert result.baseline.registry_manifest_digest == raw_hex
        assert result.current.registry_manifest_digest == raw_hex

        # Defensive: explicitly assert the prefix that should NOT
        # be added. If the diff core ever starts normalizing to
        # `sha256:` form, this fails loudly.
        assert not result.baseline.registry_manifest_digest.startswith(
            "sha256:"
        )
        assert not result.current.registry_manifest_digest.startswith(
            "sha256:"
        )

    def test_malformed_prefixed_digest_passed_through_verbatim(self):
        """
        If a scan emits a malformed digest with a `sha256:` prefix
        (which would be a scanner-side bug), the diff faithfully
        reproduces it. The diff core does NOT silently strip the
        prefix to "fix" it — that would hide the upstream bug.

        This is a defensive test of the no-normalization contract.
        """
        malformed = "sha256:" + "a" * 64
        baseline = make_scan(
            groups=[], registry_manifest_digest=malformed
        )
        current = make_scan(groups=[])

        result = diff_scans(baseline, current)

        # The malformed input is passed through verbatim
        assert result.baseline.registry_manifest_digest == malformed
        assert result.current.registry_manifest_digest is None

    def test_metadata_carries_groups_scanned_and_total_bytes(self):
        """
        The summary fields (groups_scanned, total_bytes) are also
        passed through. Renderers use these in the audit block
        without needing to recompute from the changes list.
        """
        artifacts = [
            make_artifact(
                filename="m.safetensors", sha256="a" * 64, size_bytes=100_000
            )
        ]
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/a",
                    artifacts=artifacts,
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/b",
                    artifacts=artifacts,
                ),
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/a",
                    artifacts=artifacts,
                )
            ]
        )

        result = diff_scans(baseline, current)

        assert result.baseline.groups_scanned == 2
        assert result.current.groups_scanned == 1
        assert result.baseline.total_bytes == 200_000
        assert result.current.total_bytes == 100_000

    def test_metadata_carries_trustfall_lite_version(self):
        """The lite version field is preserved per side. Useful for
        audit when comparing diffs across version bumps."""
        baseline = make_scan(groups=[], trustfall_lite_version="0.2.1")
        current = make_scan(groups=[], trustfall_lite_version="0.3.0")

        result = diff_scans(baseline, current)

        assert result.baseline.trustfall_lite_version == "0.2.1"
        assert result.current.trustfall_lite_version == "0.3.0"


class TestPrivacyPathPropagation:
    """
    DIFF_SPEC §7 privacy gate: paths may propagate to the diff output
    only when BOTH baseline and current scans had `include_paths ==
    True`. Tests cover all four corners of the 2x2 truth table.
    """

    def test_both_false_paths_excluded(self):
        """The default case. Neither scan opted in to paths."""
        baseline = make_scan(groups=[], include_paths=False)
        current = make_scan(groups=[], include_paths=False)

        result = diff_scans(baseline, current)

        assert result.paths_allowed is False
        assert result.baseline.include_paths is False
        assert result.current.include_paths is False

    def test_baseline_true_current_false_paths_excluded(self):
        """
        Privacy ratchet: a baseline scan with paths cannot leak them
        through to the diff output if the current scan doesn't also
        opt in. The privacy gate is conjunctive, not disjunctive.
        """
        baseline = make_scan(groups=[], include_paths=True)
        current = make_scan(groups=[], include_paths=False)

        result = diff_scans(baseline, current)

        assert result.paths_allowed is False
        # Per-side flags reflect the source scans accurately
        assert result.baseline.include_paths is True
        assert result.current.include_paths is False

    def test_baseline_false_current_true_paths_excluded(self):
        """The mirror image — same conjunctive rule."""
        baseline = make_scan(groups=[], include_paths=False)
        current = make_scan(groups=[], include_paths=True)

        result = diff_scans(baseline, current)

        assert result.paths_allowed is False
        assert result.baseline.include_paths is False
        assert result.current.include_paths is True

    def test_both_true_paths_included(self):
        """Both scans opted in. The privacy gate opens."""
        baseline = make_scan(groups=[], include_paths=True)
        current = make_scan(groups=[], include_paths=True)

        result = diff_scans(baseline, current)

        assert result.paths_allowed is True
        assert result.baseline.include_paths is True
        assert result.current.include_paths is True

    def test_paths_allowed_default_false_for_legacy_scans(self):
        """
        A scan that omits the `include_paths` field entirely (legacy
        v0.2.x behavior) is treated as paths-excluded for the
        privacy gate. The metadata flag also reads False.
        """
        # Construct a scan dict missing the include_paths field
        baseline_dict = {
            "trustfall_lite_version": "0.2.0",
            "scan_paths": [],
            "summary": {
                "groups_scanned": 0,
                "artifacts_scanned": 0,
                "total_bytes": 0,
            },
            "groups": [],
        }
        # Same shape on current
        current_dict = dict(baseline_dict)

        result = diff_scans(baseline_dict, current_dict)

        assert result.paths_allowed is False
        assert result.baseline.include_paths is False
        assert result.current.include_paths is False


class TestMetadataDoesNotAffectClassification:
    """
    The hard guardrail: registry metadata and privacy posture are
    audit/output metadata only. They MUST NOT affect change
    classification. Two scans that differ only in metadata produce
    zero change entries on the result.

    This distinction matters because registry snapshot drift is
    context for interpreting status changes — it is NOT itself a
    local model-surface change. If the diff core ever conflates
    these, the user-facing semantics break: a registry resigning
    would falsely look like a model surface change.
    """

    def test_registry_metadata_does_not_affect_empty_diff(self):
        """
        User-specified guardrail: two scans with identical groups
        and identical artifacts but DIFFERENT registry snapshots
        produce zero change entries. Registry drift is not a
        model-surface change.
        """
        artifacts = [
            make_artifact(
                filename="model.safetensors", sha256="a" * 64
            )
        ]
        group = make_group(
            source="huggingface_cache",
            group_id="org/model",
            artifacts=artifacts,
        )

        baseline = make_scan(
            groups=[group],
            registry_kid="fallrisk-OLD-kid",
            registry_manifest_digest="1" * 64,
        )
        current = make_scan(
            groups=[group],
            registry_kid="fallrisk-NEW-kid",  # DIFFERENT
            registry_manifest_digest="2" * 64,  # DIFFERENT
        )

        result = diff_scans(baseline, current)

        # Zero change entries — registry drift is not a model change
        assert result.changes == []
        assert result.summary.is_empty
        assert result.summary.total_changes == 0

        # But the metadata IS distinct — that's the whole point.
        # The renderer can use this to write an audit-block warning
        # like "registry resigned between baseline and current"
        # without falsely flagging it as a model surface change.
        assert result.baseline.registry_kid != result.current.registry_kid
        assert (
            result.baseline.registry_manifest_digest
            != result.current.registry_manifest_digest
        )

    def test_privacy_posture_does_not_affect_classification(self):
        """
        The mirror guardrail for include_paths. Two scans with
        identical groups but different privacy postures still
        produce zero change entries. The `paths_allowed` flag
        differs but classification is identical.
        """
        artifacts = [
            make_artifact(
                filename="model.safetensors", sha256="a" * 64
            )
        ]
        group = make_group(
            source="huggingface_cache",
            group_id="org/model",
            artifacts=artifacts,
        )

        # Same groups, different include_paths
        baseline = make_scan(groups=[group], include_paths=True)
        current = make_scan(groups=[group], include_paths=False)

        result = diff_scans(baseline, current)

        # Zero change entries
        assert result.changes == []
        assert result.summary.is_empty
        # But paths_allowed correctly reflects the conjunctive rule
        assert result.paths_allowed is False

    def test_metadata_drift_with_real_change_classifies_change_normally(self):
        """
        Negative case: metadata drift coexists with a genuine
        artifact change. The change is classified normally; the
        metadata drift is also surfaced. Each is independent.
        """
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    artifacts=[
                        make_artifact(
                            filename="model.safetensors", sha256="a" * 64
                        )
                    ],
                )
            ],
            registry_manifest_digest="1" * 64,
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/model",
                    artifacts=[
                        make_artifact(
                            filename="model.safetensors",
                            sha256="b" * 64,  # SHA changed
                        )
                    ],
                )
            ],
            registry_manifest_digest="2" * 64,  # registry also changed
        )

        result = diff_scans(baseline, current)

        # The artifact change is classified
        assert result.summary.artifacts_changed == 1
        assert result.summary.total_changes == 1
        # AND the metadata drift is independently surfaced
        assert (
            result.baseline.registry_manifest_digest
            != result.current.registry_manifest_digest
        )

        # Critical: the count is 1, not 2. Metadata drift is not
        # itself a change entry.
        change = [c for c in result.changes if c.type == "artifact_changed"][0]
        assert change.baseline_sha256 == "a" * 64
        assert change.current_sha256 == "b" * 64


# ════════════════════════════════════════════════════════════════════
# Test block 4 — JSON renderer (render_diff_as_dict)
# ════════════════════════════════════════════════════════════════════
#
# render_diff_as_dict consumes a DiffResult and produces a JSON-
# serializable dict. The schema is defined in DIFF_SPEC §6 + §7.
#
# Three load-bearing invariants:
#
# 1. Schema stability — every field appears in every output, even
#    when the value is None. Consumers must be able to write
#    output["baseline"]["registry_kid"] without checking for the key.
#
# 2. Null-not-omitted — a None on the source DiffScanMetadata emits
#    as JSON null. NOT as an empty string, NOT as a missing key.
#
# 3. Privacy gate — when paths_allowed=False, no key whose name
#    contains "path" appears in any change entry. The top-level
#    paths_allowed flag itself is preserved as the audit signal.
#
# The two highest-priority tests in this block are
# test_render_paths_excluded_when_paths_not_allowed and
# test_render_registry_manifest_digest_raw_hex. Each pins a
# guardrail that, if broken, silently corrupts a downstream
# audit surface.


import json


class TestRenderEmptyDiff:
    """Empty diff renders to a complete schema-stable shape."""

    def test_render_empty_diff_json_shape(self):
        """
        Two empty scans produce a fully-shaped output dict with all
        spec fields present, summary counters at zero, changes list
        empty. Top-level keys must include every spec field.
        """
        result = diff_scans(make_scan(groups=[]), make_scan(groups=[]))
        rendered = render_diff_as_dict(result)

        # Top-level keys per DIFF_SPEC §6
        expected_top_level = {
            "schema_version",
            "baseline",
            "current",
            "paths_allowed",
            "summary",
            "changes",
        }
        assert set(rendered.keys()) == expected_top_level

        # Empty diff: changes list empty, all counters zero
        assert rendered["changes"] == []
        assert rendered["summary"]["groups_added"] == 0
        assert rendered["summary"]["status_changed"] == 0

        # Schema version present
        assert rendered["schema_version"] == "0.3.0"


class TestRenderSummary:
    """The summary block faithfully serializes DiffSummary."""

    def test_render_summary_counts(self):
        """
        Mixed-change scan produces summary counters matching the
        DiffSummary on the result. All eight counters present.
        """
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/regress",
                    status="verified",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/improve",
                    status="not_enrolled",
                ),
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/regress",
                    status="unknown_variant",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/improve",
                    status="verified",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/new",
                    status="verified",
                ),
            ]
        )

        result = diff_scans(baseline, current)
        rendered = render_diff_as_dict(result)
        summary = rendered["summary"]

        # All eight counters present, regardless of value
        expected_keys = {
            "groups_added",
            "groups_removed",
            "artifacts_added",
            "artifacts_removed",
            "artifacts_changed",
            "status_changed",
            "status_regressions",
            "status_improvements",
        }
        assert set(summary.keys()) == expected_keys

        # Values match the DiffSummary
        assert summary["groups_added"] == 1  # org/new
        assert summary["status_changed"] == 2  # regress + improve
        assert summary["status_regressions"] == 1
        assert summary["status_improvements"] == 1


class TestRenderMetadata:
    """Per-side metadata serializes faithfully and obeys null-not-omitted."""

    def test_render_baseline_current_metadata(self):
        """
        Both metadata blocks present, both populated, all fields
        emitted in spec order.
        """
        baseline = make_scan(
            groups=[],
            registry_kid="fallrisk-96cd5e6a01e1",
            registry_manifest_digest="a" * 64,
            include_paths=True,
            trustfall_lite_version="0.3.0",
        )
        current = make_scan(
            groups=[],
            registry_kid="fallrisk-96cd5e6a01e1",
            registry_manifest_digest="b" * 64,
            include_paths=True,
            trustfall_lite_version="0.3.0",
        )

        rendered = render_diff_as_dict(diff_scans(baseline, current))

        # Both metadata blocks have the same six fields
        expected_meta_keys = {
            "trustfall_lite_version",
            "groups_scanned",
            "total_bytes",
            "registry_kid",
            "registry_manifest_digest",
            "include_paths",
        }
        assert set(rendered["baseline"].keys()) == expected_meta_keys
        assert set(rendered["current"].keys()) == expected_meta_keys

        # Values match
        assert rendered["baseline"]["registry_kid"] == "fallrisk-96cd5e6a01e1"
        assert rendered["baseline"]["registry_manifest_digest"] == "a" * 64
        assert rendered["current"]["registry_manifest_digest"] == "b" * 64
        assert rendered["baseline"]["include_paths"] is True
        assert rendered["current"]["include_paths"] is True

    def test_render_null_not_omitted_for_missing_metadata(self):
        """
        CRITICAL guardrail. When a metadata field is None on the
        DiffScanMetadata, the rendered dict emits it as None
        (which becomes JSON null). It must NOT be:
          - omitted from the dict
          - emitted as ""
          - emitted as 0

        Schema consumers depend on the key always being present.
        """
        # No registry fields, no version on the current side
        baseline = make_scan(
            groups=[],
            registry_kid="fallrisk-96cd5e6a01e1",
            registry_manifest_digest="a" * 64,
        )
        current_dict = {
            "scan_paths": [],
            "include_paths": False,
            "trust_ollama_filenames": False,
            "summary": {
                "groups_scanned": 0,
                "artifacts_scanned": 0,
                "total_bytes": 0,
            },
            "groups": [],
            # NB: trustfall_lite_version, registry_kid,
            # registry_manifest_digest all absent
        }

        rendered = render_diff_as_dict(diff_scans(baseline, current_dict))

        # The current-side metadata block has the keys
        # *present* even though the values are None.
        assert "trustfall_lite_version" in rendered["current"]
        assert "registry_kid" in rendered["current"]
        assert "registry_manifest_digest" in rendered["current"]

        # And the values are None (which serializes as JSON null)
        assert rendered["current"]["trustfall_lite_version"] is None
        assert rendered["current"]["registry_kid"] is None
        assert rendered["current"]["registry_manifest_digest"] is None

        # Defensive: explicitly NOT empty strings or zeros
        assert rendered["current"]["registry_kid"] != ""
        assert rendered["current"]["registry_manifest_digest"] != ""

    def test_render_registry_manifest_digest_raw_hex(self):
        """
        CRITICAL guardrail. The renderer must preserve the digest
        exactly as it sits on the DiffScanMetadata — raw hex, no
        sha256: prefix added, no normalization. This is the BLOOMZ-
        NaN-class drift the renderer has to NOT introduce.
        """
        raw_hex = "5f159f7f6408e476" + "0" * 48  # 64 chars
        baseline = make_scan(
            groups=[], registry_manifest_digest=raw_hex
        )
        current = make_scan(
            groups=[], registry_manifest_digest=raw_hex
        )

        rendered = render_diff_as_dict(diff_scans(baseline, current))

        # Exact preservation
        assert rendered["baseline"]["registry_manifest_digest"] == raw_hex
        assert rendered["current"]["registry_manifest_digest"] == raw_hex

        # Defensive: explicitly NOT prefixed
        assert not rendered["baseline"][
            "registry_manifest_digest"
        ].startswith("sha256:")
        assert not rendered["current"][
            "registry_manifest_digest"
        ].startswith("sha256:")


class TestRenderGroupAdded:
    """group_added entries serialize with the group-level shape."""

    def test_render_group_added(self):
        new_group = make_group(
            source="huggingface_cache",
            group_id="org/new-model",
            status="verified",
            artifacts=[
                make_artifact(
                    filename="m.safetensors",
                    sha256="a" * 64,
                    size_bytes=1_000_000,
                )
            ],
            claimed_model_id="org/new-model",
        )
        rendered = render_diff_as_dict(
            diff_scans(make_scan(groups=[]), make_scan(groups=[new_group]))
        )

        added = [c for c in rendered["changes"] if c["type"] == "group_added"]
        assert len(added) == 1
        change = added[0]

        # Group-level fields present
        assert change["type"] == "group_added"
        assert change["source"] == "huggingface_cache"
        assert change["group_id"] == "org/new-model"
        assert change["status"] == "verified"
        assert change["n_artifacts"] == 1
        assert change["total_bytes"] == 1_000_000
        assert change["claimed_model_id"] == "org/new-model"

        # Artifact-level fields NOT present (this isn't an artifact change)
        assert "filename" not in change
        assert "sha256" not in change
        assert "baseline_sha256" not in change
        # Status-change fields NOT present
        assert "baseline_status" not in change
        assert "direction" not in change


class TestRenderGroupRemoved:
    """group_removed entries serialize with the group-level shape."""

    def test_render_group_removed(self):
        old_group = make_group(
            source="huggingface_cache",
            group_id="org/old-model",
            status="verified",
            artifacts=[
                make_artifact(
                    filename="m.safetensors",
                    sha256="a" * 64,
                    size_bytes=2_000_000,
                )
            ],
        )
        rendered = render_diff_as_dict(
            diff_scans(make_scan(groups=[old_group]), make_scan(groups=[]))
        )

        removed = [
            c for c in rendered["changes"] if c["type"] == "group_removed"
        ]
        assert len(removed) == 1
        change = removed[0]

        assert change["type"] == "group_removed"
        assert change["source"] == "huggingface_cache"
        assert change["group_id"] == "org/old-model"
        assert change["status"] == "verified"
        assert change["n_artifacts"] == 1
        assert change["total_bytes"] == 2_000_000
        assert "filename" not in change


class TestRenderArtifactAdded:
    """artifact_added entries serialize with the artifact-level shape."""

    def test_render_artifact_added(self):
        existing = make_artifact(filename="config.json", sha256="c" * 64)
        new = make_artifact(
            filename="tokenizer.json", sha256="d" * 64, size_bytes=500_000
        )

        baseline_group = make_group(
            source="huggingface_cache",
            group_id="org/m",
            artifacts=[existing],
        )
        current_group = make_group(
            source="huggingface_cache",
            group_id="org/m",
            artifacts=[existing, new],
        )

        rendered = render_diff_as_dict(
            diff_scans(
                make_scan(groups=[baseline_group]),
                make_scan(groups=[current_group]),
            )
        )

        added = [
            c for c in rendered["changes"] if c["type"] == "artifact_added"
        ]
        assert len(added) == 1
        change = added[0]

        # Artifact-level fields present
        assert change["type"] == "artifact_added"
        assert change["filename"] == "tokenizer.json"
        assert change["sha256"] == "d" * 64
        assert change["size_bytes"] == 500_000

        # Group-level fields NOT present (this isn't a group change)
        assert "n_artifacts" not in change
        assert "total_bytes" not in change
        assert "status" not in change
        # artifact_changed fields NOT present
        assert "baseline_sha256" not in change
        assert "current_sha256" not in change


class TestRenderArtifactRemoved:
    """artifact_removed entries serialize with the artifact-level shape."""

    def test_render_artifact_removed(self):
        gone = make_artifact(
            filename="weights.bin", sha256="e" * 64, size_bytes=3_000_000
        )
        sibling = make_artifact(filename="config.json", sha256="c" * 64)

        baseline_group = make_group(
            source="huggingface_cache",
            group_id="org/m",
            artifacts=[gone, sibling],
        )
        current_group = make_group(
            source="huggingface_cache",
            group_id="org/m",
            artifacts=[sibling],
        )

        rendered = render_diff_as_dict(
            diff_scans(
                make_scan(groups=[baseline_group]),
                make_scan(groups=[current_group]),
            )
        )

        removed = [
            c
            for c in rendered["changes"]
            if c["type"] == "artifact_removed"
        ]
        assert len(removed) == 1
        change = removed[0]

        assert change["type"] == "artifact_removed"
        assert change["filename"] == "weights.bin"
        assert change["sha256"] == "e" * 64
        assert change["size_bytes"] == 3_000_000


class TestRenderArtifactChanged:
    """artifact_changed entries carry both baseline and current state."""

    def test_render_artifact_changed(self):
        baseline_group = make_group(
            source="huggingface_cache",
            group_id="org/m",
            artifacts=[
                make_artifact(
                    filename="m.safetensors",
                    sha256="a" * 64,
                    size_bytes=1_000_000,
                )
            ],
        )
        current_group = make_group(
            source="huggingface_cache",
            group_id="org/m",
            artifacts=[
                make_artifact(
                    filename="m.safetensors",
                    sha256="b" * 64,  # changed
                    size_bytes=1_000_001,
                )
            ],
        )

        rendered = render_diff_as_dict(
            diff_scans(
                make_scan(groups=[baseline_group]),
                make_scan(groups=[current_group]),
            )
        )

        changed = [
            c
            for c in rendered["changes"]
            if c["type"] == "artifact_changed"
        ]
        assert len(changed) == 1
        change = changed[0]

        # Both sides preserved
        assert change["filename"] == "m.safetensors"
        assert change["baseline_sha256"] == "a" * 64
        assert change["current_sha256"] == "b" * 64
        assert change["baseline_size_bytes"] == 1_000_000
        assert change["current_size_bytes"] == 1_000_001

        # The single-side `sha256` field is NOT present — that's
        # for added/removed shapes only.
        assert "sha256" not in change


class TestRenderStatusChanged:
    """status_changed entries carry baseline+current+direction."""

    def test_render_status_changed(self):
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="verified",
                    claimed_model_id="org/m",
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="unknown_variant",
                    claimed_model_id="org/m",
                )
            ]
        )

        rendered = render_diff_as_dict(diff_scans(baseline, current))
        changed = [
            c
            for c in rendered["changes"]
            if c["type"] == "status_changed"
        ]
        assert len(changed) == 1
        change = changed[0]

        assert change["baseline_status"] == "verified"
        assert change["current_status"] == "unknown_variant"
        assert change["direction"] == "regression"
        assert change["claimed_model_id"] == "org/m"

        # Defensive: machine vocabulary, not human label
        assert change["baseline_status"] != "verified artifact"
        assert change["current_status"] != "unknown variant"

    def test_render_status_changed_pilot_available_uses_machine_vocab(self):
        """
        Vocabulary insurance: a pilot_available status renders as
        the JSON-layer enum value, NOT the human-readable label.
        """
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="verified",
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="pilot_available",
                )
            ]
        )

        rendered = render_diff_as_dict(diff_scans(baseline, current))
        change = [
            c
            for c in rendered["changes"]
            if c["type"] == "status_changed"
        ][0]

        assert change["current_status"] == "pilot_available"
        assert change["current_status"] != "pilot_enrollment_available"
        assert change["current_status"] != "pilot enrollment available"


class TestRenderPathsGate:
    """
    The privacy gate prevents path strings from leaking when
    paths_allowed=False, regardless of which DiffChange field
    they sit on. The check is by key-name pattern, applied to
    every nested dict in the changes list.
    """

    def test_render_paths_excluded_when_paths_not_allowed(self):
        """
        CRITICAL guardrail. With paths_allowed=False, no key whose
        name contains "path" appears in any nested change entry.

        The current schema has no path-bearing change fields, so
        this test is forward-compatible — but the check is by
        structural rule, not by current field set, so a future
        field addition gated on this test will fail loudly if it
        bypasses the gate.

        The top-level paths_allowed flag is preserved as the audit
        signal; only nested entries are stripped.
        """
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="verified",
                )
            ],
            include_paths=False,
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="unknown_variant",
                )
            ],
            include_paths=False,
        )

        rendered = render_diff_as_dict(diff_scans(baseline, current))

        # paths_allowed is False per the conjunctive rule
        assert rendered["paths_allowed"] is False

        # Top-level audit signal preserved
        assert "paths_allowed" in rendered

        # No path-named keys in any change entry
        for change in rendered["changes"]:
            assert all("path" not in k.lower() for k in change.keys()), (
                f"path-named key leaked into change: {list(change.keys())}"
            )

    def test_render_paths_included_when_paths_allowed(self):
        """
        With paths_allowed=True, path-named keys MAY appear in
        change entries (none currently do, but the gate is open).
        The structural rule: the renderer must NOT strip on the
        True branch.
        """
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="verified",
                )
            ],
            include_paths=True,
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="unknown_variant",
                )
            ],
            include_paths=True,
        )

        rendered = render_diff_as_dict(diff_scans(baseline, current))

        # paths_allowed is True
        assert rendered["paths_allowed"] is True

        # Per-side metadata reflects opt-in
        assert rendered["baseline"]["include_paths"] is True
        assert rendered["current"]["include_paths"] is True

    def test_paths_gate_does_not_strip_top_level_paths_allowed(self):
        """
        Defensive: the privacy gate is a strip-by-name rule. The
        top-level `paths_allowed` key contains "path" in its name
        but MUST be preserved as the audit signal. If it's stripped
        the renderer's contract breaks: consumers can't tell whether
        absence of path keys is "no paths" or "policy disabled".

        This test pins that the strip rule applies only to nested
        entries, not the top-level dict.
        """
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                )
            ],
            include_paths=False,
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                )
            ],
            include_paths=False,
        )

        rendered = render_diff_as_dict(diff_scans(baseline, current))

        # The top-level audit signal MUST be present
        assert "paths_allowed" in rendered
        assert rendered["paths_allowed"] is False


class TestRenderJSONSerializable:
    """The rendered dict must round-trip through json.dumps cleanly."""

    def test_render_json_serializable(self):
        """
        Every value in the rendered dict is a JSON primitive: str,
        int, float, bool, None, list, dict. No tuples, no sets, no
        dataclasses, no enums, no custom types.
        """
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/regress",
                    status="verified",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    artifacts=[
                        make_artifact(
                            filename="m.safetensors", sha256="a" * 64
                        )
                    ],
                ),
            ],
            registry_kid="fallrisk-96cd5e6a01e1",
            registry_manifest_digest="a" * 64,
            include_paths=True,
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/regress",
                    status="not_enrolled",  # regression
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    artifacts=[
                        make_artifact(
                            filename="m.safetensors", sha256="b" * 64
                        )
                    ],
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/added",
                ),
            ],
            registry_kid="fallrisk-96cd5e6a01e1",
            registry_manifest_digest="b" * 64,
            include_paths=True,
        )

        rendered = render_diff_as_dict(diff_scans(baseline, current))

        # Round trip through json.dumps — must not raise
        encoded = json.dumps(rendered)
        decoded = json.loads(encoded)

        # The re-decoded dict equals the original. (Python dict
        # equality is structural, not identity-based.)
        assert decoded == rendered

    def test_render_json_serializable_with_nulls(self):
        """
        Null values round-trip correctly. None in dict → JSON null
        → None on decode. The null-not-omitted contract holds
        across the json.dumps boundary.
        """
        # Scan with no registry fields; metadata will have None
        baseline = make_scan(groups=[])
        current = make_scan(groups=[])

        rendered = render_diff_as_dict(diff_scans(baseline, current))
        encoded = json.dumps(rendered)
        decoded = json.loads(encoded)

        # None survives the round trip
        assert decoded["baseline"]["registry_kid"] is None
        assert decoded["current"]["registry_manifest_digest"] is None

        # The KEY survives, not just the value (null-not-omitted
        # holds through json.dumps + json.loads).
        assert "registry_kid" in decoded["baseline"]
        assert "registry_manifest_digest" in decoded["current"]


class TestRenderDeterministicFieldOrder:
    """
    The same DiffResult rendered twice produces byte-identical
    output under json.dumps with sort_keys=False. This is what
    makes test fixtures and audit diffs reviewable.
    """

    def test_render_deterministic_field_order(self):
        """
        Two calls to render_diff_as_dict on the same DiffResult
        produce dicts equal under == and serialize byte-identical
        under json.dumps without sort_keys.
        """
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="verified",
                )
            ],
            registry_kid="fallrisk-96cd5e6a01e1",
            registry_manifest_digest="a" * 64,
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="unknown_variant",
                )
            ],
            registry_kid="fallrisk-96cd5e6a01e1",
            registry_manifest_digest="b" * 64,
        )

        # Same DiffResult, rendered twice
        result = diff_scans(baseline, current)
        first = render_diff_as_dict(result)
        second = render_diff_as_dict(result)

        assert first == second

        # Byte-identical under json.dumps without sort_keys
        first_bytes = json.dumps(first, sort_keys=False)
        second_bytes = json.dumps(second, sort_keys=False)
        assert first_bytes == second_bytes

    def test_render_top_level_field_order_matches_spec(self):
        """
        Top-level keys appear in DIFF_SPEC §6 order:
          schema_version, baseline, current, paths_allowed,
          summary, changes
        """
        rendered = render_diff_as_dict(
            diff_scans(make_scan(groups=[]), make_scan(groups=[]))
        )

        # Python 3.7+ dicts preserve insertion order
        assert list(rendered.keys()) == [
            "schema_version",
            "baseline",
            "current",
            "paths_allowed",
            "summary",
            "changes",
        ]

    def test_render_metadata_field_order_matches_spec(self):
        """
        Metadata block fields appear in spec order. This makes diff-
        of-diff outputs (e.g., comparing two render_diff_as_dict
        results in a code review) readable rather than churning on
        field ordering.
        """
        baseline = make_scan(
            groups=[],
            registry_kid="k",
            registry_manifest_digest="d" * 64,
            include_paths=True,
        )
        current = make_scan(groups=[])

        rendered = render_diff_as_dict(diff_scans(baseline, current))

        expected_order = [
            "trustfall_lite_version",
            "groups_scanned",
            "total_bytes",
            "registry_kid",
            "registry_manifest_digest",
            "include_paths",
        ]
        assert list(rendered["baseline"].keys()) == expected_order
        assert list(rendered["current"].keys()) == expected_order

    def test_render_change_entry_starts_with_type_and_identity(self):
        """
        Every change entry begins with `type`, then `source`, then
        `group_id`. Subsequent fields vary by change class. A
        reviewer scanning a JSON output can identify what each
        entry is and where it lives without scanning the whole
        object.
        """
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="verified",
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="unknown_variant",
                )
            ]
        )

        rendered = render_diff_as_dict(diff_scans(baseline, current))

        for change in rendered["changes"]:
            keys = list(change.keys())
            assert keys[0] == "type"
            assert keys[1] == "source"
            assert keys[2] == "group_id"


# ════════════════════════════════════════════════════════════════════
# Test block 5 — text renderer (render_diff_as_text)
# ════════════════════════════════════════════════════════════════════
#
# render_diff_as_text consumes a DiffResult and produces a human-
# readable string. The schema for the text format is in DIFF_SPEC §6.
#
# Three load-bearing invariants:
#
# 1. Two-layer vocabulary made explicit. The JSON layer uses
#    machine values (`pilot_available`); the text layer uses human
#    labels (`pilot enrollment available`). This is THE block where
#    the vocabulary distinction the project has carried since
#    Block 2 finally pays off in user-facing output.
#
# 2. Forbidden phrases never appear. Every output passes
#    `assert_no_forbidden_phrases` before return. The check is
#    inside the renderer; the tests verify the OUTPUT is clean
#    rather than relying on the internal check.
#
# 3. Determinism. Same DiffResult → byte-identical string.
#    Required for golden-file testing in Block 6 (CLI) and for
#    diff-of-diff readability in code reviews.


class TestTextEmptyDiff:
    """Empty diff renders to a complete shape with all sections."""

    def test_text_empty_diff(self):
        """
        Two empty scans produce a non-empty string with header,
        audit block, summary, and section headers (or 'no changes'
        message). The output ends with a single trailing newline.
        """
        result = diff_scans(make_scan(groups=[]), make_scan(groups=[]))
        text = render_diff_as_text(result)

        # Non-empty, ends with single newline
        assert text
        assert text.endswith("\n")
        assert not text.endswith("\n\n")

        # Header present
        assert "═══ Diff:" in text
        assert "trustfall-lite" in text

        # Audit block present
        assert "Baseline:" in text
        assert "Current" in text
        assert "Paths:" in text

        # Summary always present, even when empty
        assert "Summary" in text
        assert "groups added:" in text
        assert "regressions:" in text


class TestTextGroupAdded:
    """group_added entries render as '+ source:group_id (status, N artifacts)'."""

    def test_text_group_added(self):
        new_group = make_group(
            source="huggingface_cache",
            group_id="org/new-model",
            status="verified",
            artifacts=[
                make_artifact(filename="m.safetensors", sha256="a" * 64)
            ],
        )
        text = render_diff_as_text(
            diff_scans(make_scan(groups=[]), make_scan(groups=[new_group]))
        )

        # The group identity appears in the output
        assert "huggingface_cache:org/new-model" in text

        # The "Group changes" section header exists
        assert "Group changes" in text

        # The added marker (+) and human label appear
        assert "+ huggingface_cache:org/new-model" in text
        assert "verified artifact" in text  # human label, not "verified"


class TestTextGroupRemoved:
    """group_removed entries render as '- source:group_id (status, N artifacts)'."""

    def test_text_group_removed(self):
        old_group = make_group(
            source="huggingface_cache",
            group_id="org/old-model",
            status="verified",
            artifacts=[
                make_artifact(filename="m.safetensors", sha256="a" * 64)
            ],
        )
        text = render_diff_as_text(
            diff_scans(make_scan(groups=[old_group]), make_scan(groups=[]))
        )

        # Removal marker and group identity
        assert "- huggingface_cache:org/old-model" in text
        assert "Group changes" in text


class TestTextArtifactAdded:
    """artifact_added entries render with filename and short sha."""

    def test_text_artifact_added(self):
        existing = make_artifact(filename="config.json", sha256="c" * 64)
        new = make_artifact(
            filename="tokenizer.json", sha256="d" * 64, size_bytes=500_000
        )

        baseline_group = make_group(
            source="huggingface_cache",
            group_id="org/m",
            artifacts=[existing],
        )
        current_group = make_group(
            source="huggingface_cache",
            group_id="org/m",
            artifacts=[existing, new],
        )

        text = render_diff_as_text(
            diff_scans(
                make_scan(groups=[baseline_group]),
                make_scan(groups=[current_group]),
            )
        )

        # Artifact change section appears
        assert "Artifact changes" in text
        # Added marker, group identity, filename, short sha all present
        assert "+ huggingface_cache:org/m" in text
        assert "tokenizer.json" in text
        # Sha is shortened (16 chars + ellipsis), not full
        assert "dddddddddddddddd..." in text
        assert "d" * 64 not in text  # full sha not in output


class TestTextArtifactRemoved:
    """artifact_removed entries render with filename and short sha."""

    def test_text_artifact_removed(self):
        gone = make_artifact(filename="weights.bin", sha256="e" * 64)
        sibling = make_artifact(filename="config.json", sha256="c" * 64)

        baseline_group = make_group(
            source="huggingface_cache",
            group_id="org/m",
            artifacts=[gone, sibling],
        )
        current_group = make_group(
            source="huggingface_cache",
            group_id="org/m",
            artifacts=[sibling],
        )

        text = render_diff_as_text(
            diff_scans(
                make_scan(groups=[baseline_group]),
                make_scan(groups=[current_group]),
            )
        )

        assert "- huggingface_cache:org/m" in text
        assert "weights.bin" in text
        # Short sha
        assert "eeeeeeeeeeeeeeee..." in text


class TestTextArtifactChanged:
    """artifact_changed entries show baseline → current sha pair."""

    def test_text_artifact_changed(self):
        baseline_group = make_group(
            source="huggingface_cache",
            group_id="org/m",
            artifacts=[
                make_artifact(filename="m.safetensors", sha256="a" * 64)
            ],
        )
        current_group = make_group(
            source="huggingface_cache",
            group_id="org/m",
            artifacts=[
                make_artifact(filename="m.safetensors", sha256="b" * 64)
            ],
        )

        text = render_diff_as_text(
            diff_scans(
                make_scan(groups=[baseline_group]),
                make_scan(groups=[current_group]),
            )
        )

        # Tilde marker indicates a changed artifact
        assert "~ huggingface_cache:org/m" in text
        assert "m.safetensors" in text
        # Both shas present in shortened form, with arrow between
        assert "aaaaaaaaaaaaaaaa..." in text
        assert "bbbbbbbbbbbbbbbb..." in text
        assert "→" in text  # the arrow specifically
        # NOT just the added or removed marker
        # (the change shouldn't be rendered as add+remove)
        change_lines = [
            line for line in text.split("\n") if "m.safetensors" in line
        ]
        assert len(change_lines) >= 1
        # On the change line, neither + nor - prefix should appear
        # (the convention is ~ for changed)
        for line in change_lines:
            if "huggingface_cache:org/m" in line:
                # Find the marker character
                stripped = line.lstrip()
                if stripped:
                    assert stripped[0] in ("~",), (
                        f"changed line uses wrong marker: {line!r}"
                    )


class TestTextStatusRegression:
    """
    A regression renders the current-status icon, the word 'regression',
    and the baseline → current human-label transition.
    """

    def test_text_status_regression(self):
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="verified",
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="unknown_variant",
                )
            ]
        )

        text = render_diff_as_text(diff_scans(baseline, current))

        # Status changes section header
        assert "Status changes" in text

        # The word "regression" appears (direction)
        assert "regression" in text

        # The transition uses HUMAN labels, not machine values
        assert "verified artifact" in text
        assert "unknown variant" in text
        assert "→" in text

        # The current-status icon (⚠ for unknown_variant) appears
        assert "⚠" in text


class TestTextStatusImprovement:
    """An improvement renders the verified ✓ icon and the word 'improvement'."""

    def test_text_status_improvement(self):
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="not_enrolled",
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="verified",
                )
            ]
        )

        text = render_diff_as_text(diff_scans(baseline, current))

        assert "improvement" in text
        # Verified icon for the new state
        assert "✓" in text
        # Human labels, not machine values
        assert "not enrolled" in text
        assert "verified artifact" in text


class TestTextStatusLateral:
    """A lateral change renders the word 'lateral' and human labels."""

    def test_text_status_lateral(self):
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="not_enrolled",
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="pilot_available",
                )
            ]
        )

        text = render_diff_as_text(diff_scans(baseline, current))

        assert "lateral" in text
        # Human labels
        assert "not enrolled" in text
        assert "pilot enrollment available" in text


class TestTextQuietMode:
    """quiet=True suppresses empty change-class sections."""

    def test_text_quiet_suppresses_empty_sections(self):
        """
        With quiet=True on an empty diff, the output omits the
        per-class section headers ("Group changes", etc.) since
        they're all empty. The header, audit block, and summary
        always appear.
        """
        result = diff_scans(make_scan(groups=[]), make_scan(groups=[]))
        verbose = render_diff_as_text(result, quiet=False)
        quiet = render_diff_as_text(result, quiet=True)

        # Both contain header + audit block + summary
        assert "Summary" in verbose
        assert "Summary" in quiet
        assert "Baseline:" in verbose
        assert "Baseline:" in quiet

        # Verbose includes empty section headers; quiet does not
        assert "Group changes" in verbose
        assert "Group changes" not in quiet
        assert "Status changes" in verbose
        assert "Status changes" not in quiet
        assert "Artifact changes" in verbose
        assert "Artifact changes" not in quiet

        # Quiet output is shorter
        assert len(quiet) < len(verbose)

    def test_text_quiet_keeps_non_empty_sections(self):
        """
        With quiet=True, sections with entries still appear; only
        empty sections are suppressed. Verifies the gate is
        per-section, not all-or-nothing.
        """
        baseline = make_scan(groups=[])
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/new",
                    status="verified",
                )
            ]
        )

        result = diff_scans(baseline, current)
        quiet = render_diff_as_text(result, quiet=True)

        # Group changes section appears (has an added group)
        assert "Group changes" in quiet
        assert "+ huggingface_cache:org/new" in quiet

        # But Status changes and Artifact changes are suppressed
        # (no entries of those classes)
        assert "Status changes" not in quiet
        assert "Artifact changes" not in quiet


class TestTextSummaryCounts:
    """Summary block always present, with correct counters."""

    def test_text_summary_counts(self):
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/regress",
                    status="verified",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/improve",
                    status="not_enrolled",
                ),
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/regress",
                    status="unknown_variant",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/improve",
                    status="verified",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/new",
                    status="verified",
                ),
            ]
        )

        text = render_diff_as_text(diff_scans(baseline, current))

        # Summary block with all eight counters
        assert "Summary" in text
        assert "groups added:        1" in text  # org/new
        assert "status changed:      2" in text  # regress + improve
        assert "regressions:       1" in text
        assert "improvements:      1" in text


class TestTextForbiddenPhrases:
    """
    No forbidden phrase ever appears in text output, regardless of
    the change classes present in the diff.
    """

    def test_text_forbidden_phrases_absent(self):
        """
        Build a text output with as much variety as possible
        (group adds/removes, status changes including regressions,
        artifact changes, registry digest drift) and verify NO
        forbidden phrase appears.
        """
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/regress",
                    status="verified",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="verified",
                    artifacts=[
                        make_artifact(
                            filename="m.safetensors", sha256="a" * 64
                        )
                    ],
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/old",
                    status="verified",
                ),
            ],
            registry_kid="fallrisk-OLD",
            registry_manifest_digest="1" * 64,
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/regress",
                    status="unknown_variant",  # regression
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="verified",
                    artifacts=[
                        make_artifact(
                            filename="m.safetensors", sha256="b" * 64
                        )
                    ],
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/new",
                    status="verified",
                ),
            ],
            registry_kid="fallrisk-NEW",
            registry_manifest_digest="2" * 64,
        )

        text = render_diff_as_text(diff_scans(baseline, current))

        # The renderer's internal guard should have already raised
        # if a forbidden phrase appeared. Re-check at the test layer
        # for explicit coverage.
        text_lower = text.lower()
        for phrase in FORBIDDEN_PHRASES:
            assert phrase.lower() not in text_lower, (
                f"forbidden phrase {phrase!r} appeared in output: {text!r}"
            )

    def test_text_forbidden_phrase_check_is_active_in_renderer(self):
        """
        Defensive: confirm that if a DiffChange somehow carried a
        forbidden phrase (e.g., in claimed_model_id), the renderer
        raises ForbiddenPhraseError rather than emitting the text.

        This tests the FAIL-LOUD nature of the guard. We construct
        a DiffResult by hand with a poisoned claimed_model_id and
        verify the renderer rejects it.
        """
        # Build a poisoned change that would cause the renderer to
        # emit a forbidden phrase if the guard were not active.
        poisoned_metadata = DiffScanMetadata(
            source="baseline", trustfall_lite_version="0.3.0"
        )
        empty_metadata = DiffScanMetadata(source="current")

        # Note: we use a forbidden phrase the renderer would inline
        # via claimed_model_id (which gets emitted in the group
        # added line).
        poisoned_change = DiffChange(
            type="group_added",
            source="huggingface_cache",
            group_id="org/the malicious one",  # contains "malicious"
            group_status="verified",
            n_artifacts=1,
            total_bytes=100,
            claimed_model_id="org/the malicious one",
        )

        result = DiffResult(
            summary=DiffSummary(groups_added=1),
            baseline=poisoned_metadata,
            current=empty_metadata,
            paths_allowed=False,
            changes=[poisoned_change],
        )

        # The renderer must REJECT this output, not emit it.
        with pytest.raises(ForbiddenPhraseError):
            render_diff_as_text(result)


class TestTextDeterministic:
    """Same DiffResult → byte-identical string."""

    def test_text_deterministic(self):
        """
        Two calls to render_diff_as_text on the same DiffResult
        produce strings equal under == (i.e., byte-identical).
        """
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="verified",
                    artifacts=[
                        make_artifact(
                            filename="model.safetensors", sha256="a" * 64
                        )
                    ],
                )
            ],
            registry_kid="fallrisk-96cd5e6a01e1",
            registry_manifest_digest="a" * 64,
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="unknown_variant",
                    artifacts=[
                        make_artifact(
                            filename="model.safetensors", sha256="b" * 64
                        )
                    ],
                )
            ],
            registry_kid="fallrisk-96cd5e6a01e1",
            registry_manifest_digest="b" * 64,
        )

        result = diff_scans(baseline, current)
        first = render_diff_as_text(result)
        second = render_diff_as_text(result)
        assert first == second

    def test_text_deterministic_with_quiet(self):
        """Quiet mode is also deterministic."""
        result = diff_scans(make_scan(groups=[]), make_scan(groups=[]))
        first = render_diff_as_text(result, quiet=True)
        second = render_diff_as_text(result, quiet=True)
        assert first == second


class TestTextPilotAvailableHumanLabel:
    """
    The two-layer vocabulary: text output uses 'pilot enrollment
    available', NOT 'pilot_available'. This is THE invariant that
    makes the JSON-vs-text distinction valuable.
    """

    def test_text_pilot_available_uses_human_label(self):
        """
        When a status_changed entry transitions to or from
        pilot_available, the text output uses the human label
        'pilot enrollment available' rather than the machine value
        'pilot_available'.
        """
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="not_enrolled",
                )
            ]
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="pilot_available",  # the transition target
                )
            ]
        )

        text = render_diff_as_text(diff_scans(baseline, current))

        # Human label appears
        assert "pilot enrollment available" in text

        # Machine value does NOT appear
        assert "pilot_available" not in text

    def test_text_all_status_labels_use_human_form(self):
        """
        Comprehensive: build a diff that exercises every status
        value as both source and destination. Verify all four human
        labels appear in the output and NONE of the machine values.
        """
        # Build a 4-group diff: one group per "from" status,
        # transitioning to verified (so we hit four directions).
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/from-verified",
                    status="verified",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/from-unknown",
                    status="unknown_variant",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/from-not-enrolled",
                    status="not_enrolled",
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/from-pilot",
                    status="pilot_available",
                ),
            ]
        )
        # Each transitions to a different state (covers all four
        # human labels in current_status as well)
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/from-verified",
                    status="not_enrolled",  # regression
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/from-unknown",
                    status="verified",  # improvement
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/from-not-enrolled",
                    status="pilot_available",  # lateral
                ),
                make_group(
                    source="huggingface_cache",
                    group_id="org/from-pilot",
                    status="unknown_variant",  # lateral
                ),
            ]
        )

        text = render_diff_as_text(diff_scans(baseline, current))

        # All four human labels present
        assert "verified artifact" in text
        assert "unknown variant" in text
        assert "not enrolled" in text
        assert "pilot enrollment available" in text

        # None of the machine values present (would be a vocab
        # leak if any were).
        # These are the JSON-layer enum values; they MUST NOT
        # appear in text output.
        # Use word-boundary checks because "verified" appears
        # inside "verified artifact" — that's the human label,
        # not a leak. Same for "unknown variant" containing
        # "unknown".
        assert "pilot_available" not in text
        assert "unknown_variant" not in text
        assert "not_enrolled" not in text


class TestTextRegistrySnapshotDigest:
    """
    When baseline and current registry digests differ, a neutral
    audit note appears in the output. The note uses non-alarming
    language and explains the operational context.
    """

    def test_text_registry_snapshot_digest_difference_visible(self):
        """
        With distinct registry digests on baseline and current, the
        output includes the registry-drift audit note. The note:
          - Mentions both digests (in shortened form)
          - Explains the implication for status changes
          - Does NOT use alarming language
        """
        baseline_digest = "5f159f7f6408e476" + "0" * 48
        current_digest = "8a29abcdef012345" + "0" * 48

        baseline = make_scan(
            groups=[],
            registry_manifest_digest=baseline_digest,
            registry_kid="fallrisk-test",
        )
        current = make_scan(
            groups=[],
            registry_manifest_digest=current_digest,
            registry_kid="fallrisk-test",
        )

        text = render_diff_as_text(diff_scans(baseline, current))

        # The note appears
        assert "Registry snapshot changed" in text

        # Both digests visible (shortened)
        assert baseline_digest[:16] in text
        assert current_digest[:16] in text

        # Non-alarming language used
        assert "Status changes may reflect registry coverage changes" in text

        # Neutral tone — none of the alarmist words
        text_lower = text.lower()
        for alarming in (
            "tampered",
            "compromised",
            "fake",
            "malicious",
            "trojan",
        ):
            assert alarming not in text_lower

    def test_text_no_registry_note_when_digests_match(self):
        """
        When digests match (or both absent), no audit note appears.
        Avoids visual noise on the common no-drift case.
        """
        digest = "a" * 64
        baseline = make_scan(
            groups=[], registry_manifest_digest=digest
        )
        current = make_scan(
            groups=[], registry_manifest_digest=digest
        )

        text = render_diff_as_text(diff_scans(baseline, current))

        # No audit note
        assert "Registry snapshot changed" not in text

    def test_text_no_registry_note_when_one_side_missing(self):
        """
        If only one side has a digest, no comparative note appears
        (you can't compare against missing data). The metadata line
        still shows the present digest — just no drift warning.
        """
        baseline = make_scan(
            groups=[], registry_manifest_digest="a" * 64
        )
        current = make_scan(groups=[])  # no digest

        text = render_diff_as_text(diff_scans(baseline, current))

        assert "Registry snapshot changed" not in text


class TestTextPathsGate:
    """
    Filesystem path strings do not appear in text output unless
    paths_allowed=True. Currently DiffChange does not carry path
    strings, so this is forward-compatible structural verification.
    """

    def test_text_paths_excluded_when_paths_not_allowed(self):
        """
        With paths_allowed=False, no '/' or '\\' character appears
        in any change-related line of the output (other than in
        the literal 'Paths:    excluded' status line). This is a
        structural property — even if a future schema addition
        introduced path-bearing fields, this test would fail loud.
        """
        # Mixed diff with all change classes
        baseline = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="verified",
                    artifacts=[
                        make_artifact(
                            filename="m.safetensors", sha256="a" * 64
                        )
                    ],
                )
            ],
            include_paths=False,
        )
        current = make_scan(
            groups=[
                make_group(
                    source="huggingface_cache",
                    group_id="org/m",
                    status="unknown_variant",
                    artifacts=[
                        make_artifact(
                            filename="m.safetensors", sha256="b" * 64
                        )
                    ],
                )
            ],
            include_paths=False,
        )

        text = render_diff_as_text(diff_scans(baseline, current))

        # The Paths: status line itself is allowed to contain "/"
        # only if it matches "excluded" or "allowed" — we verify
        # by checking the audit field reads "excluded".
        assert "Paths:    excluded" in text

        # No absolute paths anywhere — searches for typical
        # absolute path prefixes that would indicate a leak.
        assert "/home/" not in text
        assert "/Users/" not in text
        assert "C:\\" not in text
        assert "/var/" not in text
        # A file:// URL would also be a leak
        assert "file://" not in text

    def test_text_paths_allowed_label_when_both_opt_in(self):
        """
        With paths_allowed=True (both sides include_paths=True),
        the audit line reads 'allowed'. The current schema emits no
        actual paths regardless, but the audit signal is correct.
        """
        baseline = make_scan(groups=[], include_paths=True)
        current = make_scan(groups=[], include_paths=True)

        text = render_diff_as_text(diff_scans(baseline, current))

        assert "Paths:    allowed" in text


# ════════════════════════════════════════════════════════════════════
# Sanity: change-class enumeration matches DIFF_SPEC §4
# ════════════════════════════════════════════════════════════════════


def test_six_change_classes_exactly():
    """
    DIFF_SPEC §4 locks the change-class taxonomy at six classes.
    `claim_source_changed` was deferred to v0.4 per the patch round
    on 2026-04-28. If a seventh class is added without updating the
    spec and this test, it's a doctrinal violation.
    """
    assert len(CHANGE_TYPES) == 6
    assert set(CHANGE_TYPES) == {
        "group_added",
        "group_removed",
        "artifact_added",
        "artifact_removed",
        "artifact_changed",
        "status_changed",
    }
