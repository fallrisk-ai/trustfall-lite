"""
Tests for the scanner orchestrator.

The scanner is where Decision 1 (sharded model roll-up) lives. Tests
prove the classification logic across the full matrix:

  Group has claim?  All artifacts verified?  Same model_id?  → Status
  ─────────────────────────────────────────────────────────────────
  yes              all verified             same          → VERIFIED
  yes              all verified             different     → UNKNOWN_VARIANT
  yes              partial                  irrelevant    → UNKNOWN_VARIANT
  yes              none                     —             → UNKNOWN_VARIANT
  no               all verified             same          → VERIFIED
  no               partial / none           —             → NOT_ENROLLED
  any              hash failure on any      —             → handled

Plus: signature failure must NEVER produce VERIFIED, even if the API
returns 200 (reinforces the trust contract from the API tests).
"""

from typing import Any

import pytest

from fallrisk_trustfall.api import APILookupResult, VerifiedRecord
from fallrisk_trustfall.formatter import Status
from fallrisk_trustfall.models import ArtifactCandidate, Claim, ModelGroup
from fallrisk_trustfall.scanner import (
    APIHashLookup,
    GroupScanResult,
    HashLookup,
    LocalHashLookup,
    verify_groups,
)


# ════════════════════════════════════════════════════════════════════
# MockHashLookup — drives precise scenarios for classification tests
# ════════════════════════════════════════════════════════════════════


class MockHashLookup(HashLookup):
    """In-memory lookup that returns pre-canned results."""

    def __init__(self, results: dict[str, APILookupResult]) -> None:
        self._results = results

    def lookup_many(self, sha256s: list[str]) -> dict[str, APILookupResult]:
        return {h: self._results.get(h, APILookupResult(sha256=h, status="not_enrolled"))
                for h in sha256s}


def _verified_result(sha256: str, model_id: str) -> APILookupResult:
    """Build a verified APILookupResult with synthetic claims."""
    return APILookupResult(
        sha256=sha256,
        status="verified",
        record=VerifiedRecord(
            sha256=sha256,
            record_jws="<jws-omitted-for-test>",
            claims={
                "model_id": model_id,
                "publisher": "Example Org",
                "license": "Apache-2.0",
                "enrollment_id": f"enroll-{sha256[:8]}",
            },
            registry_kid="fallrisk-96cd5e6a01e1",
            registry_snapshot_at="2026-04-26T22:45:45+00:00",
        ),
    )


def _not_enrolled(sha256: str) -> APILookupResult:
    return APILookupResult(sha256=sha256, status="not_enrolled")


def _make_artifact(sha256: str, filename: str = "model.safetensors") -> ArtifactCandidate:
    return ArtifactCandidate(
        sha256=sha256, size_bytes=1024,
        format_hint="safetensors", source="path",
        path=f"/fake/{filename}", filename=filename, claim=None,
    )


def _make_group(
    artifacts: list[ArtifactCandidate],
    claim_model_id: str | None = None,
    group_kind: str = "single_file",
) -> ModelGroup:
    return ModelGroup(
        group_id="test-group",
        source="path",
        group_kind=group_kind,  # type: ignore[arg-type]
        artifacts=tuple(artifacts),
        claimed_model_id=claim_model_id,
    )


# ════════════════════════════════════════════════════════════════════
# Single-artifact group classification
# ════════════════════════════════════════════════════════════════════


class TestSingleFileClassification:
    def test_verified_when_hash_matches(self):
        h = "a" * 64
        group = _make_group([_make_artifact(h)], claim_model_id="example/model")
        lookup = MockHashLookup({h: _verified_result(h, "example/model")})

        results = verify_groups([group], lookup)
        assert len(results) == 1
        assert results[0].file_result.status == Status.VERIFIED
        assert results[0].file_result.model_id == "example/model"
        assert results[0].matched_record is not None

    def test_unknown_variant_when_claim_present_but_not_enrolled(self):
        h = "b" * 64
        group = _make_group([_make_artifact(h)], claim_model_id="example/model")
        lookup = MockHashLookup({h: _not_enrolled(h)})

        results = verify_groups([group], lookup)
        assert results[0].file_result.status == Status.UNKNOWN_VARIANT
        assert results[0].file_result.model_id == "example/model"

    def test_not_enrolled_when_no_claim_and_not_enrolled(self):
        h = "c" * 64
        group = _make_group([_make_artifact(h)], claim_model_id=None)
        lookup = MockHashLookup({h: _not_enrolled(h)})

        results = verify_groups([group], lookup)
        assert results[0].file_result.status == Status.NOT_ENROLLED

    def test_verified_with_no_claim_when_hash_matches(self):
        """Loose file with no claim that happens to be in the registry → still verified."""
        h = "d" * 64
        group = _make_group([_make_artifact(h)], claim_model_id=None)
        lookup = MockHashLookup({h: _verified_result(h, "auto/discovered")})

        results = verify_groups([group], lookup)
        assert results[0].file_result.status == Status.VERIFIED
        assert results[0].file_result.model_id == "auto/discovered"


# ════════════════════════════════════════════════════════════════════
# Sharded model classification (Decision 1 logic)
# ════════════════════════════════════════════════════════════════════


class TestShardedModelClassification:
    def test_all_shards_verified_same_model_id(self):
        """Spec §5: sharded verified ONLY when ALL shards match same record."""
        h1, h2, h3 = "a" * 64, "b" * 64, "c" * 64
        group = _make_group(
            [_make_artifact(h1, "model-00001-of-00003.safetensors"),
             _make_artifact(h2, "model-00002-of-00003.safetensors"),
             _make_artifact(h3, "model-00003-of-00003.safetensors")],
            claim_model_id="meta-llama/Llama-3.1-8B-Instruct",
            group_kind="sharded_safetensors",
        )
        lookup = MockHashLookup({
            h1: _verified_result(h1, "meta-llama/Llama-3.1-8B-Instruct"),
            h2: _verified_result(h2, "meta-llama/Llama-3.1-8B-Instruct"),
            h3: _verified_result(h3, "meta-llama/Llama-3.1-8B-Instruct"),
        })

        results = verify_groups([group], lookup)
        assert results[0].file_result.status == Status.VERIFIED
        assert results[0].file_result.model_id == "meta-llama/Llama-3.1-8B-Instruct"

    def test_all_shards_verified_but_mixed_model_ids_is_unknown_variant(self):
        """If shards verify to DIFFERENT models, the group is unknown_variant."""
        h1, h2 = "a" * 64, "b" * 64
        group = _make_group(
            [_make_artifact(h1, "model-00001-of-00002.safetensors"),
             _make_artifact(h2, "model-00002-of-00002.safetensors")],
            claim_model_id="claimed/model",
            group_kind="sharded_safetensors",
        )
        lookup = MockHashLookup({
            h1: _verified_result(h1, "model-A"),
            h2: _verified_result(h2, "model-B"),  # mismatch!
        })

        results = verify_groups([group], lookup)
        assert results[0].file_result.status == Status.UNKNOWN_VARIANT

    def test_partial_verification_is_unknown_variant_with_claim(self):
        """One shard verified, one not → unknown_variant."""
        h1, h2 = "a" * 64, "b" * 64
        group = _make_group(
            [_make_artifact(h1), _make_artifact(h2)],
            claim_model_id="claimed/model",
            group_kind="sharded_safetensors",
        )
        lookup = MockHashLookup({
            h1: _verified_result(h1, "claimed/model"),
            h2: _not_enrolled(h2),
        })

        results = verify_groups([group], lookup)
        assert results[0].file_result.status == Status.UNKNOWN_VARIANT

    def test_sharded_total_size_aggregated(self):
        """The reported size_bytes should be the sum across all shards."""
        h1, h2 = "a" * 64, "b" * 64
        a1 = ArtifactCandidate(
            sha256=h1, size_bytes=1000, format_hint="safetensors", source="path",
            path="/x/s1", filename="s1", claim=None,
        )
        a2 = ArtifactCandidate(
            sha256=h2, size_bytes=2000, format_hint="safetensors", source="path",
            path="/x/s2", filename="s2", claim=None,
        )
        group = ModelGroup(
            group_id="sharded", source="path", group_kind="sharded_safetensors",
            artifacts=(a1, a2), claimed_model_id="example/model",
        )
        lookup = MockHashLookup({
            h1: _verified_result(h1, "example/model"),
            h2: _verified_result(h2, "example/model"),
        })

        results = verify_groups([group], lookup)
        assert results[0].file_result.size_bytes == 3000

    def test_per_shard_lookups_preserved_in_artifact_lookups(self):
        """Decision 1 lower half: per-shard data is preserved for JSON output."""
        h1, h2 = "a" * 64, "b" * 64
        group = _make_group(
            [_make_artifact(h1), _make_artifact(h2)],
            claim_model_id="example/model",
            group_kind="sharded_safetensors",
        )
        lookup = MockHashLookup({
            h1: _verified_result(h1, "example/model"),
            h2: _not_enrolled(h2),
        })

        results = verify_groups([group], lookup)
        assert len(results[0].artifact_lookups) == 2
        assert results[0].artifact_lookups[0].status == "verified"
        assert results[0].artifact_lookups[1].status == "not_enrolled"


# ════════════════════════════════════════════════════════════════════
# Trust contract: signature failure must NOT produce VERIFIED
# ════════════════════════════════════════════════════════════════════


class TestTrustContract:
    def test_api_error_status_does_not_produce_verified(self):
        """
        Reinforces the trust contract: an artifact whose API result is
        `error` (which includes signature mismatch per the API client)
        must not yield a VERIFIED group, even with a claim present.
        """
        h = "a" * 64
        group = _make_group([_make_artifact(h)], claim_model_id="example/model")
        lookup = MockHashLookup({
            h: APILookupResult(
                sha256=h, status="error",
                error_message="JWS signature verification failed",
            ),
        })

        results = verify_groups([group], lookup)
        # Status MUST NOT be VERIFIED. With a claim present, it falls
        # to UNKNOWN_VARIANT (correct: the local context suggests this
        # model, but we cannot confirm it).
        assert results[0].file_result.status != Status.VERIFIED
        assert results[0].file_result.status == Status.UNKNOWN_VARIANT

    def test_sharded_with_one_signature_failure_not_verified(self):
        """One shard that fails signature verification breaks the whole group."""
        h1, h2 = "a" * 64, "b" * 64
        group = _make_group(
            [_make_artifact(h1), _make_artifact(h2)],
            claim_model_id="example/model",
            group_kind="sharded_safetensors",
        )
        lookup = MockHashLookup({
            h1: _verified_result(h1, "example/model"),
            h2: APILookupResult(sha256=h2, status="error",
                                error_message="JWS signature verification failed"),
        })

        results = verify_groups([group], lookup)
        assert results[0].file_result.status != Status.VERIFIED


# ════════════════════════════════════════════════════════════════════
# Hash failure handling
# ════════════════════════════════════════════════════════════════════


class TestHashFailureHandling:
    def test_empty_sha256_handled_gracefully(self):
        """An artifact with empty sha256 (read failure) doesn't crash the scanner."""
        h_good = "a" * 64
        # One artifact with no sha256 (simulates failed read)
        bad = ArtifactCandidate(
            sha256="", size_bytes=0, format_hint="safetensors", source="path",
            path="/dev/null/unreadable", filename="bad", claim=None,
        )
        good = _make_artifact(h_good)
        group = _make_group([bad, good], claim_model_id="example/model",
                            group_kind="sharded_safetensors")
        lookup = MockHashLookup({h_good: _verified_result(h_good, "example/model")})

        # Should not raise
        results = verify_groups([group], lookup)
        # Group is not VERIFIED because one artifact didn't get to lookup
        assert results[0].file_result.status != Status.VERIFIED


# ════════════════════════════════════════════════════════════════════
# Multi-group end-to-end
# ════════════════════════════════════════════════════════════════════


class TestMultiGroupScan:
    def test_multiple_groups_classified_independently(self):
        """A real scan produces a mix of verified, unknown_variant, not_enrolled."""
        h1, h2, h3 = "a" * 64, "b" * 64, "c" * 64

        groups = [
            _make_group([_make_artifact(h1)], claim_model_id="example/verified"),
            _make_group([_make_artifact(h2)], claim_model_id="example/unknown"),
            _make_group([_make_artifact(h3)], claim_model_id=None),
        ]

        lookup = MockHashLookup({
            h1: _verified_result(h1, "example/verified"),
            h2: _not_enrolled(h2),
            h3: _not_enrolled(h3),
        })

        results = verify_groups(groups, lookup)
        statuses = [r.file_result.status for r in results]
        assert statuses == [Status.VERIFIED, Status.UNKNOWN_VARIANT, Status.NOT_ENROLLED]

    def test_batch_lookup_called_with_unique_hashes_only(self):
        """Duplicate hashes across groups should be deduplicated for the lookup."""
        h_shared = "a" * 64

        class CountingLookup(HashLookup):
            def __init__(self):
                self.calls: list[list[str]] = []
            def lookup_many(self, sha256s):
                self.calls.append(sha256s)
                return {h: _verified_result(h, "shared/model") for h in sha256s}

        groups = [
            _make_group([_make_artifact(h_shared)]),
            _make_group([_make_artifact(h_shared)]),  # same hash again
        ]
        counting = CountingLookup()
        verify_groups(groups, counting)

        # Should have been called once with one unique hash
        assert len(counting.calls) == 1
        assert counting.calls[0] == [h_shared]
