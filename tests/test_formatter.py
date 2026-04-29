"""
Tests for the status formatter.

Two contract surfaces are tested:

1. The four status states render the correct icons and labels.
2. Forbidden phrases are caught in any constructed output string.

If either contract drifts, these tests fail loudly and tomorrow's CLI
work cannot ship.
"""

import json

import pytest

from fallrisk_trustfall.formatter import (
    FORBIDDEN_PHRASES,
    FileResult,
    ForbiddenPhraseError,
    Status,
    assert_no_forbidden_phrases,
    render_file_line,
    render_results_as_dict,
    render_summary,
    status_icon,
    status_label,
)


# ════════════════════════════════════════════════════════════════════
# Status state contracts
# ════════════════════════════════════════════════════════════════════


class TestStatusStates:
    """The four locked status states must render with the correct icons and labels."""

    def test_exactly_four_status_states_exist(self):
        # If a fifth state is added, this test fails. That's the point —
        # adding a state requires updating the spec and the formatter
        # together.
        assert len(Status) == 4
        assert {s.value for s in Status} == {
            "verified", "unknown_variant", "not_enrolled", "pilot_available"
        }

    def test_verified_renders_check_mark(self):
        assert status_icon(Status.VERIFIED, colored=False) == "✓"
        assert status_label(Status.VERIFIED) == "verified artifact"

    def test_unknown_variant_renders_warning(self):
        assert status_icon(Status.UNKNOWN_VARIANT, colored=False) == "⚠"
        assert status_label(Status.UNKNOWN_VARIANT) == "unknown variant"

    def test_not_enrolled_renders_question(self):
        assert status_icon(Status.NOT_ENROLLED, colored=False) == "?"
        assert status_label(Status.NOT_ENROLLED) == "not enrolled"

    def test_pilot_available_renders_arrow(self):
        assert status_icon(Status.PILOT_AVAILABLE, colored=False) == "→"
        assert status_label(Status.PILOT_AVAILABLE) == "pilot enrollment available"


# ════════════════════════════════════════════════════════════════════
# Forbidden phrases contract
# ════════════════════════════════════════════════════════════════════


class TestForbiddenPhrases:
    """Forbidden phrases must be caught in any output string."""

    def test_forbidden_phrase_list_is_complete(self):
        # The minimum set per spec. Adding to this set is a doctrine
        # tightening; removing requires a spec amendment.
        required = {"compromised", "fake", "identity verified", "tampered",
                    "malicious", "trojan"}
        assert required <= set(FORBIDDEN_PHRASES)

    @pytest.mark.parametrize("phrase", list(FORBIDDEN_PHRASES))
    def test_each_forbidden_phrase_is_caught(self, phrase):
        with pytest.raises(ForbiddenPhraseError):
            assert_no_forbidden_phrases(f"this artifact is {phrase}")

    def test_case_insensitive(self):
        with pytest.raises(ForbiddenPhraseError):
            assert_no_forbidden_phrases("Tampered")
        with pytest.raises(ForbiddenPhraseError):
            assert_no_forbidden_phrases("TROJAN")

    def test_substring_caught(self):
        # "compromised state" should fail because "compromised" is present.
        with pytest.raises(ForbiddenPhraseError):
            assert_no_forbidden_phrases("model entered compromised state")

    def test_safe_text_passes(self):
        # Spec-allowed vocabulary must not trigger.
        assert_no_forbidden_phrases("✓ verified artifact  model.safetensors")
        assert_no_forbidden_phrases("? not enrolled  unknown_model.gguf")
        assert_no_forbidden_phrases("→ pilot enrollment available")
        assert_no_forbidden_phrases("Apache-2.0 · Alibaba · Qwen/Qwen2.5-14B-Instruct")


# ════════════════════════════════════════════════════════════════════
# Per-file rendering
# ════════════════════════════════════════════════════════════════════


class TestRenderFileLine:
    """File line rendering integrates icons, labels, and detail rows."""

    def test_verified_file_includes_model_publisher_license(self):
        result = FileResult(
            path="model-00001-of-00008.safetensors",
            sha256="b477be7572f0ab3ae3cbba38d508cc33e70600b2045669c4ad848051c3432094",
            size_bytes=3885154816,
            status=Status.VERIFIED,
            model_id="Qwen/Qwen2.5-14B-Instruct",
            publisher="Alibaba",
            license="Apache-2.0",
        )
        line = render_file_line(result, colored=False)
        assert "✓" in line
        assert "verified artifact" in line
        assert "Qwen/Qwen2.5-14B-Instruct" in line
        assert "Alibaba" in line
        assert "Apache-2.0" in line

    def test_not_enrolled_minimal(self):
        result = FileResult(
            path="random.safetensors",
            sha256="0" * 64,
            size_bytes=1024,
            status=Status.NOT_ENROLLED,
        )
        line = render_file_line(result, colored=False)
        assert "?" in line
        assert "not enrolled" in line

    def test_pilot_available_includes_contact(self):
        result = FileResult(
            path="custom.safetensors",
            sha256="0" * 64,
            size_bytes=1024,
            status=Status.PILOT_AVAILABLE,
        )
        line = render_file_line(result, colored=False)
        assert "→" in line
        assert "integrations@fallrisk.ai" in line


class TestRenderFileLine_v011:
    """v0.1.1 polish: display_name leads, no 'closest match', claim_source explained."""

    def test_unknown_variant_leads_with_display_name_not_filename(self):
        """v0.1.1: primary label must be the claimed model_id, not 'model.safetensors'."""
        result = FileResult(
            path="model.safetensors",
            sha256="0" * 64,
            size_bytes=1024,
            status=Status.UNKNOWN_VARIANT,
            model_id="EleutherAI/gpt-neo-1.3B",
            claim_source="hf_cache_path",
            display_name="EleutherAI/gpt-neo-1.3B",
        )
        line = render_file_line(result, colored=False)
        # First line should show the model_id, not the generic filename
        first_line = line.split("\n")[0]
        assert "EleutherAI/gpt-neo-1.3B" in first_line
        assert "model.safetensors" not in first_line

    def test_unknown_variant_says_claimed_by_hf_cache_path(self):
        """v0.1.1: the misleading 'closest match' must be replaced."""
        result = FileResult(
            path="model.safetensors",
            sha256="0" * 64,
            size_bytes=1024,
            status=Status.UNKNOWN_VARIANT,
            model_id="google/gemma-2-9b",
            claim_source="hf_cache_path",
            display_name="google/gemma-2-9b",
        )
        line = render_file_line(result, colored=False)
        assert "claimed by Hugging Face cache path" in line
        assert "closest match" not in line

    def test_unknown_variant_explains_what_it_means(self):
        """v0.1.1: unknown_variant must explain the hash-vs-record mismatch."""
        result = FileResult(
            path="model.safetensors",
            sha256="0" * 64,
            size_bytes=1024,
            status=Status.UNKNOWN_VARIANT,
            model_id="bigscience/bloom-560m",
            claim_source="hf_cache_path",
            display_name="bigscience/bloom-560m",
        )
        line = render_file_line(result, colored=False)
        assert "artifact hash does not match signed registry record" in line
        assert "alternate revision" in line

    def test_verified_with_multiple_shards_shows_count(self):
        """v0.1.1: sharded verified models say 'N shards verified'."""
        result = FileResult(
            path="model-00001-of-00004.safetensors",
            sha256="b477be7572f0ab3ae3cbba38d508cc33e70600b2045669c4ad848051c3432094",
            size_bytes=8 * 10**9,
            status=Status.VERIFIED,
            model_id="meta-llama/Llama-3.2-1B-Instruct",
            publisher="Meta",
            license="Llama-3.2-Community",
            claim_source="hf_cache_path",
            n_artifacts=4,
            display_name="meta-llama/Llama-3.2-1B-Instruct",
        )
        line = render_file_line(result, colored=False)
        assert "4 shards verified" in line

    def test_not_enrolled_explains_what_it_means(self):
        """v0.1.1: not_enrolled shouldn't be a bare label."""
        result = FileResult(
            path="random.gguf",
            sha256="0" * 64,
            size_bytes=1024,
            status=Status.NOT_ENROLLED,
        )
        line = render_file_line(result, colored=False)
        assert "artifact not in Fall Risk registry" in line


# ════════════════════════════════════════════════════════════════════
# Session summary rendering
# ════════════════════════════════════════════════════════════════════


class TestRenderSummary:
    def test_empty_results(self):
        assert render_summary([], colored=False) == "No model artifacts scanned."

    def test_mixed_results_count_correctly(self):
        results = [
            FileResult("a.safetensors", "0" * 64, 1024, Status.VERIFIED, "model/a"),
            FileResult("b.safetensors", "1" * 64, 2048, Status.VERIFIED, "model/b"),
            FileResult("c.gguf", "2" * 64, 4096, Status.NOT_ENROLLED),
        ]
        summary = render_summary(results, colored=False)
        # New wording per v0.1.1: model groups, not files
        assert "Scanned 3 model groups" in summary
        assert "2 verified artifact" in summary
        assert "1 not enrolled" in summary

    def test_byte_formatting(self):
        results = [FileResult("a", "0" * 64, 1_500_000_000, Status.VERIFIED)]
        summary = render_summary(results, colored=False)
        assert "1.50 GB" in summary

    def test_summary_with_sharded_groups_shows_artifact_count(self):
        """When n_artifacts != n_groups (sharding present), summary shows both."""
        results = [
            FileResult("model/a", "0" * 64, 8 * 10**9, Status.VERIFIED,
                       model_id="model/a", n_artifacts=4),
            FileResult("model/b", "1" * 64, 1 * 10**9, Status.VERIFIED,
                       model_id="model/b", n_artifacts=1),
        ]
        summary = render_summary(results, colored=False)
        assert "2 model groups" in summary
        assert "5 artifacts" in summary  # 4 + 1


# ════════════════════════════════════════════════════════════════════
# JSON output
# ════════════════════════════════════════════════════════════════════


class TestRenderResultsAsDict:
    def test_serializable(self):
        results = [
            FileResult("a", "0" * 64, 1024, Status.VERIFIED,
                       model_id="m/a", publisher="P", license="MIT"),
        ]
        out = render_results_as_dict(results)
        # Must be serializable to JSON without error
        json.dumps(out)
        assert out["scan_summary"]["files_scanned"] == 1
        assert out["scan_summary"]["counts"]["verified"] == 1
        assert out["results"][0]["status"] == "verified"


class TestRenderResultsAsDict_v011:
    """v0.1.1 polish: claim_source surfaces, group/artifact counts both present."""

    def test_claim_source_appears_in_json_when_set(self):
        """Regression test for the v0.1.0 bug where claim_source was always null."""
        results = [
            FileResult(
                path="model.safetensors",
                sha256="0" * 64,
                size_bytes=1024,
                status=Status.UNKNOWN_VARIANT,
                model_id="EleutherAI/gpt-neo-1.3B",
                claim_source="hf_cache_path",
                display_name="EleutherAI/gpt-neo-1.3B",
            ),
        ]
        out = render_results_as_dict(results)
        # The bug: this was always null in v0.1.0
        assert out["results"][0]["claim_source"] == "hf_cache_path"

    def test_summary_has_both_groups_and_artifacts(self):
        """v0.1.1: summary must have groups_scanned AND artifacts_scanned."""
        results = [
            FileResult("a", "0" * 64, 1024, Status.VERIFIED,
                       model_id="m/a", n_artifacts=4),
            FileResult("b", "1" * 64, 2048, Status.VERIFIED,
                       model_id="m/b", n_artifacts=1),
        ]
        out = render_results_as_dict(results)
        assert out["scan_summary"]["groups_scanned"] == 2
        assert out["scan_summary"]["artifacts_scanned"] == 5
        # Backward-compat alias
        assert out["scan_summary"]["files_scanned"] == 2

    def test_display_name_appears_in_json(self):
        """v0.1.1: JSON consumers should see the display_name we computed."""
        results = [
            FileResult(
                path="model-00001-of-00008.safetensors",
                sha256="0" * 64,
                size_bytes=8 * 10**9,
                status=Status.UNKNOWN_VARIANT,
                model_id="google/gemma-2-9b",
                claim_source="hf_cache_path",
                n_artifacts=8,
                display_name="google/gemma-2-9b",
            ),
        ]
        out = render_results_as_dict(results)
        assert out["results"][0]["display_name"] == "google/gemma-2-9b"
        assert out["results"][0]["n_artifacts"] == 8
