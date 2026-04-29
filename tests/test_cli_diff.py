"""
Tests for the `trustfall diff` CLI command (Block 6).

Block 6 implements the explicit two-file form of `trustfall diff`.
The implicit-current form (`trustfall diff baseline.json` with no
CURRENT) is reserved for Block 7 and these tests deliberately
EXCLUDE that case.

Exit-code precedence per DIFF_SPEC §exit-codes:

    0    No changes, or changes detected but no exit-code flags set.
    1    --exit-code set and one or more changes detected.
    2    --exit-code-on-status-regression set and a regression exists.
    64   File I/O error or malformed JSON.
    65   Parseable JSON but not a Trustfall Lite scan.
    66   Trustfall Lite scan from an incompatible major version.

The precedence is: errors > regression flag > generic-change flag > clean.

Tests use Click's CliRunner. Fixture files are written into a
tmp_path-isolated directory per test.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from fallrisk_trustfall.cli import main
from fallrisk_trustfall import __version__


# ════════════════════════════════════════════════════════════════════
# Fixture builders
# ════════════════════════════════════════════════════════════════════


def _scan_dict(
    *,
    groups: list[dict[str, Any]] | None = None,
    version: str | None = None,
    include_paths: bool = False,
    registry_kid: str | None = None,
    registry_manifest_digest: str | None = None,
) -> dict[str, Any]:
    """Build a scan-JSON dict matching the live cli.py:_render_json_scan output.

    Defaults to the current Trustfall Lite version so tests don't
    accidentally trip the major-version-mismatch check.
    """
    actual_groups = groups if groups is not None else []
    out: dict[str, Any] = {
        "trustfall_lite_version": version if version is not None else __version__,
        "scan_paths": [],
        "include_paths": include_paths,
        "trust_ollama_filenames": False,
        "summary": {
            "groups_scanned": len(actual_groups),
            "artifacts_scanned": sum(
                g.get("n_artifacts", 0) for g in actual_groups
            ),
            "total_bytes": sum(
                g.get("total_bytes", 0) for g in actual_groups
            ),
        },
        "groups": actual_groups,
    }
    if registry_kid is not None:
        out["registry_kid"] = registry_kid
    if registry_manifest_digest is not None:
        out["registry_manifest_digest"] = registry_manifest_digest
    return out


def _group(
    *,
    group_id: str,
    source: str = "huggingface_cache",
    status: str = "verified",
    artifacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a minimal group dict."""
    arts = artifacts if artifacts is not None else []
    return {
        "group_id": group_id,
        "source": source,
        "status": status,
        "n_artifacts": len(arts),
        "total_bytes": sum(a.get("size_bytes", 0) for a in arts),
        "claimed_model_id": group_id,
        "claim_source": None,
        "group_kind": "model",
        "artifacts": arts,
    }


def _artifact(
    *,
    filename: str,
    sha256: str,
    size_bytes: int = 1_000_000,
) -> dict[str, Any]:
    return {
        "filename": filename,
        "sha256": sha256,
        "size_bytes": size_bytes,
        "format_hint": "safetensors",
    }


def _write_scan(tmp_path: Path, name: str, scan: dict[str, Any]) -> Path:
    """Write a scan dict to tmp_path/name.json and return the path."""
    p = tmp_path / name
    p.write_text(json.dumps(scan, indent=2), encoding="utf-8")
    return p


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ════════════════════════════════════════════════════════════════════
# Output mode: text (default), JSON, quiet
# ════════════════════════════════════════════════════════════════════


class TestCliDiffTextOutput:
    """Default invocation emits human-readable text."""

    def test_cli_diff_text_output(self, runner, tmp_path):
        baseline = _write_scan(
            tmp_path,
            "baseline.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="verified"),
                ]
            ),
        )
        current = _write_scan(
            tmp_path,
            "current.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="unknown_variant"),
                ]
            ),
        )

        result = runner.invoke(
            main, ["diff", str(baseline), str(current)]
        )

        assert result.exit_code == 0
        # Text-format markers (the human renderer's signature)
        assert "═══ Diff:" in result.output
        assert "Summary" in result.output
        # Human labels from the two-layer vocabulary
        assert "verified artifact" in result.output
        assert "unknown variant" in result.output
        # Direction word for the regression
        assert "regression" in result.output


class TestCliDiffJsonOutput:
    """--json flag emits a parseable JSON document."""

    def test_cli_diff_json_output(self, runner, tmp_path):
        baseline = _write_scan(
            tmp_path,
            "baseline.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="verified"),
                ]
            ),
        )
        current = _write_scan(
            tmp_path,
            "current.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="unknown_variant"),
                ]
            ),
        )

        result = runner.invoke(
            main, ["diff", "--json", str(baseline), str(current)]
        )

        assert result.exit_code == 0

        # Output is valid JSON
        payload = json.loads(result.output)

        # Schema fields per DIFF_SPEC §6
        assert payload["schema_version"] == "0.3.0"
        assert "baseline" in payload
        assert "current" in payload
        assert "paths_allowed" in payload
        assert "summary" in payload
        assert "changes" in payload

        # Status change is present, machine vocabulary
        status_changes = [
            c for c in payload["changes"] if c["type"] == "status_changed"
        ]
        assert len(status_changes) == 1
        assert status_changes[0]["current_status"] == "unknown_variant"
        # NOT the human label — JSON layer is machine vocab
        assert status_changes[0]["current_status"] != "unknown variant"

    def test_cli_diff_json_does_not_emit_text_markers(self, runner, tmp_path):
        """JSON mode must NOT include the text-renderer's section banners."""
        baseline = _write_scan(
            tmp_path, "baseline.json", _scan_dict(groups=[])
        )
        current = _write_scan(
            tmp_path, "current.json", _scan_dict(groups=[])
        )

        result = runner.invoke(
            main, ["diff", "--json", str(baseline), str(current)]
        )

        assert result.exit_code == 0
        # No text-format markers leaked into JSON output
        assert "═══ Diff:" not in result.output
        assert "Summary\n" not in result.output


class TestCliDiffQuiet:
    """--quiet suppresses empty change-class sections in text mode."""

    def test_cli_diff_quiet(self, runner, tmp_path):
        baseline = _write_scan(
            tmp_path, "baseline.json", _scan_dict(groups=[])
        )
        current = _write_scan(
            tmp_path, "current.json", _scan_dict(groups=[])
        )

        verbose = runner.invoke(
            main, ["diff", str(baseline), str(current)]
        )
        quiet = runner.invoke(
            main, ["diff", "--quiet", str(baseline), str(current)]
        )

        assert verbose.exit_code == 0
        assert quiet.exit_code == 0

        # Empty section headers visible in verbose output
        assert "Group changes" in verbose.output
        assert "Status changes" in verbose.output
        assert "Artifact changes" in verbose.output

        # But suppressed in quiet output
        assert "Group changes" not in quiet.output
        assert "Status changes" not in quiet.output
        assert "Artifact changes" not in quiet.output

        # Summary always present in both
        assert "Summary" in verbose.output
        assert "Summary" in quiet.output

    def test_cli_diff_quiet_no_effect_on_json(self, runner, tmp_path):
        """--quiet on --json must not alter the JSON output."""
        baseline = _write_scan(
            tmp_path, "baseline.json", _scan_dict(groups=[])
        )
        current = _write_scan(
            tmp_path, "current.json", _scan_dict(groups=[])
        )

        json_only = runner.invoke(
            main, ["diff", "--json", str(baseline), str(current)]
        )
        json_quiet = runner.invoke(
            main,
            [
                "diff",
                "--json",
                "--quiet",
                str(baseline),
                str(current),
            ],
        )

        assert json_only.exit_code == 0
        assert json_quiet.exit_code == 0
        # Byte-identical JSON output regardless of --quiet
        assert json_only.output == json_quiet.output


# ════════════════════════════════════════════════════════════════════
# Exit-code precedence (DIFF_SPEC §exit-codes)
# ════════════════════════════════════════════════════════════════════


class TestCliDiffEmptyExitZero:
    """Two identical scans → exit 0, regardless of flags."""

    def test_cli_diff_empty_exit_zero(self, runner, tmp_path):
        baseline = _write_scan(
            tmp_path, "baseline.json", _scan_dict(groups=[])
        )
        current = _write_scan(
            tmp_path, "current.json", _scan_dict(groups=[])
        )

        result = runner.invoke(
            main, ["diff", str(baseline), str(current)]
        )
        assert result.exit_code == 0

    def test_cli_diff_empty_with_exit_code_flag_still_zero(
        self, runner, tmp_path
    ):
        """No changes + --exit-code → still exit 0 (no changes to flag)."""
        baseline = _write_scan(
            tmp_path, "baseline.json", _scan_dict(groups=[])
        )
        current = _write_scan(
            tmp_path, "current.json", _scan_dict(groups=[])
        )

        result = runner.invoke(
            main,
            ["diff", "--exit-code", str(baseline), str(current)],
        )
        assert result.exit_code == 0


class TestCliDiffChangeExitZeroWithoutFlags:
    """
    Inspection-first default: changes detected but no flags set →
    exit 0. The user gets the diff for review without the command
    pretending it's an error condition.
    """

    def test_cli_diff_change_exit_zero_without_flags(
        self, runner, tmp_path
    ):
        baseline = _write_scan(
            tmp_path,
            "baseline.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="verified"),
                ]
            ),
        )
        current = _write_scan(
            tmp_path,
            "current.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="unknown_variant"),
                ]
            ),
        )

        result = runner.invoke(
            main, ["diff", str(baseline), str(current)]
        )

        # Status regression detected, but no flags → exit 0
        assert result.exit_code == 0
        # And the regression is visible in the output
        assert "regression" in result.output


class TestCliDiffExitCodeAnyChange:
    """--exit-code makes any change exit 1."""

    def test_cli_diff_exit_code_any_change(self, runner, tmp_path):
        baseline = _write_scan(
            tmp_path, "baseline.json", _scan_dict(groups=[])
        )
        current = _write_scan(
            tmp_path,
            "current.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/new", status="verified"),
                ]
            ),
        )

        result = runner.invoke(
            main,
            ["diff", "--exit-code", str(baseline), str(current)],
        )
        # group_added counts as a change → exit 1
        assert result.exit_code == 1

    def test_cli_diff_exit_code_artifact_change_exit_one(
        self, runner, tmp_path
    ):
        """An artifact_changed entry without status regression also triggers."""
        baseline = _write_scan(
            tmp_path,
            "baseline.json",
            _scan_dict(
                groups=[
                    _group(
                        group_id="org/m",
                        status="verified",
                        artifacts=[
                            _artifact(
                                filename="m.safetensors",
                                sha256="a" * 64,
                            )
                        ],
                    ),
                ]
            ),
        )
        current = _write_scan(
            tmp_path,
            "current.json",
            _scan_dict(
                groups=[
                    _group(
                        group_id="org/m",
                        status="verified",  # still verified
                        artifacts=[
                            _artifact(
                                filename="m.safetensors",
                                sha256="b" * 64,
                            )
                        ],
                    ),
                ]
            ),
        )

        result = runner.invoke(
            main,
            ["diff", "--exit-code", str(baseline), str(current)],
        )
        # No regression but artifact_changed exists → exit 1
        assert result.exit_code == 1


class TestCliDiffExitCodeStatusRegression:
    """--exit-code-on-status-regression makes a regression exit 2."""

    def test_cli_diff_exit_code_status_regression(
        self, runner, tmp_path
    ):
        baseline = _write_scan(
            tmp_path,
            "baseline.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="verified"),
                ]
            ),
        )
        current = _write_scan(
            tmp_path,
            "current.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="unknown_variant"),
                ]
            ),
        )

        result = runner.invoke(
            main,
            [
                "diff",
                "--exit-code-on-status-regression",
                str(baseline),
                str(current),
            ],
        )
        assert result.exit_code == 2


class TestCliDiffExitCodePrecedenceRegressionOverGeneric:
    """
    When BOTH --exit-code and --exit-code-on-status-regression are
    set AND a regression exists, exit 2 wins (more specific).
    """

    def test_cli_diff_exit_code_precedence_regression_over_generic(
        self, runner, tmp_path
    ):
        baseline = _write_scan(
            tmp_path,
            "baseline.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="verified"),
                ]
            ),
        )
        current = _write_scan(
            tmp_path,
            "current.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="unknown_variant"),
                ]
            ),
        )

        result = runner.invoke(
            main,
            [
                "diff",
                "--exit-code",
                "--exit-code-on-status-regression",
                str(baseline),
                str(current),
            ],
        )
        # Both flags set + regression exists → exit 2 (not 1)
        assert result.exit_code == 2


class TestCliDiffNonRegressionWithRegressionFlag:
    """
    --exit-code-on-status-regression set BUT no regression exists
    (only an improvement, lateral, or non-status change) → exit 0.

    The flag only fires on actual regressions. An improvement does
    NOT count.
    """

    def test_cli_diff_non_regression_with_regression_flag_exit_zero(
        self, runner, tmp_path
    ):
        baseline = _write_scan(
            tmp_path,
            "baseline.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="not_enrolled"),
                ]
            ),
        )
        current = _write_scan(
            tmp_path,
            "current.json",
            _scan_dict(
                groups=[
                    _group(
                        group_id="org/m",
                        status="verified",  # improvement, not regression
                    ),
                ]
            ),
        )

        result = runner.invoke(
            main,
            [
                "diff",
                "--exit-code-on-status-regression",
                str(baseline),
                str(current),
            ],
        )
        # Status changed (improvement), but no regression → exit 0
        assert result.exit_code == 0
        # And the improvement is visible
        assert "improvement" in result.output

    def test_cli_diff_non_regression_with_both_flags_exits_one(
        self, runner, tmp_path
    ):
        """
        Defensive: when both flags are set and a non-regression
        change exists (e.g., improvement), --exit-code still fires
        with exit 1. The regression flag had no regression to fire
        on; the generic flag fires on the improvement.
        """
        baseline = _write_scan(
            tmp_path,
            "baseline.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="not_enrolled"),
                ]
            ),
        )
        current = _write_scan(
            tmp_path,
            "current.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="verified"),
                ]
            ),
        )

        result = runner.invoke(
            main,
            [
                "diff",
                "--exit-code",
                "--exit-code-on-status-regression",
                str(baseline),
                str(current),
            ],
        )
        # No regression to trip the 2; improvement trips --exit-code → 1
        assert result.exit_code == 1


# ════════════════════════════════════════════════════════════════════
# Error codes (DIFF_SPEC §exit-codes 64/65/66)
# ════════════════════════════════════════════════════════════════════


class TestCliDiffFileNotFound:
    """exit 64 on missing file (either side)."""

    def test_cli_diff_file_not_found_exit_64(self, runner, tmp_path):
        # Baseline doesn't exist
        result = runner.invoke(
            main,
            [
                "diff",
                str(tmp_path / "does-not-exist.json"),
                str(tmp_path / "current.json"),
            ],
        )
        assert result.exit_code == 64

    def test_cli_diff_current_not_found_exit_64(self, runner, tmp_path):
        baseline = _write_scan(
            tmp_path, "baseline.json", _scan_dict(groups=[])
        )
        result = runner.invoke(
            main,
            [
                "diff",
                str(baseline),
                str(tmp_path / "does-not-exist.json"),
            ],
        )
        assert result.exit_code == 64


class TestCliDiffMalformedJson:
    """exit 64 on malformed JSON in either scan file."""

    def test_cli_diff_malformed_json_exit_64(self, runner, tmp_path):
        baseline = tmp_path / "baseline.json"
        baseline.write_text("this is not json at all", encoding="utf-8")
        current = _write_scan(
            tmp_path, "current.json", _scan_dict(groups=[])
        )

        result = runner.invoke(
            main, ["diff", str(baseline), str(current)]
        )
        assert result.exit_code == 64

    def test_cli_diff_truncated_json_exit_64(self, runner, tmp_path):
        """A JSON file truncated mid-object also triggers 64."""
        baseline = tmp_path / "baseline.json"
        # Truncated JSON (closing brace missing)
        baseline.write_text('{"groups": []', encoding="utf-8")
        current = _write_scan(
            tmp_path, "current.json", _scan_dict(groups=[])
        )

        result = runner.invoke(
            main, ["diff", str(baseline), str(current)]
        )
        assert result.exit_code == 64


class TestCliDiffSchemaMismatch:
    """exit 65 on parseable JSON that's not a Trustfall Lite scan."""

    def test_cli_diff_schema_mismatch_exit_65(self, runner, tmp_path):
        # Valid JSON but missing required fields ('groups', 'summary')
        baseline = tmp_path / "baseline.json"
        baseline.write_text(
            json.dumps({"hello": "world"}), encoding="utf-8"
        )
        current = _write_scan(
            tmp_path, "current.json", _scan_dict(groups=[])
        )

        result = runner.invoke(
            main, ["diff", str(baseline), str(current)]
        )
        assert result.exit_code == 65

    def test_cli_diff_partial_schema_exit_65(self, runner, tmp_path):
        """A scan-shaped object missing 'summary' triggers 65."""
        baseline = tmp_path / "baseline.json"
        baseline.write_text(
            json.dumps({"groups": [], "trustfall_lite_version": __version__}),
            encoding="utf-8",
        )
        current = _write_scan(
            tmp_path, "current.json", _scan_dict(groups=[])
        )

        result = runner.invoke(
            main, ["diff", str(baseline), str(current)]
        )
        # Missing 'summary' field → not a valid scan
        assert result.exit_code == 65

    def test_cli_diff_top_level_array_exit_65(self, runner, tmp_path):
        """Valid JSON but an array, not an object → 65."""
        baseline = tmp_path / "baseline.json"
        baseline.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        current = _write_scan(
            tmp_path, "current.json", _scan_dict(groups=[])
        )

        result = runner.invoke(
            main, ["diff", str(baseline), str(current)]
        )
        assert result.exit_code == 65


class TestCliDiffMajorVersionMismatch:
    """exit 66 when scan major version is incompatible with the tool."""

    def test_cli_diff_major_version_mismatch_exit_66(
        self, runner, tmp_path
    ):
        # The tool is currently 0.x; pretend a baseline came from 1.x
        baseline = _write_scan(
            tmp_path,
            "baseline.json",
            _scan_dict(groups=[], version="1.0.0"),
        )
        current = _write_scan(
            tmp_path, "current.json", _scan_dict(groups=[])
        )

        result = runner.invoke(
            main, ["diff", str(baseline), str(current)]
        )
        assert result.exit_code == 66

    def test_cli_diff_minor_version_difference_does_not_trigger(
        self, runner, tmp_path
    ):
        """
        Different minor or patch versions are tolerated. Only major
        differs triggers 66.
        """
        # Construct a scan with same major but different minor version
        # (e.g., tool is 0.3.0 and baseline says 0.4.0 — same major 0)
        major = __version__.split(".")[0]
        baseline = _write_scan(
            tmp_path,
            "baseline.json",
            _scan_dict(groups=[], version=f"{major}.99.0"),
        )
        current = _write_scan(
            tmp_path, "current.json", _scan_dict(groups=[])
        )

        result = runner.invoke(
            main, ["diff", str(baseline), str(current)]
        )
        # No major mismatch → diff runs successfully
        assert result.exit_code == 0


class TestCliDiffErrorCodePrecedenceOverFlags:
    """
    Errors (64/65/66) win over the regression and generic-change
    flags. Pin this with a malformed file + flags set: still exits
    64, not 1 or 2.
    """

    def test_cli_diff_malformed_overrides_exit_code_flags(
        self, runner, tmp_path
    ):
        baseline = tmp_path / "baseline.json"
        baseline.write_text("garbage", encoding="utf-8")
        # Current is fine, but baseline is malformed
        current = _write_scan(
            tmp_path,
            "current.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="verified"),
                ]
            ),
        )

        result = runner.invoke(
            main,
            [
                "diff",
                "--exit-code",
                "--exit-code-on-status-regression",
                str(baseline),
                str(current),
            ],
        )
        # Error code wins over the flag-driven codes
        assert result.exit_code == 64


# ════════════════════════════════════════════════════════════════════
# Click option ordering (DIFF_SPEC §3 click option ordering)
# ════════════════════════════════════════════════════════════════════


class TestCliDiffClickOptionOrdering:
    """
    Per DIFF_SPEC §3 click option ordering: options may appear
    before, after, or interleaved with positional arguments.
    All orderings produce identical output.
    """

    def test_cli_diff_click_option_ordering(self, runner, tmp_path):
        baseline = _write_scan(
            tmp_path,
            "baseline.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="verified"),
                ]
            ),
        )
        current = _write_scan(
            tmp_path,
            "current.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="unknown_variant"),
                ]
            ),
        )

        # All four orderings of --json with positional arguments
        opts_first = runner.invoke(
            main, ["diff", "--json", str(baseline), str(current)]
        )
        opts_after = runner.invoke(
            main, ["diff", str(baseline), str(current), "--json"]
        )
        opts_between = runner.invoke(
            main, ["diff", str(baseline), "--json", str(current)]
        )

        # All succeed
        assert opts_first.exit_code == 0
        assert opts_after.exit_code == 0
        assert opts_between.exit_code == 0

        # All produce identical output
        assert opts_first.output == opts_after.output
        assert opts_first.output == opts_between.output

    def test_cli_diff_multiple_flags_any_order(self, runner, tmp_path):
        """--quiet and --exit-code can appear in any order."""
        baseline = _write_scan(
            tmp_path,
            "baseline.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="verified"),
                ]
            ),
        )
        current = _write_scan(
            tmp_path,
            "current.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="unknown_variant"),
                ]
            ),
        )

        result_a = runner.invoke(
            main,
            [
                "diff",
                "--quiet",
                "--exit-code",
                str(baseline),
                str(current),
            ],
        )
        result_b = runner.invoke(
            main,
            [
                "diff",
                "--exit-code",
                str(baseline),
                "--quiet",
                str(current),
            ],
        )

        # Both order variants produce same exit code and output
        assert result_a.exit_code == result_b.exit_code == 1
        assert result_a.output == result_b.output


# ════════════════════════════════════════════════════════════════════
# Help and discoverability
# ════════════════════════════════════════════════════════════════════


class TestCliDiffHelp:
    """The diff command appears in the main help and has its own help."""

    def test_diff_appears_in_main_help(self, runner):
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "diff" in result.output

    def test_diff_help_documents_all_flags(self, runner):
        result = runner.invoke(main, ["diff", "--help"])
        assert result.exit_code == 0
        assert "--json" in result.output
        assert "--quiet" in result.output
        assert "--exit-code" in result.output
        assert "--exit-code-on-status-regression" in result.output
        assert "BASELINE" in result.output
        assert "CURRENT" in result.output

    def test_diff_help_documents_exit_codes(self, runner):
        """Help text should document the exit-code precedence."""
        result = runner.invoke(main, ["diff", "--help"])
        assert result.exit_code == 0
        # Exit codes mentioned in help
        for code in ["0", "1", "2", "64", "65", "66"]:
            assert code in result.output


# ════════════════════════════════════════════════════════════════════
# Block 7: implicit-current-scan safety (DIFF_SPEC §3.5)
# ════════════════════════════════════════════════════════════════════
#
# Implicit-current form: `trustfall diff baseline.json` (with no
# CURRENT) runs a fresh default-scope scan in-process and diffs
# against the baseline. Allowed ONLY when the baseline used
# default-scope scan; refused with exit 64 otherwise.
#
# Tests use monkeypatch to stub _run_implicit_current_scan_or_die,
# so they never depend on the developer's actual HF/Ollama cache.


def _stub_implicit_scan(monkeypatch, return_dict: dict[str, Any]) -> None:
    """Replace _run_implicit_current_scan_or_die with a stub that
    returns the given dict. Use this in any Block 7 test that
    exercises the allowed-implicit-current path.
    """
    from fallrisk_trustfall import cli as cli_module

    monkeypatch.setattr(
        cli_module,
        "_run_implicit_current_scan_or_die",
        lambda: return_dict,
    )


class TestCliDiffImplicitCurrentDefaultBaseline:
    """
    Allowed path: baseline used default-scope scan (scan_paths==[]),
    implicit-current runs a fresh scan and produces a diff.
    """

    def test_cli_diff_implicit_current_default_baseline_runs_scan(
        self, runner, tmp_path, monkeypatch
    ):
        # Baseline: default-scope scan with one verified group
        baseline = _write_scan(
            tmp_path,
            "baseline.json",
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="verified"),
                ]
            ),  # scan_paths defaults to []
        )

        # Stub the implicit scan to return a regressed-state scan
        # of the same group
        stubbed_current = _scan_dict(
            groups=[
                _group(group_id="org/m", status="unknown_variant"),
            ]
        )
        _stub_implicit_scan(monkeypatch, stubbed_current)

        # Invoke with NO current argument
        result = runner.invoke(main, ["diff", str(baseline)])

        assert result.exit_code == 0
        # The diff actually ran and shows the regression
        assert "regression" in result.output
        assert "verified artifact" in result.output
        assert "unknown variant" in result.output


class TestCliDiffImplicitCurrentExplicitBaselineRefused:
    """
    Refused path: baseline used explicit paths (scan_paths is non-
    empty). Implicit-current would scan a different scope, so the
    command refuses with exit 64.
    """

    def test_cli_diff_implicit_current_explicit_baseline_refused_exit_64(
        self, runner, tmp_path
    ):
        # Build a baseline that includes literal explicit paths
        baseline_dict = _scan_dict(
            groups=[
                _group(group_id="org/m", status="verified"),
            ]
        )
        baseline_dict["scan_paths"] = [
            "/home/user/.cache/huggingface/hub"
        ]
        baseline_dict["include_paths"] = True
        baseline = _write_scan(tmp_path, "baseline.json", baseline_dict)

        # Implicit-current invocation
        result = runner.invoke(main, ["diff", str(baseline)])

        assert result.exit_code == 64
        # Refusal reason mentions explicit paths
        assert "explicit paths" in result.output

    def test_cli_diff_implicit_current_redacted_paths_refused_exit_64(
        self, runner, tmp_path
    ):
        """
        Privacy-redacted scan_paths (the placeholder string emitted
        when --include-paths was not set but explicit paths WERE
        given) is also a refusal. We can tell from the placeholder
        that the baseline was explicit-paths even though the literal
        paths are hidden.
        """
        baseline_dict = _scan_dict(
            groups=[
                _group(group_id="org/m", status="verified"),
            ]
        )
        # The exact placeholder format the live cli produces
        baseline_dict["scan_paths"] = [
            "<2 path(s) — pass --include-paths to surface>"
        ]
        baseline_dict["include_paths"] = False
        baseline = _write_scan(tmp_path, "baseline.json", baseline_dict)

        result = runner.invoke(main, ["diff", str(baseline)])
        assert result.exit_code == 64


class TestCliDiffImplicitCurrentMissingScanPaths:
    """
    Refused path: baseline JSON omits the scan_paths field entirely
    (legacy v0.2.x). Cannot prove safety — refuse.
    """

    def test_cli_diff_implicit_current_missing_scan_paths_refused_exit_64(
        self, runner, tmp_path
    ):
        # Hand-build a scan without scan_paths
        legacy_baseline = {
            "trustfall_lite_version": __version__,
            "include_paths": False,
            "trust_ollama_filenames": False,
            "summary": {
                "groups_scanned": 1,
                "artifacts_scanned": 1,
                "total_bytes": 1000,
            },
            "groups": [
                _group(group_id="org/m", status="verified"),
            ],
            # NB: no scan_paths field
        }
        baseline = tmp_path / "legacy-baseline.json"
        baseline.write_text(json.dumps(legacy_baseline), encoding="utf-8")

        result = runner.invoke(main, ["diff", str(baseline)])

        assert result.exit_code == 64
        # The refusal mentions the missing field semantically
        assert "scan_paths field" in result.output


class TestCliDiffImplicitCurrentErrorMessage:
    """
    The refusal message must be actionable. It tells the user
    exactly how to proceed (run an explicit scan and pass it).
    """

    def test_cli_diff_implicit_current_error_message_actionable(
        self, runner, tmp_path
    ):
        baseline_dict = _scan_dict(
            groups=[_group(group_id="org/m")],
        )
        baseline_dict["scan_paths"] = ["/some/path"]
        baseline_dict["include_paths"] = True
        baseline = _write_scan(tmp_path, "baseline.json", baseline_dict)

        result = runner.invoke(main, ["diff", str(baseline)])
        assert result.exit_code == 64

        # Error message contains the suggested commands
        assert "trustfall scan" in result.output
        assert "trustfall diff baseline.json current.json" in result.output
        # And the redirect / two-file pattern
        assert "current.json" in result.output


class TestCliDiffImplicitCurrentJsonOutput:
    """The --json flag works with implicit-current the same way
    as with explicit two-file."""

    def test_cli_diff_implicit_current_json_output(
        self, runner, tmp_path, monkeypatch
    ):
        baseline = _write_scan(
            tmp_path,
            "baseline.json",
            _scan_dict(
                groups=[_group(group_id="org/m", status="verified")]
            ),
        )

        # Stub: simulate a scan that finds the same group with a
        # regressed status
        _stub_implicit_scan(
            monkeypatch,
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="unknown_variant")
                ]
            ),
        )

        result = runner.invoke(
            main, ["diff", "--json", str(baseline)]
        )
        assert result.exit_code == 0

        # Output is valid JSON with the diff schema
        payload = json.loads(result.output)
        assert payload["schema_version"] == "0.3.0"
        assert payload["summary"]["status_changed"] == 1
        assert payload["summary"]["status_regressions"] == 1


class TestCliDiffImplicitCurrentExitCodeRules:
    """The same exit-code rules from Block 6 apply to implicit-current."""

    def test_cli_diff_implicit_current_exit_code_any_change(
        self, runner, tmp_path, monkeypatch
    ):
        """--exit-code with implicit-current and a real change → exit 1."""
        baseline = _write_scan(
            tmp_path,
            "baseline.json",
            _scan_dict(groups=[]),  # no groups in baseline
        )
        # Stub implicit scan to find a new group
        _stub_implicit_scan(
            monkeypatch,
            _scan_dict(
                groups=[_group(group_id="org/new", status="verified")]
            ),
        )

        result = runner.invoke(
            main, ["diff", "--exit-code", str(baseline)]
        )
        assert result.exit_code == 1

    def test_cli_diff_implicit_current_exit_code_regression(
        self, runner, tmp_path, monkeypatch
    ):
        """--exit-code-on-status-regression with regression → exit 2."""
        baseline = _write_scan(
            tmp_path,
            "baseline.json",
            _scan_dict(
                groups=[_group(group_id="org/m", status="verified")]
            ),
        )
        _stub_implicit_scan(
            monkeypatch,
            _scan_dict(
                groups=[
                    _group(group_id="org/m", status="unknown_variant")
                ]
            ),
        )

        result = runner.invoke(
            main,
            [
                "diff",
                "--exit-code-on-status-regression",
                str(baseline),
            ],
        )
        assert result.exit_code == 2

    def test_cli_diff_implicit_current_clean_exit_zero(
        self, runner, tmp_path, monkeypatch
    ):
        """No changes between baseline and stubbed current → exit 0."""
        same_groups = [_group(group_id="org/m", status="verified")]
        baseline = _write_scan(
            tmp_path, "baseline.json", _scan_dict(groups=same_groups)
        )
        _stub_implicit_scan(monkeypatch, _scan_dict(groups=same_groups))

        result = runner.invoke(
            main, ["diff", "--exit-code", str(baseline)]
        )
        assert result.exit_code == 0


class TestCliDiffImplicitCurrentNoStdin:
    """
    Defensive: implicit-current does NOT support stdin redirection
    of any kind. The dash form `-` is treated as a literal filename
    and (since no such file exists in tmp_path) errors out with 64
    via the file-not-found check, NOT consumed as a stdin signal.
    """

    def test_cli_diff_implicit_current_no_stdin(self, runner, tmp_path):
        """Treating '-' as baseline must NOT trigger stdin reading."""
        result = runner.invoke(main, ["diff", "-"])

        # '-' is an invalid baseline path → file not found → 64
        # (NOT exit 0 with an empty diff from stdin)
        assert result.exit_code == 64

    def test_cli_diff_explicit_dash_current_no_stdin(
        self, runner, tmp_path
    ):
        """A '-' for the CURRENT slot is also a literal filename."""
        baseline = _write_scan(
            tmp_path, "baseline.json", _scan_dict(groups=[])
        )

        result = runner.invoke(main, ["diff", str(baseline), "-"])

        # '-' as current → file not found → 64
        assert result.exit_code == 64


class TestCliDiffImplicitCurrentBaselineValidation:
    """
    Implicit-current must run baseline validation BEFORE the safety
    check. A malformed baseline cannot be used to determine safety —
    we exit 64 on the malformed JSON, not on the implicit-scan
    refusal. Either way it's exit 64 but the error message must be
    about the malformed file, not the implicit-current refusal.
    """

    def test_implicit_current_malformed_baseline_exits_64_on_parse(
        self, runner, tmp_path
    ):
        baseline = tmp_path / "baseline.json"
        baseline.write_text("garbage", encoding="utf-8")

        result = runner.invoke(main, ["diff", str(baseline)])

        assert result.exit_code == 64
        # Error names the parse failure, not the implicit-current refusal
        assert "not valid JSON" in result.output

    def test_implicit_current_schema_mismatch_baseline_exits_65(
        self, runner, tmp_path
    ):
        """A baseline that's parseable JSON but not a scan → exit 65,
        not 64. The schema-mismatch error wins over the implicit-
        current safety check (which never runs because the schema
        check fails first)."""
        baseline = tmp_path / "baseline.json"
        baseline.write_text(json.dumps({"hello": "world"}), encoding="utf-8")

        result = runner.invoke(main, ["diff", str(baseline)])
        assert result.exit_code == 65


class TestCliDiffImplicitCurrentPolicy:
    """
    Implicit-current policy lock: the fresh scan runs with the
    SAME defaults as `trustfall scan --json`, no diff-specific
    overrides.

    These tests are structural — they verify the wired-up entry
    point exists and is invoked. They do not exercise the actual
    scan orchestration (which depends on the developer's machine).
    """

    def test_implicit_current_helper_is_called(
        self, runner, tmp_path, monkeypatch
    ):
        """When implicit-current is allowed, the orchestration helper
        is invoked exactly once."""
        baseline = _write_scan(
            tmp_path, "baseline.json", _scan_dict(groups=[])
        )

        call_count = {"count": 0}

        def stub() -> dict[str, Any]:
            call_count["count"] += 1
            return _scan_dict(groups=[])

        from fallrisk_trustfall import cli as cli_module

        monkeypatch.setattr(
            cli_module, "_run_implicit_current_scan_or_die", stub
        )

        result = runner.invoke(main, ["diff", str(baseline)])
        assert result.exit_code == 0
        assert call_count["count"] == 1

    def test_implicit_current_helper_not_called_when_refused(
        self, runner, tmp_path, monkeypatch
    ):
        """When the baseline is non-default-scope, the orchestration
        helper is NEVER called — we refuse before scanning."""
        # Build an explicit-paths baseline
        baseline_dict = _scan_dict(
            groups=[_group(group_id="org/m")],
        )
        baseline_dict["scan_paths"] = ["/some/path"]
        baseline = _write_scan(tmp_path, "baseline.json", baseline_dict)

        call_count = {"count": 0}

        def stub() -> dict[str, Any]:
            call_count["count"] += 1
            return _scan_dict(groups=[])

        from fallrisk_trustfall import cli as cli_module

        monkeypatch.setattr(
            cli_module, "_run_implicit_current_scan_or_die", stub
        )

        result = runner.invoke(main, ["diff", str(baseline)])
        assert result.exit_code == 64
        # The implicit scan helper was NOT invoked — we refused first
        assert call_count["count"] == 0

    def test_implicit_current_helper_not_called_with_explicit_current(
        self, runner, tmp_path, monkeypatch
    ):
        """When CURRENT is provided explicitly, implicit scanning
        is not invoked — Block 6 path stays in effect."""
        baseline = _write_scan(
            tmp_path, "baseline.json", _scan_dict(groups=[])
        )
        current = _write_scan(
            tmp_path, "current.json", _scan_dict(groups=[])
        )

        call_count = {"count": 0}

        def stub() -> dict[str, Any]:
            call_count["count"] += 1
            return _scan_dict(groups=[])

        from fallrisk_trustfall import cli as cli_module

        monkeypatch.setattr(
            cli_module, "_run_implicit_current_scan_or_die", stub
        )

        result = runner.invoke(
            main, ["diff", str(baseline), str(current)]
        )
        assert result.exit_code == 0
        assert call_count["count"] == 0
