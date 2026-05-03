"""
Tests for the Click-based CLI surface.

CLI tests use Click's test runner. We verify:
  - Each command parses and runs end-to-end against test fixtures
  - Exit codes are correct (0 on success, 2 on missing snapshot etc.)
  - JSON output is valid JSON with the spec §8 schema
  - The fingerprint output is deterministic and matches the
    documented value (sha256:FlqonYO...)
"""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from fallrisk_trustfall.cli import main
from fallrisk_trustfall import __version__


@pytest.fixture
def runner():
    return CliRunner()


# ════════════════════════════════════════════════════════════════════
# trustfall version
# ════════════════════════════════════════════════════════════════════


class TestVersionCommand:
    def test_runs_successfully(self, runner):
        result = runner.invoke(main, ["version"])
        assert result.exit_code == 0
        assert "trustfall-lite" in result.output
        assert __version__ in result.output

    def test_shows_issuer_kid(self, runner):
        result = runner.invoke(main, ["version"])
        assert "fallrisk-96cd5e6a01e1" in result.output


# ════════════════════════════════════════════════════════════════════
# trustfall registry
# ════════════════════════════════════════════════════════════════════


class TestRegistryCommand:
    def test_fingerprint_is_deterministic(self, runner):
        """The RFC 7638 thumbprint of the bundled key is reproducible."""
        result = runner.invoke(main, ["registry", "--fingerprint"])
        assert result.exit_code == 0
        # The documented fingerprint from the API docs page
        assert "sha256:FlqonYOsEwXi5eaLuhjMKmHzbKxtM0MrM7yGg2xW-2M" in result.output

    def test_fingerprint_includes_issuer_and_kid(self, runner):
        result = runner.invoke(main, ["registry", "--fingerprint"])
        assert "issuer: https://attest.fallrisk.ai" in result.output
        assert "kid: fallrisk-96cd5e6a01e1" in result.output

    def test_info_with_no_snapshot_explains_how_to_fix(self, runner, tmp_path, monkeypatch):
        """When no snapshot exists, --info gives actionable guidance."""
        # Redirect to a temp HOME so this doesn't read the user's real snapshot
        monkeypatch.setenv("HOME", str(tmp_path))
        result = runner.invoke(main, ["registry", "--info"])
        assert result.exit_code == 0
        assert "trustfall registry --refresh" in result.output

    def test_info_is_default_with_no_flags(self, runner, tmp_path, monkeypatch):
        """Default behavior of `trustfall registry` is --info per spec §4."""
        monkeypatch.setenv("HOME", str(tmp_path))
        result = runner.invoke(main, ["registry"])
        assert result.exit_code == 0
        assert "trustfall registry --refresh" in result.output


# ════════════════════════════════════════════════════════════════════
# trustfall verify HASH
# ════════════════════════════════════════════════════════════════════


class TestVerifyCommand:
    def test_malformed_hash_returns_error_exit_code(self, runner):
        """A malformed hash should error out cleanly without hitting the network."""
        result = runner.invoke(main, ["verify", "not-a-valid-hash"])
        # Exit code 2 = error per CLI convention
        assert result.exit_code == 2

    def test_json_output_for_malformed_hash_is_valid_json(self, runner):
        result = runner.invoke(main, ["verify", "not-a-hash", "--json"])
        # Must be valid JSON even on error
        parsed = json.loads(result.output)
        assert parsed["status"] == "error"
        assert "error_message" in parsed


# ════════════════════════════════════════════════════════════════════
# trustfall scan
# ════════════════════════════════════════════════════════════════════


@pytest.fixture
def scan_fixture(tmp_path: Path) -> Path:
    """Build a small directory with weights files for scanning."""
    base = tmp_path / "models"
    base.mkdir()
    (base / "model.safetensors").write_bytes(b"some weights")
    (base / "config.json").write_text("{}")
    return base


class TestScanCommand:
    def test_scan_with_no_snapshot_falls_back_helpfully(self, runner, scan_fixture, tmp_path, monkeypatch):
        """
        Without network and without a snapshot, scan should fall back
        gracefully. Exit code is non-zero (we couldn't actually verify
        anything) but the output should explain what to do.
        """
        # Redirect HOME so no real snapshot is present
        monkeypatch.setenv("HOME", str(tmp_path))
        # Use --local-only to avoid the network attempt
        result = runner.invoke(main, ["scan", str(scan_fixture), "--local-only"])
        # Exit 2 because no snapshot
        assert result.exit_code == 2
        # The message should tell the user how to fix it
        assert "trustfall registry --refresh" in result.output

    def test_scan_with_no_artifacts_exits_zero_with_message(self, runner, tmp_path, monkeypatch):
        """An empty directory shouldn't crash — should print 'no artifacts found'."""
        monkeypatch.setenv("HOME", str(tmp_path))
        empty = tmp_path / "empty"
        empty.mkdir()
        result = runner.invoke(main, ["scan", str(empty), "--local-only"])
        assert result.exit_code == 0
        assert "No model artifacts found" in result.output

    def test_scan_help_lists_all_flags(self, runner):
        """All spec §4 flags must be in the help text."""
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        for flag in ["--local-only", "--include-paths", "--json", "--quiet"]:
            assert flag in result.output

    def test_scan_help_includes_trust_ollama_filenames_flag(self, runner):
        """v0.2: --trust-ollama-filenames flag must be discoverable in --help."""
        result = runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--trust-ollama-filenames" in result.output


# ════════════════════════════════════════════════════════════════════
# v0.2 CLI integration tests
# ════════════════════════════════════════════════════════════════════


@pytest.fixture
def ollama_fixture(tmp_path: Path) -> Path:
    """
    Build a minimal Ollama models/ root with one library/test:tag manifest
    pointing at a real blob whose filename matches the expected
    sha256-<hex> shape. Used to exercise the Ollama scan path end-to-end.
    """
    root = tmp_path / "ollama"
    blobs = root / "blobs"
    manifests = root / "manifests" / "registry.ollama.ai" / "library" / "test"
    blobs.mkdir(parents=True)
    manifests.mkdir(parents=True)

    # Write a real blob at the expected content-addressed filename.
    # Compute its real sha256 so the filename is honest.
    import hashlib
    content = b"fake model weights for cli test"
    digest = hashlib.sha256(content).hexdigest()
    (blobs / f"sha256-{digest}").write_bytes(content)

    # Manifest references that blob as the model layer
    manifest = {
        "schemaVersion": 2,
        "config": {"digest": "sha256:" + "0" * 64, "size": 100},
        "layers": [
            {
                "mediaType": "application/vnd.ollama.image.model",
                "digest": f"sha256:{digest}",
                "size": len(content),
            }
        ],
    }
    (manifests / "tag1").write_text(json.dumps(manifest))
    return root


class TestScanV2OllamaIntegration:
    """v0.2: end-to-end Ollama scan path."""

    def test_scan_explicit_ollama_path_discovers_groups(
        self, runner, ollama_fixture, tmp_path, monkeypatch
    ):
        """Pointing scan at an Ollama models/ root should discover Ollama groups."""
        monkeypatch.setenv("HOME", str(tmp_path))
        result = runner.invoke(
            main, ["scan", str(ollama_fixture), "--local-only", "--json"]
        )
        # Will exit 2 because no snapshot, but JSON discovery happens before lookup
        # The error path goes through _build_local_lookup_or_die which prints to stderr
        # before the JSON renderer is reached. So we check via text mode instead.
        result = runner.invoke(
            main, ["scan", str(ollama_fixture), "--local-only"]
        )
        # Either exit 2 (no snapshot) or 0 (found nothing). Either way, output
        # should report that a group was discovered. We assert on the discovery
        # behavior (group count > 0), not on path-string content, because path
        # rendering differs between POSIX and Windows.
        assert "discovered 1 model group" in result.output.lower() or "discovered 1 model group(s)" in result.output.lower()

    def test_scan_json_includes_v2_schema_fields_for_ollama(
        self, runner, ollama_fixture, tmp_path, monkeypatch, mocker
    ):
        """
        Per Silent Renderer Bug Doctrine: every v0.2 schema field must be
        present in the JSON output when Ollama groups are scanned. Tests
        for PRESENCE, not just value correctness.
        """
        monkeypatch.setenv("HOME", str(tmp_path))
        # Mock the local lookup so we don't need a real snapshot
        from fallrisk_trustfall.api import APILookupResult

        def fake_lookup(self, sha256s):
            return {h: APILookupResult(sha256=h, status="not_enrolled") for h in sha256s}

        mocker.patch(
            "fallrisk_trustfall.cli._build_local_lookup_or_die",
            return_value=mocker.Mock(lookup_many=lambda hashes: {
                h: APILookupResult(sha256=h, status="not_enrolled") for h in hashes
            }),
        )

        result = runner.invoke(
            main,
            ["scan", str(ollama_fixture), "--local-only", "--json"],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)

        # Top-level v0.2 fields
        assert "trust_ollama_filenames" in data
        assert data["trust_ollama_filenames"] is False  # default

        # Summary v0.2 fields
        summary = data["summary"]
        assert "groups_scanned" in summary
        assert "artifacts_scanned" in summary
        assert "unique_artifacts_scanned" in summary
        assert "total_bytes" in summary
        assert "unique_bytes" in summary
        assert "sources" in summary
        # `files_scanned` legacy field is GONE in v0.2
        assert "files_scanned" not in summary

        # Sources breakdown for ollama
        assert "ollama" in summary["sources"]
        ollama_summary = summary["sources"]["ollama"]
        assert "groups_scanned" in ollama_summary
        assert "artifacts_scanned" in ollama_summary
        assert "total_bytes" in ollama_summary

        # Group-level v0.2 fields
        assert len(data["groups"]) == 1
        group = data["groups"][0]
        assert group["source"] == "ollama"
        assert group["claim_source"] == "ollama_manifest"
        # Ollama-specific fields
        assert "ollama_namespace" in group
        assert "ollama_name" in group
        assert "ollama_tag" in group
        assert group["ollama_name"] == "test"
        assert group["ollama_tag"] == "tag1"

        # Per-artifact v0.2 fields
        artifact = group["artifacts"][0]
        assert "digest_verified" in artifact
        assert "digest_source" in artifact
        assert "media_type" in artifact
        # Default mode: content_hash, verified=true
        assert artifact["digest_verified"] is True
        assert artifact["digest_source"] == "content_hash"
        assert artifact["media_type"] == "application/vnd.ollama.image.model"

    def test_scan_with_trust_ollama_filenames_records_filename_mode(
        self, runner, ollama_fixture, tmp_path, monkeypatch, mocker
    ):
        """When --trust-ollama-filenames is on, JSON records the fast-path mode."""
        monkeypatch.setenv("HOME", str(tmp_path))
        from fallrisk_trustfall.api import APILookupResult

        mocker.patch(
            "fallrisk_trustfall.cli._build_local_lookup_or_die",
            return_value=mocker.Mock(lookup_many=lambda hashes: {
                h: APILookupResult(sha256=h, status="not_enrolled") for h in hashes
            }),
        )

        result = runner.invoke(
            main,
            [
                "scan",
                str(ollama_fixture),
                "--local-only",
                "--json",
                "--trust-ollama-filenames",
            ],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["trust_ollama_filenames"] is True
        artifact = data["groups"][0]["artifacts"][0]
        assert artifact["digest_verified"] is False
        assert artifact["digest_source"] == "ollama_blob_filename"


class TestScanV2PrivacyOfJsonOutput:
    """
    Per GPT review (April 27, 2026): when --include-paths is OFF (the
    default), the JSON output must not expose ANY local filesystem
    paths — including in `group_id`, which previously leaked the full
    path to the user's HF snapshot directory.

    Per Silent Renderer Bug Doctrine: assert absence of leaked paths
    explicitly. Future-Claude must not re-introduce path-as-id without
    breaking these tests.
    """

    def test_hf_cache_group_id_is_logical_not_path(
        self, runner, tmp_path, monkeypatch, mocker
    ):
        """HF cache group_id must be 'hf_cache:Org/Name:rev', not a filesystem path."""
        monkeypatch.setenv("HOME", str(tmp_path))
        # Build minimal HF cache fixture
        hf_root = tmp_path / "hf"
        snap_dir = (
            hf_root / "models--Org--Model" / "snapshots" / "abc123def456"
        )
        snap_dir.mkdir(parents=True)
        (snap_dir / "model.safetensors").write_bytes(b"fake weights")

        from fallrisk_trustfall.api import APILookupResult

        mocker.patch(
            "fallrisk_trustfall.cli._build_local_lookup_or_die",
            return_value=mocker.Mock(lookup_many=lambda hashes: {
                h: APILookupResult(sha256=h, status="not_enrolled") for h in hashes
            }),
        )

        result = runner.invoke(
            main, ["scan", str(hf_root), "--local-only", "--json"]
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert len(data["groups"]) == 1
        gid = data["groups"][0]["group_id"]
        # Stable logical form
        assert gid == "hf_cache:Org/Model:abc123def456"
        # Negative assertion: no local filesystem path leakage
        assert str(tmp_path) not in gid
        assert "/snapshots/" not in gid
        assert not gid.startswith("/")

    def test_no_user_paths_anywhere_in_default_json(
        self, runner, tmp_path, monkeypatch, mocker
    ):
        """
        Holistic check: serialize the full JSON output as a string and
        scan it for any sign of the test's home directory. Catches
        regressions where any future field starts emitting a raw path.
        """
        monkeypatch.setenv("HOME", str(tmp_path))
        # Build both an HF cache and an Ollama fixture under tmp_path
        hf_root = tmp_path / "hf"
        snap_dir = hf_root / "models--Org--Model" / "snapshots" / "rev123"
        snap_dir.mkdir(parents=True)
        (snap_dir / "model.safetensors").write_bytes(b"fake")

        ol_root = tmp_path / "ol"
        blobs = ol_root / "blobs"
        manifests = ol_root / "manifests" / "registry.ollama.ai" / "library" / "x"
        blobs.mkdir(parents=True)
        manifests.mkdir(parents=True)
        import hashlib
        c = b"ollama fake"
        d = hashlib.sha256(c).hexdigest()
        (blobs / f"sha256-{d}").write_bytes(c)
        (manifests / "y").write_text(json.dumps({
            "schemaVersion": 2,
            "config": {"digest": "sha256:" + "0" * 64, "size": 100},
            "layers": [{
                "mediaType": "application/vnd.ollama.image.model",
                "digest": f"sha256:{d}",
                "size": len(c),
            }],
        }))

        from fallrisk_trustfall.api import APILookupResult

        mocker.patch(
            "fallrisk_trustfall.cli._build_local_lookup_or_die",
            return_value=mocker.Mock(lookup_many=lambda hashes: {
                h: APILookupResult(sha256=h, status="not_enrolled") for h in hashes
            }),
        )

        result = runner.invoke(
            main,
            ["scan", str(hf_root), str(ol_root), "--local-only", "--json"],
        )
        assert result.exit_code == 0, result.output
        # Holistic assertion: tmp_path's full string must not appear
        # ANYWHERE in the JSON output unless include_paths is on.
        # This catches any field that future-Claude might add that
        # accidentally surfaces the path.
        assert str(tmp_path) not in result.output, (
            f"local path leaked in default JSON output: {result.output[:1000]}"
        )

    def test_include_paths_does_surface_paths(
        self, runner, tmp_path, monkeypatch, mocker
    ):
        """
        Sanity check: --include-paths is the explicit opt-in for path
        exposure. The artifact path field IS allowed to appear when
        the user passes the flag.
        """
        monkeypatch.setenv("HOME", str(tmp_path))
        hf_root = tmp_path / "hf"
        snap_dir = hf_root / "models--Org--Model" / "snapshots" / "rev"
        snap_dir.mkdir(parents=True)
        (snap_dir / "model.safetensors").write_bytes(b"x")

        from fallrisk_trustfall.api import APILookupResult

        mocker.patch(
            "fallrisk_trustfall.cli._build_local_lookup_or_die",
            return_value=mocker.Mock(lookup_many=lambda hashes: {
                h: APILookupResult(sha256=h, status="not_enrolled") for h in hashes
            }),
        )

        result = runner.invoke(
            main,
            ["scan", str(hf_root), "--local-only", "--json", "--include-paths"],
        )
        data = json.loads(result.output)
        # When opted in, artifact.path is present and contains the real path
        artifact = data["groups"][0]["artifacts"][0]
        assert "path" in artifact
        # Even with include-paths, group_id is still the stable logical form,
        # not a filesystem path. The path goes ONLY in artifact.path.
        assert data["groups"][0]["group_id"] == "hf_cache:Org/Model:rev"


class TestScanV2OllamaUnknownVariantWording:
    """
    Per GPT review: Ollama unknown_variant wording must NOT imply
    a missing-but-expected registry record. Use Ollama-specific
    framing instead.
    """

    def test_ollama_unknown_variant_uses_capital_ollama(
        self, runner, ollama_fixture, tmp_path, monkeypatch, mocker
    ):
        """The label is 'Ollama manifest' not 'ollama manifest'."""
        monkeypatch.setenv("HOME", str(tmp_path))
        from fallrisk_trustfall.api import APILookupResult

        mocker.patch(
            "fallrisk_trustfall.cli._build_local_lookup_or_die",
            return_value=mocker.Mock(lookup_many=lambda hashes: {
                h: APILookupResult(sha256=h, status="not_enrolled") for h in hashes
            }),
        )

        result = runner.invoke(main, ["scan", str(ollama_fixture), "--local-only"])
        assert result.exit_code == 0
        # Capitalized label
        assert "claimed by Ollama manifest" in result.output
        # NOT lowercase
        assert "claimed by ollama manifest" not in result.output

    def test_ollama_unknown_variant_uses_correct_explanation(
        self, runner, ollama_fixture, tmp_path, monkeypatch, mocker
    ):
        """
        The Ollama explanation should NOT use the HF wording about
        'hash does not match signed registry record', because for
        Ollama the registry typically has no canonical record at all.
        """
        monkeypatch.setenv("HOME", str(tmp_path))
        from fallrisk_trustfall.api import APILookupResult

        mocker.patch(
            "fallrisk_trustfall.cli._build_local_lookup_or_die",
            return_value=mocker.Mock(lookup_many=lambda hashes: {
                h: APILookupResult(sha256=h, status="not_enrolled") for h in hashes
            }),
        )

        result = runner.invoke(main, ["scan", str(ollama_fixture), "--local-only"])
        # New, correct wording
        assert "model blob digest is not in the signed Fall Risk registry" in result.output
        assert (
            "Ollama quantization, custom Modelfile, adapter, conversion, "
            "or unenrolled artifact"
        ) in result.output


class TestScanV2SourceGroupedOutput:
    """v0.2: human-readable output is split by source with global summary."""

    def test_text_output_has_section_headers(
        self, runner, ollama_fixture, tmp_path, monkeypatch, mocker
    ):
        """Section headers and underlines are present."""
        monkeypatch.setenv("HOME", str(tmp_path))
        from fallrisk_trustfall.api import APILookupResult

        mocker.patch(
            "fallrisk_trustfall.cli._build_local_lookup_or_die",
            return_value=mocker.Mock(lookup_many=lambda hashes: {
                h: APILookupResult(sha256=h, status="not_enrolled") for h in hashes
            }),
        )

        result = runner.invoke(main, ["scan", str(ollama_fixture), "--local-only"])
        assert result.exit_code == 0, result.output
        # Section header for Ollama
        assert "Ollama store" in result.output
        # Global summary at bottom
        assert "Global summary" in result.output

    def test_ollama_detection_notice_below_threshold_not_shown(
        self, runner, ollama_fixture, tmp_path, monkeypatch, mocker
    ):
        """Tiny Ollama installs (< 30 GB) do not get the up-front notice."""
        monkeypatch.setenv("HOME", str(tmp_path))
        from fallrisk_trustfall.api import APILookupResult

        mocker.patch(
            "fallrisk_trustfall.cli._build_local_lookup_or_die",
            return_value=mocker.Mock(lookup_many=lambda hashes: {
                h: APILookupResult(sha256=h, status="not_enrolled") for h in hashes
            }),
        )

        result = runner.invoke(main, ["scan", str(ollama_fixture), "--local-only"])
        # Test fixture is < 30 GB by orders of magnitude — notice should NOT appear
        assert "verifies blob digests by default" not in result.output


# ════════════════════════════════════════════════════════════════════
# Top-level CLI
# ════════════════════════════════════════════════════════════════════


class TestTopLevelCLI:
    def test_help_lists_all_commands(self, runner):
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        for cmd in ["scan", "verify", "registry", "version"]:
            assert cmd in result.output

    def test_version_flag(self, runner):
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.output

    def test_unknown_command_errors(self, runner):
        result = runner.invoke(main, ["bogus-command"])
        assert result.exit_code != 0
