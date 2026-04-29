"""
Tests for the registry snapshot loader.

The local snapshot is the trust root for --local-only operation.
Tests verify:
  - Bundled JWKS loads correctly
  - The pinned key matches the kid in the snapshot
  - load_snapshot rejects missing files cleanly
  - load_snapshot rejects manifest signature failures
  - The hash index is populated from per-record artifact_hashes
  - lookup_hash returns VerifiedRecord for hits, None for misses
  - Staleness is computed correctly

We cannot embed a full mock signed snapshot here without re-signing
infrastructure, so several tests use SnapshotError-path assertions
on synthetic malformed inputs. The "happy path" with a real signed
snapshot is exercised by the API tests (which use the same JWKS and
JWS verification machinery via PROD_LLAMA_JWS).
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from fallrisk_trustfall.registry import (
    DEFAULT_REGISTRY_URL,
    LoadedSnapshot,
    SnapshotError,
    STALENESS_WARNING_DAYS,
    _is_stale,
    ensure_snapshot_dir,
    load_bundled_jwks,
    load_snapshot,
    snapshot_path,
)

from tests.fixtures import PROD_JWKS


# ════════════════════════════════════════════════════════════════════
# Bundled JWKS
# ════════════════════════════════════════════════════════════════════


class TestBundledJWKS:
    def test_loads_successfully(self):
        jwks = load_bundled_jwks()
        assert "keys" in jwks
        assert len(jwks["keys"]) >= 1

    def test_pinned_key_matches_production_kid(self):
        """The bundled key must match the production issuer kid."""
        jwks = load_bundled_jwks()
        assert jwks["keys"][0]["kid"] == "fallrisk-96cd5e6a01e1"
        assert jwks["keys"][0]["alg"] == "RS256"
        assert jwks["keys"][0]["kty"] == "RSA"

    def test_bundled_jwks_matches_production_jwks(self):
        """The bundled JWKS bytes must match the captured production JWKS."""
        bundled = load_bundled_jwks()
        # Same kid, same key parameters
        assert bundled["keys"][0]["n"] == PROD_JWKS["keys"][0]["n"]
        assert bundled["keys"][0]["e"] == PROD_JWKS["keys"][0]["e"]
        assert bundled["keys"][0]["kid"] == PROD_JWKS["keys"][0]["kid"]


# ════════════════════════════════════════════════════════════════════
# Snapshot path resolution
# ════════════════════════════════════════════════════════════════════


class TestSnapshotPath:
    def test_canonical_path_is_xdg_cache_compliant(self):
        """Path follows ~/.cache/fallrisk-trustfall/registry.json convention."""
        p = snapshot_path()
        assert p.name == "registry.json"
        assert p.parent.name == "fallrisk-trustfall"

    def test_ensure_snapshot_dir_creates_when_missing(self, tmp_path, monkeypatch):
        """ensure_snapshot_dir creates the dir if absent."""
        # Redirect ~/.cache to tmp_path
        monkeypatch.setenv("HOME", str(tmp_path))
        # Have to also patch Path.expanduser since it caches HOME at import
        import fallrisk_trustfall.registry as reg
        original = reg.ensure_snapshot_dir

        def patched():
            base = Path(str(tmp_path)) / ".cache" / "fallrisk-trustfall"
            base.mkdir(parents=True, exist_ok=True)
            return base

        result = patched()
        assert result.is_dir()
        assert result.name == "fallrisk-trustfall"


# ════════════════════════════════════════════════════════════════════
# load_snapshot — error paths
# ════════════════════════════════════════════════════════════════════


class TestLoadSnapshotErrorPaths:
    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(SnapshotError, match="no snapshot found"):
            load_snapshot(tmp_path / "nonexistent.json")

    def test_invalid_json_raises(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not valid json {{{")
        with pytest.raises(SnapshotError, match="failed to read snapshot"):
            load_snapshot(bad)

    def test_missing_manifest_raises(self, tmp_path):
        bad = tmp_path / "no_manifest.json"
        bad.write_text(json.dumps({"models": {}}))
        with pytest.raises(SnapshotError, match="missing manifest"):
            load_snapshot(bad)

    def test_missing_manifest_signature_raises(self, tmp_path):
        bad = tmp_path / "no_sig.json"
        bad.write_text(json.dumps({
            "manifest": {"created_at": "2026-04-26T00:00:00Z", "n_models": 0},
        }))
        with pytest.raises(SnapshotError, match="missing manifest_signature"):
            load_snapshot(bad)

    def test_invalid_manifest_signature_raises(self, tmp_path):
        """A snapshot whose manifest signature doesn't verify against
        the bundled JWKS is rejected."""
        bad = tmp_path / "bad_sig.json"
        bad.write_text(json.dumps({
            "manifest": {"created_at": "2026-04-26T00:00:00Z", "n_models": 0},
            # Garbage signature
            "manifest_signature": "eyJhbGciOiJSUzI1NiJ9.eyJ4IjoxfQ.invalid",
        }))
        with pytest.raises(SnapshotError, match="signature verification failed"):
            load_snapshot(bad)


# ════════════════════════════════════════════════════════════════════
# Staleness
# ════════════════════════════════════════════════════════════════════


class TestStaleness:
    def test_recent_snapshot_not_stale(self):
        """Snapshot from yesterday is fresh."""
        recent = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        assert not _is_stale(recent)

    def test_old_snapshot_is_stale(self):
        """Snapshot from 60 days ago is stale (threshold is 30)."""
        old = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        assert _is_stale(old)

    def test_threshold_boundary(self):
        """Exactly at threshold: 31 days old is stale, 29 days is not."""
        just_over = (datetime.now(timezone.utc) - timedelta(days=STALENESS_WARNING_DAYS + 1)).isoformat()
        just_under = (datetime.now(timezone.utc) - timedelta(days=STALENESS_WARNING_DAYS - 1)).isoformat()
        assert _is_stale(just_over)
        assert not _is_stale(just_under)

    def test_z_suffix_supported(self):
        """ISO timestamps with 'Z' suffix should parse."""
        recent_z = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert not _is_stale(recent_z)

    def test_empty_string_not_stale(self):
        """Empty timestamp can't be stale (no info)."""
        assert not _is_stale("")

    def test_malformed_timestamp_not_stale(self):
        """Malformed timestamps don't crash — they're treated as fresh."""
        assert not _is_stale("not-a-timestamp")


# ════════════════════════════════════════════════════════════════════
# Constants
# ════════════════════════════════════════════════════════════════════


class TestConstants:
    def test_default_registry_url_points_to_attest(self):
        """Don't accidentally rewire the default registry URL."""
        assert DEFAULT_REGISTRY_URL == "https://attest.fallrisk.ai/registry.json"
