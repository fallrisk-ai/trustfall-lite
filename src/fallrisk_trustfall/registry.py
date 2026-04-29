"""
Local registry snapshot management.

The local snapshot lives at:
    ~/.cache/fallrisk-trustfall/registry.json

It is the cached copy of `https://attest.fallrisk.ai/registry.json`.
The CLI uses it for `--local-only` scans (zero network traffic) and
as a fallback when the API is unreachable.

The snapshot itself is signed by `fallrisk-96cd5e6a01e1`. We verify
the manifest signature on every load. A snapshot whose signature
does not validate against the bundled JWKS is rejected.

Per spec §A1 item 3: on first run with no local snapshot, the CLI
auto-fetches from `attest.fallrisk.ai/registry.json`. The fetching
is the responsibility of the CLI command layer, not this module.
This module provides:
    - load: read and verify a snapshot file
    - lookup: look up a SHA-256 in a loaded snapshot
    - paths: where snapshots live
    - bundled_jwks: load the pinned JWKS shipped with the package
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any

from jose import jws as jose_jws
from jose.exceptions import JOSEError

from .api import VerifiedRecord


SNAPSHOT_DIRNAME = "fallrisk-trustfall"
SNAPSHOT_FILENAME = "registry.json"
DEFAULT_REGISTRY_URL = "https://attest.fallrisk.ai/registry.json"

# Per spec §10: warn when the snapshot is older than this
STALENESS_WARNING_DAYS = 30


# ════════════════════════════════════════════════════════════════════
# Paths
# ════════════════════════════════════════════════════════════════════


def snapshot_path() -> Path:
    """Return the canonical local snapshot path."""
    base = Path("~/.cache").expanduser() / SNAPSHOT_DIRNAME
    return base / SNAPSHOT_FILENAME


def ensure_snapshot_dir() -> Path:
    """Create the snapshot directory if it doesn't exist; return the path."""
    base = Path("~/.cache").expanduser() / SNAPSHOT_DIRNAME
    base.mkdir(parents=True, exist_ok=True)
    return base


# ════════════════════════════════════════════════════════════════════
# Bundled JWKS
# ════════════════════════════════════════════════════════════════════


def load_bundled_jwks() -> dict[str, Any]:
    """
    Load the JWKS shipped with the package.

    The bundled key is the trust root for offline operation. Even
    when the CLI has refreshed a snapshot, signature verification
    is performed against this bundled key — never against keys
    fetched from the network. This prevents a hostile network from
    silently rotating the trust root.
    """
    pkg = resources.files("fallrisk_trustfall")
    text = pkg.joinpath("bundled_jwks.json").read_text(encoding="utf-8")
    return json.loads(text)


# ════════════════════════════════════════════════════════════════════
# Loaded snapshot
# ════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class LoadedSnapshot:
    """
    A signature-verified registry snapshot ready for lookups.

    Fields:
        path: filesystem location the snapshot was loaded from
        snapshot_at: ISO-8601 timestamp from the manifest
        kid: issuer kid found in the manifest
        manifest_digest: digest of the manifest content
        record_count: number of signed records in this snapshot
        records_by_hash: index from artifact SHA-256 → verified record claims
        records_by_model_id: index from model_id → verified record claims
        is_stale: True if older than STALENESS_WARNING_DAYS
    """

    path: Path
    snapshot_at: str
    kid: str
    manifest_digest: str
    record_count: int
    records_by_hash: dict[str, dict[str, Any]]
    records_by_model_id: dict[str, dict[str, Any]]
    records_by_hash_jws: dict[str, str]  # hash → record_jws (for offline reporting)
    is_stale: bool


class SnapshotError(Exception):
    """Raised on snapshot read, parse, or signature failure."""


# ════════════════════════════════════════════════════════════════════
# Loading
# ════════════════════════════════════════════════════════════════════


def load_snapshot(
    path: Path | None = None,
    jwks: dict[str, Any] | None = None,
) -> LoadedSnapshot:
    """
    Read a registry snapshot, verify the manifest signature, and build
    lookup indexes by hash and model_id.

    Args:
        path: snapshot file path (defaults to canonical location)
        jwks: JWKS to verify against (defaults to bundled)

    Returns:
        LoadedSnapshot with both indexes populated.

    Raises:
        SnapshotError on any read/parse/verification failure.
    """
    snap_path = path or snapshot_path()
    if not snap_path.is_file():
        raise SnapshotError(f"no snapshot found at {snap_path}")

    try:
        with snap_path.open("r", encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise SnapshotError(f"failed to read snapshot: {exc}") from exc

    jwks = jwks or load_bundled_jwks()

    manifest = doc.get("manifest")
    if not isinstance(manifest, dict):
        raise SnapshotError("snapshot missing manifest object")

    manifest_signature = doc.get("manifest_signature")
    if not isinstance(manifest_signature, str):
        raise SnapshotError("snapshot missing manifest_signature")

    # Verify the manifest signature against the bundled JWKS.
    try:
        jose_jws.verify(manifest_signature, jwks, algorithms=["RS256"])
    except JOSEError as exc:
        raise SnapshotError(
            f"snapshot manifest signature verification failed: {exc}"
        ) from exc

    snapshot_at = manifest.get("created_at") or manifest.get("snapshot_at") or ""
    kid = manifest.get("issuer_kid") or manifest.get("kid") or ""
    manifest_digest = manifest.get("manifest_digest", "")
    record_count = manifest.get("n_models") or manifest.get("model_count") or 0

    records_by_hash: dict[str, dict[str, Any]] = {}
    records_by_model_id: dict[str, dict[str, Any]] = {}
    records_by_hash_jws: dict[str, str] = {}

    models_obj = doc.get("models")
    if isinstance(models_obj, dict):
        # v0.2 shape: dict keyed by model_id, each entry has .record + .signature
        for model_id, entry in models_obj.items():
            if not isinstance(entry, dict):
                continue
            record_jws = entry.get("signature")
            record = entry.get("record")
            if not isinstance(record, dict) or not isinstance(record_jws, str):
                continue
            # Verify each per-record signature against bundled JWKS
            try:
                payload_bytes = jose_jws.verify(record_jws, jwks, algorithms=["RS256"])
                claims = json.loads(payload_bytes)
            except (JOSEError, json.JSONDecodeError, ValueError):
                continue  # skip records that don't verify
            records_by_model_id[model_id] = claims
            for h in _extract_artifact_hashes(claims, record):
                records_by_hash[h] = claims
                records_by_hash_jws[h] = record_jws

    return LoadedSnapshot(
        path=snap_path,
        snapshot_at=snapshot_at,
        kid=kid,
        manifest_digest=manifest_digest,
        record_count=record_count,
        records_by_hash=records_by_hash,
        records_by_model_id=records_by_model_id,
        records_by_hash_jws=records_by_hash_jws,
        is_stale=_is_stale(snapshot_at),
    )


# ════════════════════════════════════════════════════════════════════
# Lookups
# ════════════════════════════════════════════════════════════════════


def lookup_hash(snapshot: LoadedSnapshot, sha256: str) -> VerifiedRecord | None:
    """
    Look up a single hash in the local snapshot.

    Returns a VerifiedRecord if the hash is present, None otherwise.
    The returned VerifiedRecord uses the record_jws and claims from
    the snapshot — both of which were signature-verified during load.
    """
    claims = snapshot.records_by_hash.get(sha256)
    if claims is None:
        return None
    record_jws = snapshot.records_by_hash_jws.get(sha256, "")
    return VerifiedRecord(
        sha256=sha256,
        record_jws=record_jws,
        claims=claims,
        registry_kid=snapshot.kid,
        registry_snapshot_at=snapshot.snapshot_at,
    )


# ════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════


def _extract_artifact_hashes(
    claims: dict[str, Any], record: dict[str, Any]
) -> list[str]:
    """
    Pull artifact SHA-256s out of a verified record.

    v0.2 schema puts them in `artifact_hashes` as a list of objects
    with `sha256` fields. Falls back to `evidence_digest` if the
    artifact list is absent (some legacy records may not have it).
    """
    hashes: list[str] = []
    artifacts = claims.get("artifact_hashes") or record.get("artifact_hashes")
    if isinstance(artifacts, list):
        for item in artifacts:
            if isinstance(item, dict):
                h = item.get("sha256")
                if isinstance(h, str) and len(h) == 64:
                    hashes.append(h.lower())
            elif isinstance(item, str) and len(item) == 64:
                hashes.append(item.lower())
    return hashes


def _is_stale(snapshot_at: str) -> bool:
    """Return True when the snapshot is older than the warning threshold."""
    if not snapshot_at:
        return False
    try:
        # Tolerate both 'Z' suffix and '+00:00'
        normalized = snapshot_at.replace("Z", "+00:00")
        ts = datetime.fromisoformat(normalized)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    age_days = (datetime.now(timezone.utc) - ts).days
    return age_days > STALENESS_WARNING_DAYS
