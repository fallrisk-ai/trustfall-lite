"""
Hugging Face cache adapter.

Parses the HF cache layout. Per HF docs, the canonical structure is:

    <cache_root>/
      models--{org}--{name}/
        snapshots/
          <revision>/
            *.safetensors    -> ../../blobs/<sha>
            *.bin            -> ../../blobs/<sha>
            *.gguf           -> ../../blobs/<sha>
            config.json
            tokenizer.json
            ...
        blobs/
          <sha>              # actual content
        refs/
          main               # contains the snapshot revision

The adapter:
  1. Resolves cache root precedence (HF_HUB_CACHE > HF_HOME/hub > XDG_CACHE_HOME > ~/.cache)
  2. Walks each models--{org}--{name} directory
  3. Parses the org/name claim from the directory name
  4. Identifies weights artifacts (.safetensors, .bin, .gguf) within snapshots
  5. Resolves symlinks to actual blob files (which is what we hash)
  6. Groups files belonging to the same snapshot
  7. Recognizes single vs sharded layouts
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from ..models import (
    ArtifactCandidate,
    Claim,
    FormatHint,
    ModelGroup,
)
from .base import SourceAdapter


# Recognized weights extensions per spec §5
_WEIGHTS_EXTENSIONS: dict[str, FormatHint] = {
    ".safetensors": "safetensors",
    ".gguf": "gguf",
    ".bin": "pytorch_bin",  # supported only via HF cache (where filename is canonical)
}


def _resolve_hf_cache_roots() -> list[Path]:
    """
    Resolve HF cache locations per spec §5 ratified precedence.

    Returns all existing roots — multiple may resolve simultaneously
    if a user has both HF_HUB_CACHE and HF_HOME set.
    """
    roots: list[Path] = []

    # 1. HF_HUB_CACHE — HF's documented primary override
    if hub_cache := os.environ.get("HF_HUB_CACHE"):
        roots.append(Path(hub_cache).expanduser())

    # 2. HF_HOME/hub
    if hf_home := os.environ.get("HF_HOME"):
        roots.append(Path(hf_home).expanduser() / "hub")

    # 3. XDG_CACHE_HOME/huggingface/hub (Linux/macOS)
    if xdg := os.environ.get("XDG_CACHE_HOME"):
        roots.append(Path(xdg).expanduser() / "huggingface" / "hub")

    # 4. Default ~/.cache/huggingface/hub
    roots.append(Path("~/.cache/huggingface/hub").expanduser())

    # 5. Windows %USERPROFILE%\.cache\huggingface\hub
    if userprofile := os.environ.get("USERPROFILE"):
        roots.append(Path(userprofile) / ".cache" / "huggingface" / "hub")

    # Deduplicate while preserving order, keep only existing dirs
    seen: set[Path] = set()
    existing: list[Path] = []
    for r in roots:
        try:
            resolved = r.resolve()
        except (OSError, RuntimeError):
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_dir():
            existing.append(resolved)

    return existing


def _parse_org_name(cache_dir_name: str) -> str | None:
    """
    Parse 'models--{org}--{name}' → 'org/name'.

    Returns None for malformed names (defensive — HF cache should
    always conform, but a corrupted cache shouldn't crash the scanner).
    """
    if not cache_dir_name.startswith("models--"):
        return None
    rest = cache_dir_name[len("models--"):]
    # HF separates org and name with '--', and any '--' in the name itself
    # is escaped, so rsplit at the first '--' boundary is wrong; we want
    # split at the first one. But model names with '--' are rare; the
    # documented HF convention is that the org is the prefix before the
    # first '--' and everything after is the name (which itself may
    # contain hyphens, just not '--').
    if "--" not in rest:
        # Models without an org prefix (rare): models--{name}
        return rest
    org, name = rest.split("--", 1)
    return f"{org}/{name}"


def _format_hint_for(filename: str) -> FormatHint | None:
    """Return the format hint for a filename, or None if not a weights file."""
    lower = filename.lower()
    for ext, hint in _WEIGHTS_EXTENSIONS.items():
        if lower.endswith(ext):
            return hint
    return None


class HFCacheAdapter(SourceAdapter):
    """
    Discovers ModelGroups in Hugging Face cache directories.
    """

    name = "hf_cache"

    def __init__(self, roots: list[Path] | None = None) -> None:
        """
        Initialize with explicit cache roots, or auto-resolve.

        Tests pass explicit roots; production code passes None to
        use spec-defined precedence resolution.
        """
        self._roots = roots if roots is not None else _resolve_hf_cache_roots()

    @property
    def roots(self) -> list[Path]:
        return list(self._roots)

    def discover(self, root: Path | None = None) -> Iterator[ModelGroup]:
        """
        Yield ModelGroups across all configured cache roots.

        If `root` is given, restrict to that root only (used by the
        CLI when the user passes an explicit path that happens to
        resolve inside a cache).
        """
        roots_to_walk = [root] if root is not None else self._roots
        for cache_root in roots_to_walk:
            if not cache_root.is_dir():
                continue
            yield from self._walk_cache_root(cache_root)

    def _walk_cache_root(self, cache_root: Path) -> Iterator[ModelGroup]:
        """Walk one cache root and yield ModelGroups for each models--* directory."""
        for entry in sorted(cache_root.iterdir()):
            if not entry.is_dir():
                continue
            if not entry.name.startswith("models--"):
                continue
            yield from self._groups_for_model_dir(entry)

    def _groups_for_model_dir(self, model_dir: Path) -> Iterator[ModelGroup]:
        """
        Yield one ModelGroup per snapshot found under models--{org}--{name}/snapshots/.

        A model with multiple snapshots (e.g. user pulled different
        revisions) produces multiple groups.
        """
        snapshots_dir = model_dir / "snapshots"
        if not snapshots_dir.is_dir():
            return

        claim_model_id = _parse_org_name(model_dir.name)

        for snapshot_dir in sorted(snapshots_dir.iterdir()):
            if not snapshot_dir.is_dir():
                continue
            artifacts = self._artifacts_in_snapshot(
                snapshot_dir, claim_model_id, source="hf_cache"
            )
            if not artifacts:
                continue

            group_kind = (
                "hf_snapshot"
                if len(artifacts) > 1
                else "single_file"
            )
            # group_id is a STABLE LOGICAL identifier (not a filesystem path).
            # Format: "hf_cache:{Org/Name}:{snapshot_sha}"
            #
            # Privacy: by default, JSON output includes group_id but NOT
            # full filesystem paths. The org/name and snapshot SHA are
            # both public information (visible at huggingface.co/Org/Name
            # and in the public HF revision history); the user's local
            # cache directory is private. Using path-as-id leaked the
            # cache directory in v0.2.0 — caught by GPT review pre-launch
            # and fixed before first public release.
            #
            # snapshot_dir.name is the 40-char (or shorter) revision hash.
            # When claim_model_id is unparseable, fall back to the raw
            # model_dir.name so we still have a stable id.
            mid = claim_model_id or model_dir.name
            group_id = f"hf_cache:{mid}:{snapshot_dir.name}"

            yield ModelGroup(
                group_id=group_id,
                source="hf_cache",
                group_kind=group_kind,
                artifacts=tuple(artifacts),
                claimed_model_id=claim_model_id,
            )

    def _artifacts_in_snapshot(
        self,
        snapshot_dir: Path,
        claim_model_id: str | None,
        source: str,
    ) -> list[ArtifactCandidate]:
        """
        Find weights files in a snapshot directory.

        HF stores weights as symlinks under snapshots/{rev}/ pointing
        to the actual blob in blobs/. We hash the blob (the symlink
        target) so different snapshots that share the same blob get
        the same hash — which is what HF's deduplication intends.
        """
        artifacts: list[ArtifactCandidate] = []

        for entry in sorted(snapshot_dir.iterdir()):
            if not entry.is_file() and not entry.is_symlink():
                continue
            hint = _format_hint_for(entry.name)
            if hint is None:
                continue

            # Resolve symlink to the blob file.
            try:
                blob_path = entry.resolve()
            except (OSError, RuntimeError):
                continue
            if not blob_path.is_file():
                continue

            try:
                size = blob_path.stat().st_size
            except OSError:
                continue

            claim = (
                Claim(model_id=claim_model_id, claim_source="hf_cache_path")
                if claim_model_id
                else None
            )

            artifacts.append(
                ArtifactCandidate(
                    sha256="",  # filled by hashing layer
                    size_bytes=size,
                    format_hint=hint,
                    source=source,  # type: ignore[arg-type]
                    path=str(blob_path),
                    filename=entry.name,  # the snapshot-side name (canonical)
                    claim=claim,
                )
            )

        return artifacts
