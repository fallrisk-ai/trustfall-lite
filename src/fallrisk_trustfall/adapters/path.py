"""
Path adapter — arbitrary filesystem paths.

Handles three cases:

  1. A single weights file (.safetensors, .gguf, .bin if explicitly named)
     → ModelGroup(group_kind="single_file", artifacts=[one])

  2. A flat directory with one weights file
     → ModelGroup(group_kind="single_file", artifacts=[one])

  3. A flat directory with multiple weights files matching the
     HuggingFace shard naming convention
     (model-NNNNN-of-NNNNN.safetensors)
     → ModelGroup(group_kind="sharded_safetensors", artifacts=[N])

  4. A directory tree containing nested model directories
     (excluding HF cache layout — that's HFCacheAdapter's job)
     → one ModelGroup per terminal weights-bearing directory

The PathAdapter does NOT recurse into models--*/ directories — those
are owned by HFCacheAdapter. If a user passes a path like
~/.cache/huggingface/hub/, they get HFCacheAdapter behavior via
the scanner's path-routing logic, not this adapter.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from ..models import ArtifactCandidate, FormatHint, ModelGroup
from .base import SourceAdapter
from .hf_cache import _format_hint_for


# HF sharded model naming: "model-00001-of-00008.safetensors"
_SHARD_RE = re.compile(r"^(.+?)-(\d{5})-of-(\d{5})\.(safetensors|bin)$")


class PathAdapter(SourceAdapter):
    """
    Discovers ModelGroups under user-given filesystem paths.

    This adapter is permissive: it scans wherever you point it.
    The scanner is responsible for not pointing it at HF cache
    paths (those route to HFCacheAdapter instead).
    """

    name = "path"

    def __init__(self, paths: list[Path]) -> None:
        """`paths` are user-supplied; never resolved by environment."""
        self._paths = [p.expanduser() for p in paths]

    def discover(self, root: Path | None = None) -> Iterator[ModelGroup]:
        targets = [root] if root is not None else self._paths
        for target in targets:
            if not target.exists():
                continue
            if target.is_file():
                yield from self._groups_for_file(target)
            elif target.is_dir():
                yield from self._groups_for_directory(target)

    def _groups_for_file(self, file_path: Path) -> Iterator[ModelGroup]:
        """A single weights file becomes a single_file ModelGroup."""
        hint = _format_hint_for(file_path.name)
        if hint is None:
            return  # not a weights file; skip silently

        # Standalone .bin files are skipped per spec §5: "supported
        # only when found via HF cache layout (where filename is canonical)".
        if hint == "pytorch_bin":
            return

        try:
            size = file_path.stat().st_size
        except OSError:
            return

        artifact = ArtifactCandidate(
            sha256="",
            size_bytes=size,
            format_hint=hint,
            source="path",
            path=str(file_path.resolve()),
            filename=file_path.name,
            claim=None,  # PathAdapter has no model_id claim source for loose files
        )
        # group_id is a STABLE LOGICAL identifier (not the filesystem path).
        # The filesystem path is held in artifact.path and is only emitted
        # to JSON when --include-paths is explicitly passed. Format:
        # "path:{filename}:{size_bytes}" — uniqueness is good enough for
        # the local-machine scope of one scan invocation.
        yield ModelGroup(
            group_id=f"path:{file_path.name}:{size}",
            source="path",
            group_kind="single_file",
            artifacts=(artifact,),
            claimed_model_id=None,
        )

    def _groups_for_directory(self, dir_path: Path) -> Iterator[ModelGroup]:
        """
        Walk a directory tree, grouping weights files by parent directory.

        Skip `models--*/` subdirectories (HF cache territory) so a user
        who points the path adapter at a parent containing both bare
        models and HF cache subdirectories doesn't double-count.
        """
        for current_dir, dirnames, filenames in self._walk_skipping_hf_cache(dir_path):
            current = Path(current_dir)
            yield from self._groups_in_one_directory(current, filenames)

    def _walk_skipping_hf_cache(self, root: Path) -> Iterator[tuple[str, list[str], list[str]]]:
        """
        os.walk-style iteration that prunes HF-cache-style subdirectories.

        We yield (dir, dirnames, filenames) tuples and modify dirnames
        in place to prevent descending into models--*/ children.
        """
        import os
        for current_dir, dirnames, filenames in os.walk(root, followlinks=False):
            # Prune HF cache directories — those are HFCacheAdapter's job
            dirnames[:] = [d for d in dirnames if not d.startswith("models--")]
            yield current_dir, dirnames, filenames

    def _groups_in_one_directory(
        self, dir_path: Path, filenames: list[str]
    ) -> Iterator[ModelGroup]:
        """
        Group weights files within a single directory level.

        - Multiple shards matching the same prefix → one sharded group
        - Single weights file → one single_file group
        - Multiple unrelated weights files in the same dir → one group each
        """
        # Bucket weights files by detected format and shard prefix
        weights_files: list[tuple[str, FormatHint]] = []
        for fname in sorted(filenames):
            hint = _format_hint_for(fname)
            if hint is None or hint == "pytorch_bin":
                continue  # skip non-weights; skip standalone .bin (spec §5)
            weights_files.append((fname, hint))

        if not weights_files:
            return

        # Identify shard sets: files matching the HF shard naming convention
        # AND sharing the same prefix and total-shard-count.
        shard_buckets: dict[tuple[str, str, int], list[tuple[str, FormatHint]]] = {}
        non_shards: list[tuple[str, FormatHint]] = []

        for fname, hint in weights_files:
            m = _SHARD_RE.match(fname)
            if m and hint == "safetensors":
                prefix, _idx, total, ext = m.group(1), m.group(2), m.group(3), m.group(4)
                key = (prefix, ext, int(total))
                shard_buckets.setdefault(key, []).append((fname, hint))
            else:
                non_shards.append((fname, hint))

        # Sharded groups
        for (prefix, ext, total), files in shard_buckets.items():
            if len(files) >= 2:
                # Treat as sharded only when at least 2 shards present.
                # (One file matching the shard pattern is suspicious but
                # we don't second-guess — fall through to single_file.)
                artifacts = [
                    self._make_artifact(dir_path / fname, hint)
                    for fname, hint in sorted(files)
                ]
                artifacts = [a for a in artifacts if a is not None]
                if not artifacts:
                    continue
                yield ModelGroup(
                    group_id=f"path:{prefix}:sharded",
                    source="path",
                    group_kind="sharded_safetensors",
                    artifacts=tuple(artifacts),
                    claimed_model_id=None,
                )
            else:
                # Single file matching shard pattern — fall through to single_file
                non_shards.extend(files)

        # Single-file groups (one per remaining weights file)
        for fname, hint in non_shards:
            artifact = self._make_artifact(dir_path / fname, hint)
            if artifact is None:
                continue
            yield ModelGroup(
                group_id=f"path:{fname}:{artifact.size_bytes}",
                source="path",
                group_kind="single_file",
                artifacts=(artifact,),
                claimed_model_id=None,
            )

    def _make_artifact(
        self, file_path: Path, hint: FormatHint
    ) -> ArtifactCandidate | None:
        """Build an ArtifactCandidate; return None on stat failure."""
        try:
            size = file_path.stat().st_size
        except OSError:
            return None
        return ArtifactCandidate(
            sha256="",
            size_bytes=size,
            format_hint=hint,
            source="path",
            path=str(file_path.resolve()),
            filename=file_path.name,
            claim=None,
        )
