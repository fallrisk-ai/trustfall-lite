"""
Hashing layer.

Adapters produce ArtifactCandidates with empty `sha256` fields; the
hashing layer fills them in by streaming SHA-256 over the file
contents at the candidate's `path`.

Per spec §5: 8 MiB chunks, no full-file load, progress reporting for
files >10 GB unless `--quiet`.

The hashing layer NEVER touches network. It is pure local I/O. This
keeps the cost model predictable: hashing time is determined entirely
by file sizes and disk read speed. A user can estimate scan time as
total_bytes / disk_throughput before running.

OLLAMA FAST PATH (v0.2):

Ollama blobs are content-addressed: the on-disk filename is literally
"sha256-<hex>". When the user passes --trust-ollama-filenames at the
CLI layer, the hasher takes the digest from the filename instead of
reading the file contents — a substantial speed win for large Ollama
installs (e.g. 350+ GB) on first scan.

This is OPT-IN. The default behavior is to hash the bytes and verify
the result matches the filename digest, because:

  1. Trustfall is a trust tool; "boring correctness" beats clever
     speed for the first public impression.
  2. Filename-trust assumes the local filesystem is honest about
     filename↔content mapping. Local corruption, partial downloads,
     or rename-attacks would silently produce wrong results in
     fast-path mode.
  3. The full-hash mode catches real failure modes the fast path cannot.

When the fast path IS used, the artifact is still hashed (so it can
be looked up against the registry), but the hashing-layer marks it
internally so the JSON renderer can record:
    digest_verified: false
    digest_source: "ollama_blob_filename"

In default (verify) mode, the JSON records:
    digest_verified: true
    digest_source: "content_hash"
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable
from dataclasses import replace
from pathlib import Path
from typing import Final

from .models import ArtifactCandidate, ModelGroup


# Per spec §5
DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024  # 8 MiB

# Per spec §5: progress indicator for files >10 GB unless --quiet
PROGRESS_THRESHOLD_BYTES = 10 * 1024 * 1024 * 1024  # 10 GiB


# Ollama blob filenames are exactly "sha256-" + 64 hex chars = 71 chars.
_OLLAMA_BLOB_FILENAME_LEN: Final[int] = 71
_OLLAMA_BLOB_PREFIX: Final[str] = "sha256-"


# Type for an optional progress callback. Called periodically during
# hashing of a single file with (filename, bytes_done, bytes_total).
ProgressCallback = Callable[[str, int, int], None]


def hash_file(
    path: Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress: ProgressCallback | None = None,
) -> str:
    """
    Stream SHA-256 over a file's contents.

    Returns lowercase 64-char hex digest. Raises OSError on read
    failure; caller is responsible for skipping unreadable files.

    `progress`, if given, is called after each chunk for files
    larger than PROGRESS_THRESHOLD_BYTES. The callback receives
    (filename, bytes_processed, file_size).
    """
    h = hashlib.sha256()
    file_size = path.stat().st_size
    show_progress = progress is not None and file_size >= PROGRESS_THRESHOLD_BYTES
    bytes_done = 0

    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
            bytes_done += len(chunk)
            if show_progress:
                progress(path.name, bytes_done, file_size)  # type: ignore[misc]

    return h.hexdigest()


def _digest_from_ollama_filename(filename: str) -> str | None:
    """
    Extract the 64-char hex digest from an Ollama blob filename.

    Returns None if the filename does not match the strict shape
    "sha256-" + 64 lowercase hex chars. Defensive: never trust a
    filename that doesn't conform — the safe behavior is to fall
    back to content hashing.
    """
    if len(filename) != _OLLAMA_BLOB_FILENAME_LEN:
        return None
    if not filename.startswith(_OLLAMA_BLOB_PREFIX):
        return None
    digest = filename[len(_OLLAMA_BLOB_PREFIX):]
    if len(digest) != 64:
        return None
    if not all(c in "0123456789abcdef" for c in digest):
        return None
    return digest


def hash_artifact(
    candidate: ArtifactCandidate,
    progress: ProgressCallback | None = None,
    trust_ollama_filenames: bool = False,
) -> ArtifactCandidate:
    """
    Return a new ArtifactCandidate with the sha256 field populated.

    On read failure, returns the candidate unchanged (sha256 stays
    empty). The downstream verifier MUST treat empty-sha256 candidates
    as "skipped, error" — they cannot be looked up against the registry.

    When `trust_ollama_filenames` is True AND the candidate is an
    Ollama blob (format_hint="ollama_blob") AND its filename matches
    the strict sha256-<hex> shape, the digest is copied from the
    filename without reading bytes. This is the fast path for
    --trust-ollama-filenames mode.

    For non-Ollama artifacts, or for Ollama artifacts where the
    filename is malformed (which would itself be a bug worth
    surfacing — but the safe fallback is to hash), the standard
    content-hashing path runs.
    """
    if (
        trust_ollama_filenames
        and candidate.format_hint == "ollama_blob"
    ):
        filename_digest = _digest_from_ollama_filename(candidate.filename)
        if filename_digest is not None:
            return replace(candidate, sha256=filename_digest)
        # Filename was malformed despite format_hint=ollama_blob.
        # Fall through to content hashing.

    try:
        digest = hash_file(Path(candidate.path), progress=progress)
    except OSError:
        return candidate  # leave sha256 empty; downstream skips

    return replace(candidate, sha256=digest)


def hash_group(
    group: ModelGroup,
    progress: ProgressCallback | None = None,
    trust_ollama_filenames: bool = False,
) -> ModelGroup:
    """
    Hash every artifact in a group; return a new ModelGroup with
    hydrated artifacts.

    `trust_ollama_filenames` is forwarded to each artifact-level call;
    only Ollama artifacts (format_hint="ollama_blob") are affected by
    the flag, so it is safe to set globally for a scan that includes
    HF cache + Ollama.
    """
    hydrated = tuple(
        hash_artifact(a, progress=progress, trust_ollama_filenames=trust_ollama_filenames)
        for a in group.artifacts
    )
    return replace(group, artifacts=hydrated)


def hash_groups(
    groups: Iterable[ModelGroup],
    progress: ProgressCallback | None = None,
    trust_ollama_filenames: bool = False,
) -> list[ModelGroup]:
    """
    Hash every artifact in every group, in order. Returns a fully
    hydrated list — the verifier expects `sha256` fields populated.

    Groups are processed sequentially. The CLI's progress reporting
    layer can wrap this with a per-group "scanning N of K" line.
    """
    return [
        hash_group(g, progress=progress, trust_ollama_filenames=trust_ollama_filenames)
        for g in groups
    ]


def was_filename_trusted(candidate: ArtifactCandidate, trust_ollama_filenames: bool) -> bool:
    """
    Return True iff this artifact's sha256 was sourced from the Ollama
    blob filename rather than from a content hash.

    The JSON renderer uses this to populate `digest_verified` and
    `digest_source` fields on Ollama group output. For non-Ollama
    artifacts, always returns False.

    NOTE: This is a query function, not a state flag. It re-derives
    the fact from the candidate's current state and the user's mode
    selection. We don't carry a `digest_verified` field on
    ArtifactCandidate itself because it would couple the data model
    to the CLI's flag set, which we want to keep clean.
    """
    if not trust_ollama_filenames:
        return False
    if candidate.format_hint != "ollama_blob":
        return False
    filename_digest = _digest_from_ollama_filename(candidate.filename)
    return filename_digest is not None and filename_digest == candidate.sha256


# ════════════════════════════════════════════════════════════════════
# Helpers for callers
# ════════════════════════════════════════════════════════════════════


def total_bytes(groups: Iterable[ModelGroup]) -> int:
    """Sum size_bytes across all artifacts in all groups."""
    return sum(a.size_bytes for g in groups for a in g.artifacts)


def total_artifacts(groups: Iterable[ModelGroup]) -> int:
    """Count of artifacts across all groups."""
    return sum(len(g.artifacts) for g in groups)


def unique_bytes(groups: Iterable[ModelGroup]) -> int:
    """
    Sum size_bytes of UNIQUE artifacts (deduplicated by sha256 across
    all groups). For Ollama installs where two tags reference the
    same weight blob (e.g. `llama3:8b` and `llama3:latest` pointing at
    the same digest), this avoids double-counting storage.

    Artifacts with empty sha256 (hashing failed) are counted toward
    total_bytes but contribute nothing to unique_bytes — the safe
    behavior is to under-count uniqueness, not over-count.
    """
    seen: dict[str, int] = {}
    for g in groups:
        for a in g.artifacts:
            if not a.sha256:
                continue
            seen.setdefault(a.sha256, a.size_bytes)
    return sum(seen.values())


def unique_artifacts(groups: Iterable[ModelGroup]) -> int:
    """
    Count UNIQUE artifacts deduplicated by sha256 across all groups.
    See unique_bytes() for the dedup rationale.
    """
    seen: set[str] = set()
    for g in groups:
        for a in g.artifacts:
            if a.sha256:
                seen.add(a.sha256)
    return len(seen)
