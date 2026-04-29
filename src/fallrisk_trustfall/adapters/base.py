"""
Base interface for source adapters.

Every adapter implements `discover()` to return ModelGroups for its
ecosystem. The adapter does NOT compute hashes — it produces
candidate file paths and metadata, and the hashing layer fills in
the SHA-256 values. This separation keeps adapters fast (no I/O on
file contents) and lets the hashing layer batch and progress-report
across all sources uniformly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path

from ..models import ModelGroup


class SourceAdapter(ABC):
    """
    Abstract base for source adapters.

    Subclasses implement `discover()` to yield ModelGroups whose
    ArtifactCandidates have empty `sha256` strings. The hashing
    layer fills these in afterward, returning hydrated copies.

    This two-phase design (discover → hash) lets the CLI report
    overall progress as "scanning N candidates from K sources."
    """

    name: str = "base"

    @abstractmethod
    def discover(self, root: Path | None = None) -> Iterator[ModelGroup]:
        """
        Yield ModelGroups for this source, optionally rooted at `root`.

        ArtifactCandidates yielded here have placeholder sha256 values
        (empty string). The hashing layer fills them in.
        """
        ...
