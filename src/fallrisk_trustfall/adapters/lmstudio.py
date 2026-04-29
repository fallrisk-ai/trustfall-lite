"""
LM Studio adapter — v0.2 stub.

When implemented, this adapter will:

  1. Walk ~/.lmstudio/models/ (or $LMS_HOME/models if configured).
  2. Recognize the LM Studio publisher/model/file layout, e.g.:
        ~/.lmstudio/models/lmstudio-community/Llama-3.1-8B-Instruct-GGUF/
            Llama-3.1-8B-Instruct-Q4_K_M.gguf
  3. Produce one ModelGroup per model directory with
     group_kind="lmstudio_model", deriving a claim of
     publisher/model from the directory layout.

LM Studio uses GGUF as the primary on-disk format, so the actual
file recognition reuses the same _format_hint_for() machinery as
the path adapter. The added value is the publisher/model claim
inference from the LM Studio directory structure, which produces
better "unknown variant" diagnostics than treating these as bare
paths.

Until v0.2 ships, this adapter raises NotImplementedError.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from ..models import ModelGroup
from .base import SourceAdapter


class LMStudioAdapter(SourceAdapter):
    """v0.2 stub. Raises NotImplementedError until implemented."""

    name = "lmstudio"

    def discover(self, root: Path | None = None) -> Iterator[ModelGroup]:
        raise NotImplementedError(
            "LM Studio support is planned for Trustfall Lite v0.2. "
            "v0.1 supports Hugging Face cache and direct file paths only. "
            "Track progress at https://fallrisk.ai/."
        )
        yield  # type: ignore[unreachable]
