"""
Normalized object model for Trustfall Lite.

Every source adapter produces ModelGroup objects. The verifier and the
formatter only ever see ModelGroups and the ArtifactCandidates inside
them. Source-specific knowledge — Hugging Face cache layout, Ollama
manifests, LM Studio model directories — never leaves the adapter
layer.

This decouples the verification core from the local-ecosystem layer.
v0.1 implements two adapters (HF cache + path). v0.2+ adds Ollama and
LM Studio without touching the core.

Design rule: an adapter never produces a loose ArtifactCandidate.
A single safetensors file path produces a ModelGroup of
group_kind="single_file" containing one candidate. The downstream
code only iterates groups; it never needs a special case for
"loose artifacts."
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


# ════════════════════════════════════════════════════════════════════
# Format hints
# ════════════════════════════════════════════════════════════════════

FormatHint = Literal[
    "safetensors",   # *.safetensors, single or sharded
    "gguf",          # *.gguf, all quantization variants
    "pytorch_bin",   # *.bin (legacy PyTorch checkpoints, HF cache only)
    "ollama_blob",   # Ollama content-addressed blob (v0.2)
    "unknown",       # placeholder; should not appear in v0.1 output
]


# ════════════════════════════════════════════════════════════════════
# Source identifiers
# ════════════════════════════════════════════════════════════════════

SourceKind = Literal[
    "hf_cache",      # HFCacheAdapter
    "path",          # PathAdapter
    "ollama",        # OllamaAdapter (v0.2 stub)
    "lmstudio",      # LMStudioAdapter (v0.2 stub)
]


# ════════════════════════════════════════════════════════════════════
# Group kinds
# ════════════════════════════════════════════════════════════════════
#
# A ModelGroup is the user-visible reporting unit. Every recognized
# local artifact maps to exactly one group; some groups contain one
# artifact, others (sharded models, Ollama manifests) contain many.

GroupKind = Literal[
    "hf_snapshot",          # full HF cache snapshot (multiple shards/blobs)
    "sharded_safetensors",  # 2+ safetensors shards in a flat directory
    "single_file",          # one safetensors/gguf/bin file (any source)
    "ollama_manifest",      # Ollama manifest + its referenced blobs (v0.2)
    "lmstudio_model",       # LM Studio publisher/model/file layout (v0.2)
]


# ════════════════════════════════════════════════════════════════════
# ArtifactCandidate
# ════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class Claim:
    """
    A claim that this artifact corresponds to a particular model_id,
    derived from local context (filename, cache path, manifest, etc.).

    Used to detect the "unknown variant" case: if the local context
    strongly suggests model_id X but the hash does not match X's
    registry record, the result is unknown_variant rather than
    not_enrolled.
    """

    model_id: str
    claim_source: Literal[
        "hf_cache_path",     # parsed from models--{org}--{name}/
        "ollama_manifest",   # parsed from Ollama manifest (v0.2)
        "lmstudio_path",     # parsed from publisher/model/ layout (v0.2)
        "filename",          # parsed from filename pattern (weakest signal)
    ]


@dataclass(frozen=True)
class ArtifactCandidate:
    """
    A single hashable artifact (file or blob).

    Adapters produce these as members of a ModelGroup. They are
    never standalone in the verification flow.

    The `path` field is for local diagnostics only. It is NEVER sent
    to the API unless the user passes --include-paths, and even then
    home-directory prefixes are stripped before sending. The CLI
    treats `path` as private-by-default information.
    """

    sha256: str               # lowercase 64-char hex; computed by hashing layer
    size_bytes: int
    format_hint: FormatHint
    source: SourceKind
    path: str                 # local absolute path (NOT sent to API by default)
    filename: str             # basename, used for filename-based claims
    claim: Claim | None = None  # local-context claim, if available


# ════════════════════════════════════════════════════════════════════
# ModelGroup
# ════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class ModelGroup:
    """
    A logical model — the user-visible reporting unit.

    Examples:
      - HF snapshot of meta-llama/Llama-3.1-8B-Instruct with 4 shards
        → one ModelGroup, group_kind="hf_snapshot", 4 ArtifactCandidates
      - Single GGUF file at /home/user/llama-7b-q4.gguf
        → one ModelGroup, group_kind="single_file", 1 ArtifactCandidate
      - Ollama manifest for llama3.1:8b with 6 blobs (v0.2)
        → one ModelGroup, group_kind="ollama_manifest", N ArtifactCandidates
    """

    group_id: str                          # adapter-stable identifier (e.g. HF snapshot dir)
    source: SourceKind
    group_kind: GroupKind
    artifacts: tuple[ArtifactCandidate, ...]
    claimed_model_id: str | None = None    # group-level claim if available

    def primary_filename(self) -> str:
        """Best filename to display when there is no claimed_model_id."""
        if not self.artifacts:
            return self.group_id
        # For single_file: the one filename. For sharded: the directory or first shard.
        return self.artifacts[0].filename
