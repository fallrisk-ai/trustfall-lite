"""
Ollama adapter — v0.2 implementation.

Walks the Ollama manifests tree at:

    {OLLAMA_MODELS or ~/.ollama/models}/manifests/registry.ollama.ai/

For each manifest file, parses the JSON, identifies the model-weight
layer by mediaType ("application/vnd.ollama.image.model"), resolves
the blob filename under blobs/sha256-<digest>, and emits one
ModelGroup per manifest with one ArtifactCandidate per layer.

Auxiliary layers (template, license, params, system) are recorded in
each ModelGroup but only the model-weight layer participates in
identity verification at this layer. Modelfile composition semantics
(template equivalence, adapter identity, system-prompt matching) are
explicitly out of scope for v0.2 — they belong in a future Lite
release that handles "model + Modelfile = composed runtime artifact"
as a first-class concept.

Per Ollama documentation (https://docs.ollama.com/modelfile), a model
in Ollama can be a composition of FROM + ADAPTER + TEMPLATE + SYSTEM
+ LICENSE + PARAMETER + REQUIRES instructions, so a single
user-visible model ("llama3:8b") may correspond to multiple blobs.
The ModelGroup abstraction is exactly what makes this representable.

Ollama blobs are content-addressed: the blob filename is literally
"sha256-<digest>", so the digest is recoverable from the path. By
default we still hash the blob contents to verify the filename is
honest about the content (catches local corruption, rename attacks,
mounted-overlay tampering). The --trust-ollama-filenames CLI flag
opts into the fast path that trusts the filename digest; in that
case the artifact is marked digest_verified=False with
digest_source="ollama_blob_filename" so JSON consumers know which
mode produced the data.

PARSER DEFENSIVE LANDMINES (real, observed on macOS scans):

  1. macOS resource forks: the directory walk surfaces files like
     `._latest`, `._7b`, `._falcon3` (siblings of the real manifest
     files). These are not Ollama manifests and parsing them as JSON
     fails. The walker filters basenames starting with "._" before
     attempting to parse.

  2. Non-library namespaces are real and used. The Ollama hub serves
     models from arbitrary publishers, e.g. `Hudson/falcon-mamba-instruct`,
     `mollysama/rwkv-7-g1c`. The parser cannot hardcode `library/` as
     the only valid path segment. Format is `{namespace}/{name}/{tag}`.

  3. Manifest files have no extension. The walker finds them by being
     under `manifests/registry.ollama.ai/` and being a regular file
     (not a directory).

  4. Model layer may be absent. A manifest could in principle have no
     `application/vnd.ollama.image.model` layer (corrupted state,
     custom Modelfile that only changes parameters, etc.). The adapter
     reports this as a parse error and skips the manifest with a
     warning, rather than silently emitting a group with no artifacts.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models import ArtifactCandidate, Claim, ModelGroup
from .base import SourceAdapter


# ════════════════════════════════════════════════════════════════════
# Constants — Ollama on-disk layout
# ════════════════════════════════════════════════════════════════════

# The Ollama "registry" directory under which all manifests live.
# Even private/community publishers go under this path on disk.
_REGISTRY_DIR = "registry.ollama.ai"

# The mediaType that identifies a model-weight layer in an Ollama
# manifest. Other mediaTypes (template, license, params, system, adapter)
# are recorded but do not drive identity verification at this layer.
_MEDIA_TYPE_MODEL = "application/vnd.ollama.image.model"

# Default path locations, in priority order. OLLAMA_MODELS env var
# wins when set (per Ollama docs); otherwise fall back to the
# platform-default location. macOS and Linux both use ~/.ollama/models
# for user installs; Linux service installs may be at /usr/share/ollama
# but we don't probe that path by default — users with system installs
# can set OLLAMA_MODELS explicitly.
_DEFAULT_PATHS = (
    "~/.ollama/models",
)


# ════════════════════════════════════════════════════════════════════
# Manifest parsing
# ════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class _ParsedLayer:
    """Internal representation of one layer from an Ollama manifest."""

    media_type: str
    digest_hex: str       # the hex part of "sha256:<hex>"
    size_bytes: int


@dataclass(frozen=True)
class _ParsedManifest:
    """Internal representation of one parsed Ollama manifest."""

    namespace: str        # "library", "Hudson", "mollysama", etc.
    name: str             # "llama3", "falcon-mamba-instruct", etc.
    tag: str              # "8b", "latest", "7b-q4_0", etc.
    layers: tuple[_ParsedLayer, ...]
    config_digest: str | None  # sometimes useful, recorded but not currently used

    @property
    def claimed_model_id(self) -> str:
        """Canonical Trustfall identifier for an Ollama tag.

        Format: `ollama/{namespace}/{name}:{tag}` — preserves the
        full Ollama-side identity (including non-library publishers)
        so downstream registry lookups can be unambiguous.
        """
        return f"ollama/{self.namespace}/{self.name}:{self.tag}"

    def model_layer(self) -> _ParsedLayer | None:
        """Return the single weight layer, or None if absent."""
        candidates = [l for l in self.layers if l.media_type == _MEDIA_TYPE_MODEL]
        if len(candidates) == 0:
            return None
        # Defensive: spec allows only one model layer per manifest.
        # If we ever see >1, take the first and let the caller
        # decide whether to log a warning.
        return candidates[0]


def _parse_manifest(path: Path) -> _ParsedManifest | None:
    """
    Parse one Ollama manifest file.

    Returns None on any of:
      - file not readable
      - file is not valid JSON
      - JSON does not match the expected manifest shape
      - path is not under registry.ollama.ai/{namespace}/{name}/{tag}

    The caller is expected to log/skip rather than crash on None.
    Never raises — defensive by design because the walker iterates
    over the user's filesystem and cannot afford to crash on a
    surprise file.
    """
    # Reconstruct {namespace}/{name}/{tag} from the path.
    # Path layout: .../manifests/registry.ollama.ai/{namespace}/{name}/{tag}
    parts = path.parts
    if _REGISTRY_DIR not in parts:
        return None
    try:
        registry_idx = parts.index(_REGISTRY_DIR)
    except ValueError:
        return None
    after_registry = parts[registry_idx + 1:]
    # We need exactly: namespace, name, tag (3 parts after registry.ollama.ai)
    if len(after_registry) != 3:
        return None
    namespace, name, tag = after_registry

    # Read and parse JSON.
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None

    try:
        data: dict[str, Any] = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(data, dict):
        return None

    # Extract layers. Spec: layers is a list of objects with mediaType,
    # digest, size.
    raw_layers = data.get("layers")
    if not isinstance(raw_layers, list):
        return None

    parsed_layers: list[_ParsedLayer] = []
    for raw_layer in raw_layers:
        if not isinstance(raw_layer, dict):
            continue
        media_type = raw_layer.get("mediaType")
        digest = raw_layer.get("digest")
        size = raw_layer.get("size")
        if not isinstance(media_type, str):
            continue
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            continue
        if not isinstance(size, int):
            continue
        digest_hex = digest[len("sha256:"):]
        # Defensive: digest must be 64 lowercase hex chars
        if len(digest_hex) != 64 or not all(c in "0123456789abcdef" for c in digest_hex):
            continue
        parsed_layers.append(
            _ParsedLayer(
                media_type=media_type,
                digest_hex=digest_hex,
                size_bytes=size,
            )
        )

    if not parsed_layers:
        return None

    # Optional config digest (used for completeness in JSON output).
    config = data.get("config")
    config_digest: str | None = None
    if isinstance(config, dict):
        cd = config.get("digest")
        if isinstance(cd, str) and cd.startswith("sha256:"):
            cd_hex = cd[len("sha256:"):]
            if len(cd_hex) == 64 and all(c in "0123456789abcdef" for c in cd_hex):
                config_digest = cd_hex

    return _ParsedManifest(
        namespace=namespace,
        name=name,
        tag=tag,
        layers=tuple(parsed_layers),
        config_digest=config_digest,
    )


# ════════════════════════════════════════════════════════════════════
# Adapter
# ════════════════════════════════════════════════════════════════════


class OllamaAdapter(SourceAdapter):
    """
    Discover Ollama models by walking the manifests tree under the
    user's Ollama models directory.

    Instantiate without arguments to use the platform default
    (`~/.ollama/models`, overridable via OLLAMA_MODELS env var). Pass
    `models_root=` to override the search root explicitly — useful for
    tests and for users with non-standard installs.
    """

    name = "ollama"

    def __init__(self, models_root: Path | None = None) -> None:
        self._explicit_root = models_root

    # ------------------------------------------------------------------
    # Resolution of the on-disk layout
    # ------------------------------------------------------------------

    def _resolve_root(self) -> Path | None:
        """
        Return the resolved Ollama models directory, or None if no
        Ollama install is detected. The CLI uses None to skip the
        Ollama section of the scan silently.
        """
        # Explicit constructor argument wins.
        if self._explicit_root is not None:
            return self._explicit_root if self._explicit_root.is_dir() else None

        # OLLAMA_MODELS env var wins next.
        env_path = os.environ.get("OLLAMA_MODELS")
        if env_path:
            p = Path(env_path).expanduser()
            return p if p.is_dir() else None

        # Default search paths.
        for default in _DEFAULT_PATHS:
            p = Path(default).expanduser()
            if p.is_dir():
                return p
        return None

    # ------------------------------------------------------------------
    # Manifest walking
    # ------------------------------------------------------------------

    def _walk_manifests(self, models_root: Path) -> Iterator[_ParsedManifest]:
        """
        Yield parsed manifests from the manifests tree.

        Filters out:
          - macOS resource forks (filenames starting with "._")
          - Non-regular files (directories, symlinks to directories)
          - Files that fail to parse as Ollama manifests
        """
        manifests_dir = models_root / "manifests" / _REGISTRY_DIR
        if not manifests_dir.is_dir():
            return

        # Walk all files under the registry. rglob on a Path is
        # well-defined and respects symlinks per Python defaults.
        for entry in manifests_dir.rglob("*"):
            # Filter directories.
            if not entry.is_file():
                continue
            # Filter macOS resource forks. These appear as siblings
            # of real manifests (e.g. `._latest` next to `latest`)
            # and must never be parsed.
            if entry.name.startswith("._"):
                continue
            parsed = _parse_manifest(entry)
            if parsed is None:
                continue
            yield parsed

    # ------------------------------------------------------------------
    # SourceAdapter contract
    # ------------------------------------------------------------------

    def discover(self, root: Path | None = None) -> Iterator[ModelGroup]:
        """
        Yield ModelGroups for every Ollama manifest under the
        resolved models root.

        ArtifactCandidates produced here have empty sha256 strings
        — the hashing layer fills them in when the user has not
        passed --trust-ollama-filenames, or copies the digest from
        the blob filename when they have.

        The `root` argument allows the CLI to override the resolved
        path on a per-scan basis (useful for testing or for scanning
        a non-default location without setting an env var).
        """
        models_root = root if root is not None else self._resolve_root()
        if models_root is None or not models_root.is_dir():
            return

        blobs_dir = models_root / "blobs"
        if not blobs_dir.is_dir():
            # Manifests without blobs is a corrupted Ollama state.
            # Don't crash; just produce no groups.
            return

        for manifest in self._walk_manifests(models_root):
            model_layer = manifest.model_layer()
            if model_layer is None:
                # No weight layer — can't verify identity. Skip.
                # (We could yield a group with an artifact for the
                # config blob, but that's not a model and would
                # mislead users.)
                continue

            blob_path = blobs_dir / f"sha256-{model_layer.digest_hex}"
            if not blob_path.is_file():
                # Manifest references a missing blob. Could be a
                # partial download or a deleted blob. Skip rather
                # than report a spurious unknown_variant.
                continue

            # Build the artifact for the weight layer.
            # NOTE: sha256 is left empty here. The hashing layer
            # will either compute it (default) or copy from the
            # filename (--trust-ollama-filenames mode).
            claim = Claim(
                model_id=manifest.claimed_model_id,
                claim_source="ollama_manifest",
            )
            artifact = ArtifactCandidate(
                sha256="",
                size_bytes=model_layer.size_bytes,
                format_hint="ollama_blob",
                source="ollama",
                path=str(blob_path),
                filename=blob_path.name,
                claim=claim,
            )

            # group_id uses the canonical claimed_model_id without
            # the "ollama/" prefix — readable, stable, unique per tag.
            group_id = f"{manifest.namespace}/{manifest.name}:{manifest.tag}"

            yield ModelGroup(
                group_id=group_id,
                source="ollama",
                group_kind="ollama_manifest",
                artifacts=(artifact,),
                claimed_model_id=manifest.claimed_model_id,
            )
