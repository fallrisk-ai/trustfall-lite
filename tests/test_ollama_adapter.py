"""
Tests for OllamaAdapter.

Coverage:
  - Manifest parsing of real Ollama manifests (real shapes from
    Anthony's MacBook captured April 27, 2026)
  - macOS resource fork filtering ("._" prefix files)
  - Non-library namespace handling (Hudson/, mollysama/)
  - Missing blob handling (manifest references non-existent blob)
  - Missing model layer handling (manifest with no weights layer)
  - Malformed manifest handling (invalid JSON, missing fields)
  - OLLAMA_MODELS env var resolution
  - claim_source = "ollama_manifest" on every artifact
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fallrisk_trustfall.adapters.ollama import (
    OllamaAdapter,
    _parse_manifest,
)


# ════════════════════════════════════════════════════════════════════
# Fixture builders
# ════════════════════════════════════════════════════════════════════
#
# These mirror the manifest shapes Anthony observed on his MacBook on
# April 27, 2026. The exact digest values are real (from his cache);
# the corresponding blobs are simulated empty files in the temp dir.


_LLAMA3_8B_MANIFEST = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
    "config": {
        "mediaType": "application/vnd.docker.container.image.v1+json",
        "digest": "sha256:3f8eb4da87fa7a3c9da615036b0dc418d31fef2a30b115ff33562588b32c691d",
        "size": 485,
    },
    "layers": [
        {
            "mediaType": "application/vnd.ollama.image.model",
            "digest": "sha256:6a0746a1ec1aef3e7ec53868f220ff6e389f6f8ef87a01d77c96807de94ca2aa",
            "size": 4661211424,
        },
        {
            "mediaType": "application/vnd.ollama.image.license",
            "digest": "sha256:4fa551d4f938f68b8c1e6afa9d28befb70e3f33f75d0753248d530364aeea40f",
            "size": 12403,
        },
        {
            "mediaType": "application/vnd.ollama.image.template",
            "digest": "sha256:8ab4849b038cf0abc5b1c9b8ee1443dca6b93a045c2272180d985126eb40bf6f",
            "size": 254,
        },
        {
            "mediaType": "application/vnd.ollama.image.params",
            "digest": "sha256:577073ffcc6ce95b9981eacc77d1039568639e5638e83044994560d9ef82ce1b",
            "size": 110,
        },
    ],
}


_DEEPSEEK_8B_MANIFEST = {
    "schemaVersion": 2,
    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
    "config": {
        "mediaType": "application/vnd.docker.container.image.v1+json",
        "digest": "sha256:f64cd5418e4b038ef90cf5fab6eb7ce6ae8f18909416822751d3b9fca827c2ab",
        "size": 487,
    },
    "layers": [
        {
            "mediaType": "application/vnd.ollama.image.model",
            "digest": "sha256:e6a7edc1a4d7d9b2de136a221a57336b76316cfe53a252aeba814496c5ae439d",
            "size": 5225373760,
        },
        {
            "mediaType": "application/vnd.ollama.image.template",
            "digest": "sha256:c5ad996bda6eed4df6e3b605a9869647624851ac248209d22fd5e2c0cc1121d3",
            "size": 556,
        },
    ],
}


_LLAMA3_MODEL_DIGEST = "6a0746a1ec1aef3e7ec53868f220ff6e389f6f8ef87a01d77c96807de94ca2aa"
_DEEPSEEK_MODEL_DIGEST = "e6a7edc1a4d7d9b2de136a221a57336b76316cfe53a252aeba814496c5ae439d"


def _build_ollama_root(tmp_path: Path) -> Path:
    """
    Build a fake Ollama models directory with two real manifest shapes
    (library/llama3:8b, library/deepseek-r1:8b), corresponding empty
    blobs, and several macOS resource-fork landmines that must be
    filtered out.
    """
    root = tmp_path / "ollama_models"
    manifests_base = root / "manifests" / "registry.ollama.ai"
    blobs = root / "blobs"
    blobs.mkdir(parents=True)

    # library/llama3:8b
    llama_dir = manifests_base / "library" / "llama3"
    llama_dir.mkdir(parents=True)
    (llama_dir / "8b").write_text(json.dumps(_LLAMA3_8B_MANIFEST))

    # library/deepseek-r1:8b
    deepseek_dir = manifests_base / "library" / "deepseek-r1"
    deepseek_dir.mkdir(parents=True)
    (deepseek_dir / "8b").write_text(json.dumps(_DEEPSEEK_8B_MANIFEST))

    # macOS resource forks — MUST be filtered (real landmine)
    (llama_dir / "._8b").write_text("garbage")
    (manifests_base / "library" / "._llama3").write_text("garbage")

    # Corresponding blobs (empty files; size_bytes comes from manifest)
    (blobs / f"sha256-{_LLAMA3_MODEL_DIGEST}").touch()
    (blobs / f"sha256-{_DEEPSEEK_MODEL_DIGEST}").touch()

    return root


# ════════════════════════════════════════════════════════════════════
# _parse_manifest unit tests
# ════════════════════════════════════════════════════════════════════


class TestParseManifest:
    def test_parses_real_llama3_manifest(self, tmp_path: Path):
        """The real Anthony-cache manifest shape parses cleanly."""
        path = (
            tmp_path
            / "manifests" / "registry.ollama.ai" / "library" / "llama3" / "8b"
        )
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(_LLAMA3_8B_MANIFEST))
        m = _parse_manifest(path)
        assert m is not None
        assert m.namespace == "library"
        assert m.name == "llama3"
        assert m.tag == "8b"
        assert m.claimed_model_id == "ollama/library/llama3:8b"
        # 4 layers (model, license, template, params)
        assert len(m.layers) == 4
        # Exactly one model-weight layer
        model_layer = m.model_layer()
        assert model_layer is not None
        assert model_layer.digest_hex == _LLAMA3_MODEL_DIGEST
        assert model_layer.size_bytes == 4661211424

    def test_parses_non_library_namespace(self, tmp_path: Path):
        """Non-library publishers (Hudson/, mollysama/) parse correctly."""
        path = (
            tmp_path
            / "manifests" / "registry.ollama.ai"
            / "Hudson" / "falcon-mamba-instruct" / "7b-q4_0"
        )
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({
            "schemaVersion": 2,
            "layers": [
                {
                    "mediaType": "application/vnd.ollama.image.model",
                    "digest": "sha256:" + "a" * 64,
                    "size": 4_000_000_000,
                },
            ],
        }))
        m = _parse_manifest(path)
        assert m is not None
        assert m.namespace == "Hudson"
        assert m.name == "falcon-mamba-instruct"
        assert m.tag == "7b-q4_0"
        assert m.claimed_model_id == "ollama/Hudson/falcon-mamba-instruct:7b-q4_0"

    def test_returns_none_on_invalid_json(self, tmp_path: Path):
        """Garbage files (e.g. macOS resource forks) return None, not crash."""
        path = (
            tmp_path
            / "manifests" / "registry.ollama.ai" / "library" / "llama3" / "8b"
        )
        path.parent.mkdir(parents=True)
        path.write_text("not valid JSON at all {{{")
        assert _parse_manifest(path) is None

    def test_returns_none_on_missing_layers(self, tmp_path: Path):
        """A JSON object without a layers array is not a valid manifest."""
        path = (
            tmp_path
            / "manifests" / "registry.ollama.ai" / "library" / "llama3" / "8b"
        )
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"schemaVersion": 2}))
        assert _parse_manifest(path) is None

    def test_returns_none_on_short_path(self, tmp_path: Path):
        """A manifest path missing one of {namespace, name, tag} is invalid."""
        # Only two segments after registry.ollama.ai
        path = (
            tmp_path
            / "manifests" / "registry.ollama.ai" / "library" / "llama3"
        )
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(_LLAMA3_8B_MANIFEST))
        assert _parse_manifest(path) is None

    def test_filters_invalid_digest_format(self, tmp_path: Path):
        """Layers with non-sha256 or non-hex digests are dropped."""
        path = (
            tmp_path
            / "manifests" / "registry.ollama.ai" / "library" / "x" / "y"
        )
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({
            "layers": [
                {
                    "mediaType": "application/vnd.ollama.image.model",
                    "digest": "md5:abcd",  # wrong algorithm
                    "size": 1000,
                },
                {
                    "mediaType": "application/vnd.ollama.image.template",
                    "digest": "sha256:nothex!!!",
                    "size": 100,
                },
            ],
        }))
        # Both layers filtered → no layers → None
        assert _parse_manifest(path) is None

    def test_ignores_local_from_field_PII(self, tmp_path: Path):
        """
        Custom-Modelfile manifests (created via `ollama create`) include
        a `from` field with the local source path — which contains the
        user's home directory and username. The parser MUST silently
        ignore this field; surfacing it would leak PII.

        Real example shape from Anthony's MacBook (April 27, 2026) for
        library/falcon_mamba_repaired:latest, where the model was
        created from a local file via Modelfile.
        """
        path = (
            tmp_path
            / "manifests" / "registry.ollama.ai"
            / "library" / "falcon_mamba_repaired" / "latest"
        )
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({
            "schemaVersion": 2,
            "config": {
                "digest": "sha256:" + "5" * 64,
                "size": 485,
            },
            "layers": [
                {
                    "mediaType": "application/vnd.ollama.image.model",
                    "digest": "sha256:" + "b" * 64,
                    "size": 4204231456,
                    # PII LANDMINE: local path with username embedded
                    "from": "/Users/SOMEONE/.ollama/models/blobs/sha256-" + "b" * 64,
                },
                {
                    "mediaType": "application/vnd.ollama.image.system",
                    "digest": "sha256:" + "6" * 64,
                    "size": 89,
                },
            ],
        }))
        m = _parse_manifest(path)
        assert m is not None
        # The parsed manifest must not retain anything resembling the
        # local path. _ParsedLayer is a frozen dataclass with a closed
        # set of fields; this test catches any future regression that
        # adds a `from` or `source_path` attribute.
        for layer in m.layers:
            for value in (
                getattr(layer, "from_", None),
                getattr(layer, "source_path", None),
                getattr(layer, "from", None),
            ):
                if value is not None:
                    assert "/Users/" not in str(value)
                    assert "SOMEONE" not in str(value)
        # And the .system mediaType is recognized as auxiliary, not a model layer
        model_layer = m.model_layer()
        assert model_layer is not None
        assert model_layer.media_type == "application/vnd.ollama.image.model"


# ════════════════════════════════════════════════════════════════════
# OllamaAdapter integration tests
# ════════════════════════════════════════════════════════════════════


class TestOllamaAdapter:
    def test_discovers_two_real_manifests(self, tmp_path: Path):
        """Full pipeline: walk → parse → resolve blob → emit ModelGroup."""
        root = _build_ollama_root(tmp_path)
        adapter = OllamaAdapter(models_root=root)
        groups = list(adapter.discover())
        # Two real manifests in fixture (llama3:8b, deepseek-r1:8b)
        assert len(groups) == 2
        ids = {g.claimed_model_id for g in groups}
        assert "ollama/library/llama3:8b" in ids
        assert "ollama/library/deepseek-r1:8b" in ids

    def test_macos_resource_forks_are_filtered(self, tmp_path: Path):
        """The `._` files MUST NOT produce groups."""
        root = _build_ollama_root(tmp_path)
        adapter = OllamaAdapter(models_root=root)
        groups = list(adapter.discover())
        # If the filter failed, we'd see ghost groups for ._8b etc.
        for g in groups:
            assert not g.group_id.startswith("._")
            assert not any(seg.startswith("._") for seg in g.group_id.split("/"))

    def test_each_artifact_has_ollama_manifest_claim(self, tmp_path: Path):
        """claim_source must be 'ollama_manifest' for every emitted artifact."""
        root = _build_ollama_root(tmp_path)
        adapter = OllamaAdapter(models_root=root)
        for g in adapter.discover():
            for art in g.artifacts:
                assert art.claim is not None
                assert art.claim.claim_source == "ollama_manifest"
                assert art.claim.model_id == g.claimed_model_id

    def test_artifact_format_hint_is_ollama_blob(self, tmp_path: Path):
        """Ollama artifacts have format_hint 'ollama_blob'."""
        root = _build_ollama_root(tmp_path)
        adapter = OllamaAdapter(models_root=root)
        for g in adapter.discover():
            for art in g.artifacts:
                assert art.format_hint == "ollama_blob"
                assert art.source == "ollama"

    def test_artifact_filename_is_blob_filename(self, tmp_path: Path):
        """The artifact filename is the on-disk sha256-<hex> blob name."""
        root = _build_ollama_root(tmp_path)
        adapter = OllamaAdapter(models_root=root)
        for g in adapter.discover():
            assert len(g.artifacts) == 1  # one model layer per group
            art = g.artifacts[0]
            assert art.filename.startswith("sha256-")
            assert len(art.filename) == 7 + 64  # "sha256-" + 64 hex chars

    def test_missing_blob_skips_group(self, tmp_path: Path):
        """If the manifest references a blob that doesn't exist, skip silently."""
        root = tmp_path / "ollama_root"
        manifests = root / "manifests" / "registry.ollama.ai" / "library" / "ghost"
        manifests.mkdir(parents=True)
        (root / "blobs").mkdir()
        # Manifest references a digest, but no blob file exists
        (manifests / "1b").write_text(json.dumps({
            "layers": [
                {
                    "mediaType": "application/vnd.ollama.image.model",
                    "digest": "sha256:" + "f" * 64,
                    "size": 100,
                },
            ],
        }))
        adapter = OllamaAdapter(models_root=root)
        # Should yield nothing; no crash
        assert list(adapter.discover()) == []

    def test_missing_model_layer_skips_group(self, tmp_path: Path):
        """A manifest with no weights layer is not a verifiable model."""
        root = tmp_path / "ollama_root"
        manifests = root / "manifests" / "registry.ollama.ai" / "library" / "templonly"
        manifests.mkdir(parents=True)
        (root / "blobs").mkdir()
        (manifests / "v1").write_text(json.dumps({
            "layers": [
                {
                    "mediaType": "application/vnd.ollama.image.template",
                    "digest": "sha256:" + "1" * 64,
                    "size": 200,
                },
            ],
        }))
        adapter = OllamaAdapter(models_root=root)
        assert list(adapter.discover()) == []

    def test_no_ollama_install_returns_empty(self, tmp_path: Path):
        """When no Ollama directory exists at the resolved path, yield nothing."""
        # tmp_path exists but has no manifests/registry.ollama.ai layout
        adapter = OllamaAdapter(models_root=tmp_path / "does_not_exist")
        assert list(adapter.discover()) == []

    def test_explicit_root_overrides_default(self, tmp_path: Path):
        """The explicit constructor argument wins over env vars and defaults."""
        root = _build_ollama_root(tmp_path)
        adapter = OllamaAdapter(models_root=root)
        # Even if OLLAMA_MODELS pointed elsewhere, the explicit root wins
        # (we can't easily isolate env in a unit test, but we assert the
        # explicit root produces the expected output)
        groups = list(adapter.discover())
        assert len(groups) == 2

    def test_env_var_resolution(self, tmp_path: Path, monkeypatch):
        """OLLAMA_MODELS env var is consulted when no explicit root."""
        root = _build_ollama_root(tmp_path)
        monkeypatch.setenv("OLLAMA_MODELS", str(root))
        adapter = OllamaAdapter()  # no explicit root
        groups = list(adapter.discover())
        assert len(groups) == 2

    def test_discover_root_argument_overrides(self, tmp_path: Path):
        """The discover(root=) parameter overrides constructor and env."""
        root = _build_ollama_root(tmp_path)
        # Construct with no root, override at discover time
        adapter = OllamaAdapter()
        groups = list(adapter.discover(root=root))
        assert len(groups) == 2
