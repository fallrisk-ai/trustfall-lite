"""
Tests for source adapters.

HFCacheAdapter and PathAdapter both have to handle several local-layout
variants. These tests build temporary fixtures and assert that:
- Files are detected with the right format hint
- Sharded sets are grouped correctly
- HF cache symlinks are resolved
- Stubs raise NotImplementedError

Adapters are NOT tested for hashing — that's a separate layer.
ArtifactCandidates produced by adapters have empty sha256 fields.
"""

import os
from pathlib import Path

import pytest

from fallrisk_trustfall.adapters import (
    HFCacheAdapter,
    LMStudioAdapter,
    OllamaAdapter,
    PathAdapter,
)
from fallrisk_trustfall.adapters.hf_cache import _format_hint_for, _parse_org_name


# ════════════════════════════════════════════════════════════════════
# Org/name parsing
# ════════════════════════════════════════════════════════════════════


class TestOrgNameParsing:
    def test_standard_org_model(self):
        assert _parse_org_name("models--meta-llama--Llama-3.1-8B-Instruct") == \
            "meta-llama/Llama-3.1-8B-Instruct"

    def test_simple_names(self):
        assert _parse_org_name("models--google--gemma-3-12b-it") == "google/gemma-3-12b-it"
        assert _parse_org_name("models--Qwen--Qwen2.5-14B-Instruct") == "Qwen/Qwen2.5-14B-Instruct"

    def test_no_org_prefix(self):
        # Models without an org are rare but supported
        assert _parse_org_name("models--gpt2") == "gpt2"

    def test_non_models_dir_returns_none(self):
        assert _parse_org_name("not-a-models-dir") is None
        assert _parse_org_name("snapshots") is None
        assert _parse_org_name("") is None


class TestFormatHint:
    def test_safetensors(self):
        assert _format_hint_for("model.safetensors") == "safetensors"
        assert _format_hint_for("model-00001-of-00008.safetensors") == "safetensors"

    def test_gguf(self):
        assert _format_hint_for("llama-q4.gguf") == "gguf"
        assert _format_hint_for("Llama-3.1-8B-Q5_K_M.gguf") == "gguf"

    def test_pytorch_bin(self):
        assert _format_hint_for("pytorch_model.bin") == "pytorch_bin"

    def test_non_weights_returns_none(self):
        assert _format_hint_for("config.json") is None
        assert _format_hint_for("README.md") is None
        assert _format_hint_for("tokenizer.json") is None


# ════════════════════════════════════════════════════════════════════
# HFCacheAdapter — fixture-based
# ════════════════════════════════════════════════════════════════════


@pytest.fixture
def hf_cache_fixture(tmp_path: Path) -> Path:
    """
    Build a synthetic HF cache:
      llama-8B-instruct: sharded (2 shards) → ModelGroup(hf_snapshot)
      gemma-12b-it:      single file        → ModelGroup(single_file)
      no-weights-model:  config only        → no group
    """
    cache = tmp_path / "hub"
    cache.mkdir()

    # Llama: sharded
    llama = cache / "models--meta-llama--Llama-3.1-8B-Instruct"
    (llama / "blobs").mkdir(parents=True)
    (llama / "snapshots" / "rev-llama").mkdir(parents=True)
    (llama / "blobs" / "blob-shard1").write_text("llama shard 1")
    (llama / "blobs" / "blob-shard2").write_text("llama shard 2")
    os.symlink("../../blobs/blob-shard1",
               llama / "snapshots" / "rev-llama" / "model-00001-of-00002.safetensors")
    os.symlink("../../blobs/blob-shard2",
               llama / "snapshots" / "rev-llama" / "model-00002-of-00002.safetensors")

    # Gemma: single file
    gemma = cache / "models--google--gemma-3-12b-it"
    (gemma / "blobs").mkdir(parents=True)
    (gemma / "snapshots" / "rev-gemma").mkdir(parents=True)
    (gemma / "blobs" / "blob-gemma").write_text("gemma single file")
    os.symlink("../../blobs/blob-gemma",
               gemma / "snapshots" / "rev-gemma" / "model.safetensors")
    (gemma / "snapshots" / "rev-gemma" / "config.json").write_text("{}")

    # Empty-snapshot model: no weights
    empty = cache / "models--example--no-weights"
    (empty / "blobs").mkdir(parents=True)
    (empty / "snapshots" / "rev-empty").mkdir(parents=True)
    (empty / "snapshots" / "rev-empty" / "config.json").write_text("{}")

    return cache


class TestHFCacheAdapter:
    def test_discovers_two_groups_with_correct_kinds(self, hf_cache_fixture):
        adapter = HFCacheAdapter(roots=[hf_cache_fixture])
        groups = list(adapter.discover())

        # 2 groups (gemma + llama). The empty-weights model is dropped.
        assert len(groups) == 2

        # Sort for deterministic test
        groups_by_id = {g.claimed_model_id: g for g in groups}
        assert "meta-llama/Llama-3.1-8B-Instruct" in groups_by_id
        assert "google/gemma-3-12b-it" in groups_by_id

        # Llama is sharded → hf_snapshot
        assert groups_by_id["meta-llama/Llama-3.1-8B-Instruct"].group_kind == "hf_snapshot"
        assert len(groups_by_id["meta-llama/Llama-3.1-8B-Instruct"].artifacts) == 2

        # Gemma is single-file
        assert groups_by_id["google/gemma-3-12b-it"].group_kind == "single_file"
        assert len(groups_by_id["google/gemma-3-12b-it"].artifacts) == 1

    def test_artifacts_have_claims_with_hf_cache_path_source(self, hf_cache_fixture):
        adapter = HFCacheAdapter(roots=[hf_cache_fixture])
        groups = list(adapter.discover())
        for g in groups:
            for art in g.artifacts:
                assert art.claim is not None
                assert art.claim.claim_source == "hf_cache_path"
                assert art.claim.model_id == g.claimed_model_id

    def test_artifacts_have_empty_sha256(self, hf_cache_fixture):
        """Adapters DO NOT hash; that's the hashing layer's job."""
        adapter = HFCacheAdapter(roots=[hf_cache_fixture])
        for g in adapter.discover():
            for art in g.artifacts:
                assert art.sha256 == ""

    def test_artifacts_have_filenames_and_resolved_paths(self, hf_cache_fixture):
        adapter = HFCacheAdapter(roots=[hf_cache_fixture])
        groups = list(adapter.discover())
        gemma = next(g for g in groups if g.claimed_model_id == "google/gemma-3-12b-it")
        art = gemma.artifacts[0]
        # Filename comes from the snapshot symlink (the canonical name)
        assert art.filename == "model.safetensors"
        # Path is the resolved blob (what we'll hash)
        assert "blobs" in art.path
        assert art.size_bytes > 0

    def test_empty_root_yields_nothing(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        adapter = HFCacheAdapter(roots=[empty])
        assert list(adapter.discover()) == []

    def test_nonexistent_root_yields_nothing(self, tmp_path):
        nonexistent = tmp_path / "does-not-exist"
        adapter = HFCacheAdapter(roots=[nonexistent])
        assert list(adapter.discover()) == []


# ════════════════════════════════════════════════════════════════════
# PathAdapter — fixture-based
# ════════════════════════════════════════════════════════════════════


@pytest.fixture
def path_fixture(tmp_path: Path) -> Path:
    """
    Build path-adapter fixtures:
      sharded/   - 3-shard model
      single/    - single GGUF
      mixed/     - one safetensors + one loose .bin (should skip .bin)
      not_a_model/ - no weights files
    """
    base = tmp_path / "models"
    base.mkdir()

    sharded = base / "sharded"
    sharded.mkdir()
    (sharded / "model-00001-of-00003.safetensors").write_text("shard 1")
    (sharded / "model-00002-of-00003.safetensors").write_text("shard 2")
    (sharded / "model-00003-of-00003.safetensors").write_text("shard 3")
    (sharded / "config.json").write_text("{}")

    single = base / "single"
    single.mkdir()
    (single / "llama-q4.gguf").write_text("single gguf")

    mixed = base / "mixed"
    mixed.mkdir()
    (mixed / "random.safetensors").write_text("loose safetensors")
    (mixed / "pytorch_model.bin").write_text("loose bin (skip per spec)")

    not_a_model = base / "not_a_model"
    not_a_model.mkdir()
    (not_a_model / "README.md").write_text("# README")

    return base


class TestPathAdapter:
    def test_sharded_directory_grouped(self, path_fixture):
        sharded_dir = path_fixture / "sharded"
        adapter = PathAdapter([sharded_dir])
        groups = list(adapter.discover())
        assert len(groups) == 1
        assert groups[0].group_kind == "sharded_safetensors"
        assert len(groups[0].artifacts) == 3
        # All shards in lexicographic order
        assert [a.filename for a in groups[0].artifacts] == [
            "model-00001-of-00003.safetensors",
            "model-00002-of-00003.safetensors",
            "model-00003-of-00003.safetensors",
        ]

    def test_single_gguf_file_path(self, path_fixture):
        gguf = path_fixture / "single" / "llama-q4.gguf"
        adapter = PathAdapter([gguf])
        groups = list(adapter.discover())
        assert len(groups) == 1
        assert groups[0].group_kind == "single_file"
        assert groups[0].artifacts[0].format_hint == "gguf"

    def test_mixed_directory_skips_loose_bin(self, path_fixture):
        """Per spec §5, standalone .bin files are NOT scanned outside HF cache."""
        mixed_dir = path_fixture / "mixed"
        adapter = PathAdapter([mixed_dir])
        groups = list(adapter.discover())
        assert len(groups) == 1
        assert groups[0].artifacts[0].filename == "random.safetensors"

    def test_no_weights_directory_yields_nothing(self, path_fixture):
        adapter = PathAdapter([path_fixture / "not_a_model"])
        assert list(adapter.discover()) == []

    def test_recursive_walk(self, path_fixture):
        """Walking the parent of all fixtures finds all groups."""
        adapter = PathAdapter([path_fixture])
        groups = list(adapter.discover())
        # 1 sharded + 1 single + 1 mixed = 3 groups (not_a_model is empty)
        assert len(groups) == 3

    def test_skips_models_subdirs_for_hf_cache_safety(self, tmp_path):
        """
        If a user points PathAdapter at a parent that contains a
        models--*/ subdirectory, PathAdapter must NOT descend into it.
        That's HFCacheAdapter's territory.
        """
        parent = tmp_path / "parent"
        parent.mkdir()
        # A bare safetensors in the parent
        (parent / "loose.safetensors").write_text("loose")
        # A models--*/ subdir that PathAdapter should skip
        models_dir = parent / "models--meta-llama--Llama-3.1-8B-Instruct"
        (models_dir / "snapshots" / "rev").mkdir(parents=True)
        (models_dir / "blobs").mkdir()
        (models_dir / "blobs" / "blob1").write_text("would be a shard")
        os.symlink("../../blobs/blob1",
                   models_dir / "snapshots" / "rev" / "model.safetensors")

        adapter = PathAdapter([parent])
        groups = list(adapter.discover())
        # Only the loose.safetensors; the models--*/ contents are skipped
        assert len(groups) == 1
        assert groups[0].artifacts[0].filename == "loose.safetensors"

    def test_nonexistent_path_silently_skipped(self, tmp_path):
        nope = tmp_path / "does-not-exist"
        adapter = PathAdapter([nope])
        assert list(adapter.discover()) == []


# ════════════════════════════════════════════════════════════════════
# Stub adapters
# ════════════════════════════════════════════════════════════════════


class TestStubAdapters:
    def test_ollama_returns_empty_when_no_install(self, tmp_path):
        """OllamaAdapter is now implemented (v0.2). With no Ollama install
        at the resolved root, it yields zero groups instead of raising —
        the CLI relies on this behavior to silently skip the Ollama
        section when scanning a machine without Ollama."""
        adapter = OllamaAdapter(models_root=tmp_path / "no_ollama_here")
        assert list(adapter.discover()) == []

    def test_lmstudio_stub_raises(self):
        adapter = LMStudioAdapter()
        with pytest.raises(NotImplementedError, match="v0.2"):
            list(adapter.discover())
