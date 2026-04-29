"""
Tests for the hashing layer.

Hashing is pure local I/O — no network, no JWS verification. Tests
prove:
  - Bit-exact equivalence with system sha256sum
  - hash_artifact correctly hydrates the sha256 field
  - hash_group hydrates all artifacts in a group
  - OSError on read leaves sha256 empty (downstream skips)
  - Helpers (total_bytes, total_artifacts) sum correctly
"""

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from fallrisk_trustfall.hashing import (
    DEFAULT_CHUNK_SIZE,
    hash_artifact,
    hash_file,
    hash_group,
    hash_groups,
    total_artifacts,
    total_bytes,
)
from fallrisk_trustfall.models import ArtifactCandidate, ModelGroup


# ════════════════════════════════════════════════════════════════════
# hash_file
# ════════════════════════════════════════════════════════════════════


class TestHashFile:
    def test_matches_system_sha256sum(self, tmp_path):
        """Our streaming hash must produce identical output to sha256sum."""
        f = tmp_path / "data.bin"
        f.write_bytes(b"the quick brown fox jumps over the lazy dog\n")

        ours = hash_file(f)

        result = subprocess.run(
            ["sha256sum", str(f)], capture_output=True, text=True
        )
        system = result.stdout.split()[0]

        assert ours == system

    def test_known_empty_file_hash(self, tmp_path):
        """SHA-256 of empty file is well-known: e3b0c44...b855."""
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        assert hash_file(f) == (
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_known_known_string(self, tmp_path):
        """SHA-256 of 'abc' is well-known: ba7816bf...0015a."""
        f = tmp_path / "abc.bin"
        f.write_bytes(b"abc")
        assert hash_file(f) == (
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )

    def test_lowercase_hex_output(self, tmp_path):
        """Output must be lowercase per spec §6.1 (API requirement)."""
        f = tmp_path / "data.bin"
        f.write_bytes(b"some content")
        digest = hash_file(f)
        assert digest == digest.lower()
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_chunk_boundary_correctness(self, tmp_path):
        """Streaming across chunk boundaries must match a single-buffer hash."""
        # Write a file that's slightly larger than the default chunk size
        f = tmp_path / "large.bin"
        content = b"x" * (DEFAULT_CHUNK_SIZE + 1024)
        f.write_bytes(content)

        ours = hash_file(f)
        reference = hashlib.sha256(content).hexdigest()
        assert ours == reference

    def test_small_chunk_size_matches_default(self, tmp_path):
        """Different chunk sizes must produce identical output."""
        f = tmp_path / "data.bin"
        f.write_bytes(b"x" * 10000)

        small = hash_file(f, chunk_size=128)
        default = hash_file(f, chunk_size=DEFAULT_CHUNK_SIZE)
        assert small == default

    def test_raises_on_nonexistent_file(self, tmp_path):
        with pytest.raises(OSError):
            hash_file(tmp_path / "does-not-exist")


# ════════════════════════════════════════════════════════════════════
# hash_artifact
# ════════════════════════════════════════════════════════════════════


def _make_artifact(path: Path) -> ArtifactCandidate:
    """Helper: build a candidate for the given file path."""
    return ArtifactCandidate(
        sha256="",
        size_bytes=path.stat().st_size,
        format_hint="safetensors",
        source="path",
        path=str(path),
        filename=path.name,
        claim=None,
    )


class TestHashArtifact:
    def test_populates_sha256(self, tmp_path):
        f = tmp_path / "weights.safetensors"
        f.write_bytes(b"weight data")
        candidate = _make_artifact(f)

        hydrated = hash_artifact(candidate)
        assert hydrated.sha256 != ""
        assert hydrated.sha256 == hashlib.sha256(b"weight data").hexdigest()

    def test_returns_new_instance(self, tmp_path):
        """Frozen dataclass: must return a new instance, not mutate input."""
        f = tmp_path / "data.bin"
        f.write_bytes(b"content")
        original = _make_artifact(f)

        hydrated = hash_artifact(original)
        assert hydrated is not original
        assert original.sha256 == ""  # original untouched

    def test_preserves_other_fields(self, tmp_path):
        f = tmp_path / "model.safetensors"
        f.write_bytes(b"data")
        candidate = _make_artifact(f)
        hydrated = hash_artifact(candidate)

        assert hydrated.size_bytes == candidate.size_bytes
        assert hydrated.format_hint == candidate.format_hint
        assert hydrated.source == candidate.source
        assert hydrated.path == candidate.path
        assert hydrated.filename == candidate.filename
        assert hydrated.claim == candidate.claim

    def test_unreadable_file_leaves_sha256_empty(self, tmp_path):
        """Read failure must NOT raise; downstream treats empty sha256 as skip."""
        # Build a candidate pointing at a nonexistent file
        candidate = ArtifactCandidate(
            sha256="",
            size_bytes=0,
            format_hint="safetensors",
            source="path",
            path=str(tmp_path / "nonexistent"),
            filename="nonexistent",
            claim=None,
        )
        hydrated = hash_artifact(candidate)
        assert hydrated.sha256 == ""


# ════════════════════════════════════════════════════════════════════
# hash_group / hash_groups
# ════════════════════════════════════════════════════════════════════


class TestHashGroup:
    def test_hydrates_all_artifacts_in_group(self, tmp_path):
        a = tmp_path / "shard1.safetensors"
        b = tmp_path / "shard2.safetensors"
        a.write_bytes(b"shard 1 data")
        b.write_bytes(b"shard 2 data")

        group = ModelGroup(
            group_id="test-group",
            source="path",
            group_kind="sharded_safetensors",
            artifacts=(_make_artifact(a), _make_artifact(b)),
        )

        hydrated = hash_group(group)
        assert all(art.sha256 != "" for art in hydrated.artifacts)
        assert hydrated.artifacts[0].sha256 == hashlib.sha256(b"shard 1 data").hexdigest()
        assert hydrated.artifacts[1].sha256 == hashlib.sha256(b"shard 2 data").hexdigest()

    def test_preserves_group_metadata(self, tmp_path):
        f = tmp_path / "model.safetensors"
        f.write_bytes(b"data")
        group = ModelGroup(
            group_id="test-id",
            source="hf_cache",
            group_kind="single_file",
            artifacts=(_make_artifact(f),),
            claimed_model_id="test/model",
        )

        hydrated = hash_group(group)
        assert hydrated.group_id == "test-id"
        assert hydrated.source == "hf_cache"
        assert hydrated.group_kind == "single_file"
        assert hydrated.claimed_model_id == "test/model"


class TestHashGroups:
    def test_hydrates_multiple_groups(self, tmp_path):
        f1 = tmp_path / "a.safetensors"
        f2 = tmp_path / "b.safetensors"
        f1.write_bytes(b"a")
        f2.write_bytes(b"b")

        groups = [
            ModelGroup(
                group_id="g1", source="path", group_kind="single_file",
                artifacts=(_make_artifact(f1),),
            ),
            ModelGroup(
                group_id="g2", source="path", group_kind="single_file",
                artifacts=(_make_artifact(f2),),
            ),
        ]

        hydrated = hash_groups(groups)
        assert len(hydrated) == 2
        assert all(g.artifacts[0].sha256 != "" for g in hydrated)

    def test_empty_input_returns_empty(self):
        assert hash_groups([]) == []


# ════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════


class TestSizeHelpers:
    def _build_groups(self, sizes: list[list[int]]) -> list[ModelGroup]:
        """Build groups with the given per-artifact sizes (test-only synthetic)."""
        groups = []
        for gi, group_sizes in enumerate(sizes):
            artifacts = tuple(
                ArtifactCandidate(
                    sha256="",
                    size_bytes=s,
                    format_hint="safetensors",
                    source="path",
                    path=f"/fake/g{gi}/a{ai}",
                    filename=f"a{ai}",
                    claim=None,
                )
                for ai, s in enumerate(group_sizes)
            )
            groups.append(ModelGroup(
                group_id=f"g{gi}", source="path",
                group_kind="single_file" if len(group_sizes) == 1 else "sharded_safetensors",
                artifacts=artifacts,
            ))
        return groups

    def test_total_bytes(self):
        groups = self._build_groups([[100, 200], [50], [1000, 2000, 3000]])
        # 300 + 50 + 6000 = 6350
        assert total_bytes(groups) == 6350

    def test_total_artifacts(self):
        groups = self._build_groups([[100, 200], [50], [1, 2, 3]])
        # 2 + 1 + 3 = 6
        assert total_artifacts(groups) == 6

    def test_empty_input(self):
        assert total_bytes([]) == 0
        assert total_artifacts([]) == 0


# ════════════════════════════════════════════════════════════════════
# v0.2: Ollama fast-path mode (--trust-ollama-filenames)
# ════════════════════════════════════════════════════════════════════


from fallrisk_trustfall.hashing import (
    _digest_from_ollama_filename,
    unique_artifacts,
    unique_bytes,
    was_filename_trusted,
)
from fallrisk_trustfall.models import Claim


class TestOllamaFilenameDigestExtraction:
    """The fast-path filename parser must be strict about format."""

    def test_extracts_valid_digest(self):
        digest = "0" * 64
        assert _digest_from_ollama_filename(f"sha256-{digest}") == digest

    def test_rejects_wrong_length(self):
        # 63 hex chars - one short
        assert _digest_from_ollama_filename("sha256-" + "a" * 63) is None
        # 65 hex chars - one long
        assert _digest_from_ollama_filename("sha256-" + "a" * 65) is None

    def test_rejects_uppercase_hex(self):
        # Strict: lowercase only (matches Ollama's actual filenames)
        assert _digest_from_ollama_filename("sha256-" + "A" * 64) is None

    def test_rejects_non_hex_chars(self):
        # 'g' is not hex
        assert _digest_from_ollama_filename("sha256-g" + "0" * 63) is None

    def test_rejects_wrong_prefix(self):
        # Wrong algorithm prefix
        assert _digest_from_ollama_filename("md5-" + "a" * 64) is None
        # Missing dash
        assert _digest_from_ollama_filename("sha256" + "a" * 65) is None


class TestHashArtifactOllamaFastPath:
    """When --trust-ollama-filenames is on, Ollama blobs use the filename digest."""

    def test_fast_path_uses_filename_for_ollama_blob(self, tmp_path: Path):
        """Real digest goes in via filename, no bytes are hashed."""
        digest = "0123456789abcdef" * 4  # 64 hex chars
        blob = tmp_path / f"sha256-{digest}"
        # Write CONTENT that hashes to something different
        blob.write_bytes(b"definitely not the contents matching that digest")

        candidate = ArtifactCandidate(
            sha256="",
            size_bytes=blob.stat().st_size,
            format_hint="ollama_blob",
            source="ollama",
            path=str(blob),
            filename=blob.name,
            claim=Claim(model_id="ollama/library/x:y", claim_source="ollama_manifest"),
        )

        result = hash_artifact(candidate, trust_ollama_filenames=True)
        # Filename digest used, NOT content hash
        assert result.sha256 == digest

    def test_default_path_hashes_content_for_ollama_blob(self, tmp_path: Path):
        """Without the flag, Ollama blobs are content-hashed normally."""
        digest = "0123456789abcdef" * 4
        blob = tmp_path / f"sha256-{digest}"
        content = b"different content"
        blob.write_bytes(content)

        candidate = ArtifactCandidate(
            sha256="",
            size_bytes=blob.stat().st_size,
            format_hint="ollama_blob",
            source="ollama",
            path=str(blob),
            filename=blob.name,
            claim=Claim(model_id="ollama/library/x:y", claim_source="ollama_manifest"),
        )

        # Default mode: hash the actual content
        result = hash_artifact(candidate, trust_ollama_filenames=False)
        expected = hashlib.sha256(content).hexdigest()
        assert result.sha256 == expected
        assert result.sha256 != digest  # filename and content disagree (test setup)

    def test_fast_path_falls_back_on_malformed_filename(self, tmp_path: Path):
        """Malformed Ollama filename (not 'sha256-<64hex>') falls back to content hash."""
        blob = tmp_path / "sha256-not-a-real-digest"
        blob.write_bytes(b"x")
        candidate = ArtifactCandidate(
            sha256="",
            size_bytes=1,
            format_hint="ollama_blob",
            source="ollama",
            path=str(blob),
            filename=blob.name,
            claim=Claim(model_id="ollama/x/y:z", claim_source="ollama_manifest"),
        )
        result = hash_artifact(candidate, trust_ollama_filenames=True)
        # Fell back to content hash
        assert result.sha256 == hashlib.sha256(b"x").hexdigest()

    def test_fast_path_does_not_apply_to_non_ollama_artifacts(self, tmp_path: Path):
        """HF cache safetensors must be content-hashed regardless of flag."""
        f = tmp_path / "model.safetensors"
        content = b"safetensors bytes"
        f.write_bytes(content)
        candidate = ArtifactCandidate(
            sha256="",
            size_bytes=len(content),
            format_hint="safetensors",
            source="hf_cache",
            path=str(f),
            filename=f.name,
        )
        result = hash_artifact(candidate, trust_ollama_filenames=True)
        # Trust flag is irrelevant for non-ollama_blob format
        assert result.sha256 == hashlib.sha256(content).hexdigest()


class TestWasFilenameTrustedQuery:
    """The query function correctly identifies filename-trusted artifacts."""

    def test_returns_true_for_ollama_blob_in_fast_path(self):
        digest = "a" * 64
        candidate = ArtifactCandidate(
            sha256=digest,
            size_bytes=100,
            format_hint="ollama_blob",
            source="ollama",
            path="/path",
            filename=f"sha256-{digest}",
        )
        assert was_filename_trusted(candidate, trust_ollama_filenames=True) is True

    def test_returns_false_when_flag_off(self):
        digest = "a" * 64
        candidate = ArtifactCandidate(
            sha256=digest,
            size_bytes=100,
            format_hint="ollama_blob",
            source="ollama",
            path="/path",
            filename=f"sha256-{digest}",
        )
        # Even though sha256 matches filename, we hashed it ourselves
        assert was_filename_trusted(candidate, trust_ollama_filenames=False) is False

    def test_returns_false_for_non_ollama(self):
        candidate = ArtifactCandidate(
            sha256="a" * 64,
            size_bytes=100,
            format_hint="safetensors",
            source="hf_cache",
            path="/path",
            filename="model.safetensors",
        )
        assert was_filename_trusted(candidate, trust_ollama_filenames=True) is False

    def test_returns_false_when_digest_disagrees_with_filename(self):
        """If sha256 was content-hashed and disagrees with filename, not trusted."""
        candidate = ArtifactCandidate(
            sha256="b" * 64,  # different from filename digest
            size_bytes=100,
            format_hint="ollama_blob",
            source="ollama",
            path="/path",
            filename="sha256-" + "a" * 64,
        )
        assert was_filename_trusted(candidate, trust_ollama_filenames=True) is False


class TestUniqueByteAndArtifactCounting:
    """Shared-blob deduplication for storage reporting."""

    def _candidate(self, digest: str, size: int) -> ArtifactCandidate:
        return ArtifactCandidate(
            sha256=digest,
            size_bytes=size,
            format_hint="ollama_blob",
            source="ollama",
            path=f"/blobs/sha256-{digest}",
            filename=f"sha256-{digest}",
        )

    def _group(self, group_id: str, candidates: list[ArtifactCandidate]) -> ModelGroup:
        return ModelGroup(
            group_id=group_id,
            source="ollama",
            group_kind="ollama_manifest",
            artifacts=tuple(candidates),
        )

    def test_unique_bytes_dedups_by_digest(self):
        # Two tags reference the same model blob (real Ollama scenario)
        shared = self._candidate("a" * 64, 4_000_000_000)
        # And one tag with its own unique blob
        unique = self._candidate("b" * 64, 1_000_000_000)
        groups = [
            self._group("library/llama3:8b", [shared]),
            self._group("library/llama3:latest", [shared]),
            self._group("library/mistral:7b", [unique]),
        ]
        # total_bytes counts shared twice (once per group reference)
        assert total_bytes(groups) == 4_000_000_000 + 4_000_000_000 + 1_000_000_000
        # unique_bytes counts shared once
        assert unique_bytes(groups) == 4_000_000_000 + 1_000_000_000

    def test_unique_artifacts_dedups_by_digest(self):
        shared = self._candidate("a" * 64, 100)
        unique = self._candidate("b" * 64, 100)
        groups = [
            self._group("g1", [shared]),
            self._group("g2", [shared]),
            self._group("g3", [unique]),
        ]
        assert total_artifacts(groups) == 3
        assert unique_artifacts(groups) == 2

    def test_unique_excludes_empty_sha256(self):
        """Failed-to-hash artifacts contribute to total but not to unique."""
        valid = self._candidate("a" * 64, 100)
        failed = ArtifactCandidate(
            sha256="",  # hashing failed
            size_bytes=999,
            format_hint="ollama_blob",
            source="ollama",
            path="/blobs/missing",
            filename="sha256-missing",
        )
        groups = [self._group("g1", [valid, failed])]
        assert total_artifacts(groups) == 2
        assert unique_artifacts(groups) == 1
        assert total_bytes(groups) == 1099
        assert unique_bytes(groups) == 100  # failed excluded
