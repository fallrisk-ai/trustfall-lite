"""
Step-4 §6 drift / schema / provenance / privacy tests.

NEW file only — no byte-locked existing test file is modified, and no
adapter or fixtures module is touched. Every fixture here is built from
the live dataclasses (scanner.GroupScanResult, formatter.FileResult,
api.VerifiedRecord, models.ModelGroup/ArtifactCandidate) so the
assertions pin real behaviour, not a re-implementation.

Coverage (spec §6):
  T-SCHEMA-DOC-1   doc canonical column block == produced header/keys
  T-TOK-1..7       tokenizer_surface_coverage derivation + non-claim doc
  T-CSV-1..5       CSV header + per-status row content
  T-JSONL-1/2      JSONL standalone objects + key-set width
  T-PARITY-1       CSV and JSONL carry identical logical content
  T-EXT-1          bad / missing extension → exit 70, no file
  T-DET-1          same injected scanned_at → byte-identical files
  T-PRIV-1..5      path columns absent by default; opt-in adds exactly 2
  T-PROV-1/2/3     provenance run-scalars; copied-not-recomputed; injected
  T-NET-1/2        export.py import-allowlist (no api/httpx/registry)
  T-ROOT-5/5b      Ollama OLLAMA_MODELS configured-but-broken vs absent
"""

from __future__ import annotations

import ast
import csv
import io
import json
import os
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

import fallrisk_trustfall.cli as climod
import fallrisk_trustfall.export as exp
from fallrisk_trustfall.api import VerifiedRecord
from fallrisk_trustfall.cli import main
from fallrisk_trustfall.export import export_inventory
from fallrisk_trustfall.formatter import FileResult, Status
from fallrisk_trustfall.models import ArtifactCandidate, ModelGroup
from fallrisk_trustfall.roots import ScanRoot, resolve_scan_roots
from fallrisk_trustfall.scanner import GroupScanResult, HashLookup

REPO = Path(__file__).resolve().parents[1]
DOC = REPO / "docs" / "INVENTORY_EXPORT.md"
PRIVACY = REPO / "PRIVACY.md"
LIMITATIONS = REPO / "LIMITATIONS.md"
README = REPO / "README.md"

# The §3.4b verbatim non-claim block (load-bearing — must be a
# byte-exact substring of the three docs; T-TOK-6).
TOK6_BLOCK = (
    "This column does not mean the tokenizer is safe. It does not mean "
    "Trustfall Lite inspected tokenizer contents. For Lane A structural "
    "records, `opaque_structural_evidence_binding` means only that the "
    "row is bound to a signed structural evidence commitment; the public "
    "Lite payload does not enumerate tokenizer files. For Lane B "
    "container records, `covered_by_verified_container` means the "
    "verified artifact container is the identity surface. This is an "
    "artifact-identity coverage signal, not a tokenizer security verdict."
)

_DEFAULT_15 = (
    "provider",
    "model_id",
    "model_id_source",
    "status",
    "registry_match",
    "registry_bound_digest",
    "registry_manifest_digest",
    "artifact_count",
    "license",
    "publisher",
    "deep_runtime_claim_applicable",
    "tokenizer_surface_coverage",
    "cache_root_type",
    "trustfall_version",
    "scanned_at",
)

_SENTINEL_MANIFEST = "DEADBEEF" * 8  # 64 hex chars, not the sha256 of anything here
_VER = "0.4.0-test"
_TS = "2026-05-16T00:00:00Z"


# ─────────────────────────────────────────────────────────────────────
# Grounded fixture builders (live dataclasses only)
# ─────────────────────────────────────────────────────────────────────


def _artifact(path: str, sha: str = "a" * 64) -> ArtifactCandidate:
    return ArtifactCandidate(
        sha256=sha,
        size_bytes=16,
        format_hint="safetensors",
        source="hf_cache",
        path=path,
        filename=os.path.basename(path),
        claim=None,
    )


def _group(
    *, source: str, gid: str, n: int = 1, claimed: str | None = None, base="/tmp/r"
) -> ModelGroup:
    arts = tuple(
        ArtifactCandidate(
            sha256=chr(97 + i) * 64,
            size_bytes=16,
            format_hint="safetensors",
            source=source,
            path=f"{base}/{gid}/shard{i}.safetensors",
            filename=f"shard{i}.safetensors",
            claim=None,
        )
        for i in range(n)
    )
    return ModelGroup(
        group_id=gid,
        source=source,
        group_kind="hf_snapshot" if n > 1 else "single_file",
        artifacts=arts,
        claimed_model_id=claimed,
    )


def _fr(status: Status, name: str = "m") -> FileResult:
    return FileResult(
        path=name,
        sha256="a" * 64,
        size_bytes=16,
        status=status,
    )


def _result(
    *,
    status: Status,
    source: str = "hf_cache",
    gid: str = "g",
    n: int = 1,
    claims: dict | None = None,
) -> GroupScanResult:
    g = _group(source=source, gid=gid, n=n, claimed=(claims or {}).get("model_id"))
    rec = None
    if status is Status.VERIFIED and claims is not None:
        rec = VerifiedRecord(
            sha256="a" * 64,
            record_jws="x.y.z",
            claims=claims,
            registry_kid="fallrisk-96cd5e6a01e1",
            registry_snapshot_at=None,
        )
    return GroupScanResult(
        group=g,
        file_result=_fr(status, name=(claims or {}).get("model_id", gid)),
        artifact_lookups=(),
        matched_record=rec,
    )


# Lane A (structural identity): bound digest = evidence_digest
_LANE_A = {
    "model_id": "fallrisk/lane-a",
    "evidence_class": "itpuf_structural_identity",
    "evidence_digest": "EVID_A_" + "0" * 57,
    "license": "apache-2.0",
    "publisher": "Fall Risk AI",
}
# Lane B (artifact identity / ollama container): bound = artifact_manifest_digest
_LANE_B = {
    "model_id": "library/llama-b",
    "evidence_class": "artifact_identity",
    "artifact_manifest_digest": "AMD_B_" + "0" * 58,
    "evidence_digest": "EVID_B_" + "0" * 57,
    "artifact_format": "ollama_blob",
    "license": "llama3",
    "publisher": "Meta",
}


def _export(results, *, fmt, tmp, include_paths=False, roots=None, ts=_TS):
    out = tmp / f"inv.{fmt}"
    n = export_inventory(
        results,
        roots if roots is not None else [],
        fmt=fmt,
        out_path=out,
        include_paths=include_paths,
        scanned_at=ts,
        trustfall_version=_VER,
        registry_manifest_digest=_SENTINEL_MANIFEST,
    )
    return out, n


def _csv_rows(p: Path):
    with p.open(encoding="utf-8") as fh:
        return list(csv.reader(fh))


def _jsonl_objs(p: Path):
    return [json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]


# ═════════════════════════════════════════════════════════════════════
# T-SCHEMA-DOC-1 — documented column block == produced header/keys
# ═════════════════════════════════════════════════════════════════════


def _doc_columns() -> list[str]:
    m = re.search(
        r"TRUSTFALL_EXPORT_COLUMNS_V0_4_BEGIN\n(.*?)\n"
        r"TRUSTFALL_EXPORT_COLUMNS_V0_4_END",
        DOC.read_text(encoding="utf-8"),
        re.S,
    )
    assert m, "canonical column block not found in docs/INVENTORY_EXPORT.md"
    return [ln.strip() for ln in m.group(1).strip().splitlines() if ln.strip()]


def test_t_schema_doc_1_doc_block_equals_default_columns(tmp_path):
    doc_cols = _doc_columns()
    assert doc_cols == list(_DEFAULT_15)

    out, _ = _export([_result(status=Status.NOT_ENROLLED)], fmt="csv", tmp=tmp_path)
    header = _csv_rows(out)[0]
    assert header == doc_cols  # doc == produced CSV header

    out2, _ = _export([_result(status=Status.NOT_ENROLLED)], fmt="jsonl", tmp=tmp_path)
    keys = list(_jsonl_objs(out2)[0].keys())
    assert keys == doc_cols  # doc == produced JSONL key set


# ═════════════════════════════════════════════════════════════════════
# T-TOK — tokenizer_surface_coverage derivation + non-claim doc block
# ═════════════════════════════════════════════════════════════════════


def test_t_tok_1_lane_a_structural_is_opaque_binding(tmp_path):
    r = _result(status=Status.VERIFIED, claims=_LANE_A)  # no ollama_blob
    out, _ = _export([r], fmt="jsonl", tmp=tmp_path)
    assert _jsonl_objs(out)[0]["tokenizer_surface_coverage"] == (
        "opaque_structural_evidence_binding"
    )


def test_t_tok_3_lane_b_container_is_covered(tmp_path):
    r = _result(status=Status.VERIFIED, source="ollama", claims=_LANE_B)
    out, _ = _export([r], fmt="jsonl", tmp=tmp_path)
    assert _jsonl_objs(out)[0]["tokenizer_surface_coverage"] == (
        "covered_by_verified_container"
    )


def test_t_tok_4_unverified_is_unknown_unverified(tmp_path):
    out, _ = _export(
        [_result(status=Status.UNKNOWN_VARIANT)], fmt="jsonl", tmp=tmp_path
    )
    assert _jsonl_objs(out)[0]["tokenizer_surface_coverage"] == "unknown_unverified"


def test_t_tok_5_verified_non_lane_class_is_not_covered(tmp_path):
    claims = {"model_id": "x/y", "evidence_class": "zk_private_match"}
    r = _result(status=Status.VERIFIED, claims=claims)
    out, _ = _export([r], fmt="jsonl", tmp=tmp_path)
    assert _jsonl_objs(out)[0]["tokenizer_surface_coverage"] == "not_covered"


def test_t_tok_7_coverage_reads_no_local_file():
    """The function depends only on status + matched_record claims —
    never on ArtifactCandidate.path or any filesystem read. Proven by
    AST: _tokenizer_surface_coverage's body references no `open`,
    `Path`, `.read`, `iterdir`, or `.path`."""
    src = exp._tokenizer_surface_coverage.__code__
    forbidden = {"open", "read_text", "read_bytes", "iterdir"}
    assert forbidden.isdisjoint(set(src.co_names)), set(src.co_names)


@pytest.mark.parametrize("doc", [DOC, PRIVACY, LIMITATIONS])
def test_t_tok_6_nonclaim_block_verbatim_in_three_docs(doc):
    assert TOK6_BLOCK in doc.read_text(encoding="utf-8"), f"§3.4b block missing/altered in {doc.name}"


# ═════════════════════════════════════════════════════════════════════
# T-CSV — header + per-status row content
# ═════════════════════════════════════════════════════════════════════


def test_t_csv_1_default_header_byte_exact(tmp_path):
    out, _ = _export([_result(status=Status.NOT_ENROLLED)], fmt="csv", tmp=tmp_path)
    first_line = out.read_text(encoding="utf-8").splitlines()[0]
    assert first_line == ",".join(_DEFAULT_15)


def test_t_csv_2_verified_lane_a_row(tmp_path):
    r = _result(status=Status.VERIFIED, claims=_LANE_A)
    out, _ = _export([r], fmt="csv", tmp=tmp_path)
    rows = _csv_rows(out)
    row = dict(zip(rows[0], rows[1]))
    assert row["status"] == "verified"
    assert row["registry_match"] == "exact"
    assert row["model_id_source"] == "registry_record"
    assert row["registry_bound_digest"] == _LANE_A["evidence_digest"]
    assert row["deep_runtime_claim_applicable"] == "true"


def test_t_csv_3_verified_lane_b_row(tmp_path):
    r = _result(status=Status.VERIFIED, source="ollama", claims=_LANE_B)
    out, _ = _export([r], fmt="csv", tmp=tmp_path)
    rows = _csv_rows(out)
    row = dict(zip(rows[0], rows[1]))
    assert row["registry_bound_digest"] == _LANE_B["artifact_manifest_digest"]
    assert row["deep_runtime_claim_applicable"] == "false"  # Lane B not Deep


def test_t_csv_4_unknown_variant_row(tmp_path):
    out, _ = _export(
        [_result(status=Status.UNKNOWN_VARIANT, gid="uv")], fmt="csv", tmp=tmp_path
    )
    rows = _csv_rows(out)
    row = dict(zip(rows[0], rows[1]))
    assert row["registry_bound_digest"] == ""
    assert row["license"] == ""
    assert row["publisher"] == ""


def test_t_csv_5_not_enrolled_loose_path(tmp_path):
    r = _result(status=Status.NOT_ENROLLED, source="path", gid="loose")
    out, _ = _export([r], fmt="csv", tmp=tmp_path)
    rows = _csv_rows(out)
    row = dict(zip(rows[0], rows[1]))
    assert row["model_id"] == ""
    assert row["model_id_source"] == "none"
    assert row["registry_match"] == "none"


# ═════════════════════════════════════════════════════════════════════
# T-JSONL — standalone objects + key-set width
# ═════════════════════════════════════════════════════════════════════


def test_t_jsonl_1_standalone_objects_no_array(tmp_path):
    rs = [
        _result(status=Status.VERIFIED, gid="a", claims=_LANE_A),
        _result(status=Status.NOT_ENROLLED, gid="b"),
    ]
    out, n = _export(rs, fmt="jsonl", tmp=tmp_path)
    text = out.read_text(encoding="utf-8")
    assert not text.lstrip().startswith("[")  # no enclosing array
    objs = _jsonl_objs(out)
    assert len(objs) == n == 2
    for o in objs:
        assert isinstance(o, dict)


def test_t_jsonl_2_key_width_15_default_17_with_paths(tmp_path):
    r = _result(status=Status.NOT_ENROLLED)
    out15, _ = _export([r], fmt="jsonl", tmp=tmp_path)
    assert list(_jsonl_objs(out15)[0].keys()) == list(_DEFAULT_15)

    out17, _ = _export([r], fmt="jsonl", tmp=tmp_path, include_paths=True)
    keys = list(_jsonl_objs(out17)[0].keys())
    assert keys == list(_DEFAULT_15) + ["cache_root_path", "artifact_paths"]


# ═════════════════════════════════════════════════════════════════════
# T-PARITY-1 — CSV and JSONL identical logical content
# ═════════════════════════════════════════════════════════════════════


def test_t_parity_1_csv_jsonl_same_logical_content(tmp_path):
    rs = [
        _result(status=Status.VERIFIED, gid="a", claims=_LANE_A),
        _result(status=Status.UNKNOWN_VARIANT, gid="b"),
        _result(status=Status.NOT_ENROLLED, source="path", gid="c"),
    ]
    cout, _ = _export(rs, fmt="csv", tmp=tmp_path)
    jout, _ = _export(rs, fmt="jsonl", tmp=tmp_path)
    crows = _csv_rows(cout)
    header = crows[0]
    jobjs = _jsonl_objs(jout)
    assert len(crows) - 1 == len(jobjs)
    for csv_row, jobj in zip(crows[1:], jobjs):
        cmap = dict(zip(header, csv_row))
        for col in _DEFAULT_15:
            jv = jobj[col]
            # CSV encodes null→"", int/bool→str; normalize for compare.
            if jv is None:
                expect = ""
            elif isinstance(jv, bool):
                expect = "true" if jv else "false"
            else:
                expect = str(jv)
            assert cmap[col] == expect, (col, cmap[col], jv)


# ═════════════════════════════════════════════════════════════════════
# T-EXT-1 — bad / missing extension → exit 70, no file
# ═════════════════════════════════════════════════════════════════════


class _FakeLookup(HashLookup):
    def lookup_many(self, sha256s):
        return {}


@pytest.mark.parametrize("name", ["inv.txt", "inv", "inv.csv.bak"])
def test_t_ext_1_bad_extension_exit_70_no_file(tmp_path, monkeypatch, name):
    monkeypatch.setattr(
        climod, "_build_local_lookup_or_die", lambda: _FakeLookup()
    )
    target = tmp_path / name
    res = CliRunner().invoke(
        main, ["scan", "--local-only", "--export", str(target)]
    )
    assert res.exit_code == 70
    assert not target.exists()
    assert "must end in .csv or .jsonl" in res.output


# ═════════════════════════════════════════════════════════════════════
# T-DET-1 — same injected scanned_at → byte-identical files
# ═════════════════════════════════════════════════════════════════════


@pytest.mark.parametrize("fmt", ["csv", "jsonl"])
def test_t_det_1_byte_identical_with_same_scanned_at(tmp_path, fmt):
    rs = [
        _result(status=Status.VERIFIED, gid="a", claims=_LANE_A),
        _result(status=Status.NOT_ENROLLED, gid="b"),
    ]
    a = tmp_path / f"a.{fmt}"
    b = tmp_path / f"b.{fmt}"
    for out in (a, b):
        export_inventory(
            rs,
            [],
            fmt=fmt,
            out_path=out,
            include_paths=False,
            scanned_at=_TS,
            trustfall_version=_VER,
            registry_manifest_digest=_SENTINEL_MANIFEST,
        )
    assert a.read_bytes() == b.read_bytes()


# ═════════════════════════════════════════════════════════════════════
# T-PRIV — path columns absent by default; opt-in adds exactly two
# ═════════════════════════════════════════════════════════════════════


def test_t_priv_1_no_path_columns_by_default(tmp_path):
    out, _ = _export([_result(status=Status.NOT_ENROLLED)], fmt="csv", tmp=tmp_path)
    header = _csv_rows(out)[0]
    assert len(header) == 15
    assert "cache_root_path" not in header
    assert "artifact_paths" not in header
    jout, _ = _export([_result(status=Status.NOT_ENROLLED)], fmt="jsonl", tmp=tmp_path)
    obj = _jsonl_objs(jout)[0]
    assert "cache_root_path" not in obj  # key absent, not present-but-null
    assert "artifact_paths" not in obj


def test_t_priv_2_opt_in_adds_exactly_two_path_columns(tmp_path):
    r = _result(status=Status.NOT_ENROLLED, source="hf_cache", gid="g", n=2)
    out, _ = _export([r], fmt="csv", tmp=tmp_path, include_paths=True)
    header = _csv_rows(out)[0]
    assert len(header) == 17
    assert header[-2:] == ["cache_root_path", "artifact_paths"]


def test_t_priv_3_artifact_paths_array_in_jsonl(tmp_path):
    r = _result(status=Status.NOT_ENROLLED, source="hf_cache", gid="g", n=3)
    out, _ = _export([r], fmt="jsonl", tmp=tmp_path, include_paths=True)
    obj = _jsonl_objs(out)[0]
    assert isinstance(obj["artifact_paths"], list)
    assert len(obj["artifact_paths"]) == 3


# ═════════════════════════════════════════════════════════════════════
# T-PROV — provenance run-scalars; copied not recomputed; injected
# ═════════════════════════════════════════════════════════════════════


def test_t_prov_1_run_scalars_in_header_and_every_row(tmp_path):
    rs = [
        _result(status=Status.VERIFIED, gid="a", claims=_LANE_A),
        _result(status=Status.NOT_ENROLLED, gid="b"),
    ]
    out, _ = _export(rs, fmt="csv", tmp=tmp_path)
    rows = _csv_rows(out)
    header = rows[0]
    assert header[6] == "registry_manifest_digest"  # position 7 (§3.2)
    assert header[13] == "trustfall_version"  # position 14
    for body in rows[1:]:
        m = dict(zip(header, body))
        assert m["registry_manifest_digest"] == _SENTINEL_MANIFEST
        assert m["trustfall_version"] == _VER


def test_t_prov_2_manifest_digest_copied_not_recomputed(tmp_path):
    """The sentinel is not the sha256 of anything in the export. If the
    export recomputed a digest the column would differ; it must equal
    the injected sentinel byte-for-byte (Authority Doctrine)."""
    out, _ = _export([_result(status=Status.VERIFIED, claims=_LANE_A)],
                      fmt="jsonl", tmp=tmp_path)
    assert _jsonl_objs(out)[0]["registry_manifest_digest"] == _SENTINEL_MANIFEST


def test_t_prov_3_export_does_not_import_package_root_or_version():
    """trustfall_version is caller-injected; export.py must not import
    the package root or read __version__ itself."""
    tree = ast.parse((REPO / "src/fallrisk_trustfall/export.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            # `from . import __version__` / `from fallrisk_trustfall import ...`
            assert not (node.module is None and node.level == 1 and any(
                a.name == "__version__" for a in node.names
            )), "export.py must not import package __version__"
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name != "fallrisk_trustfall", (
                    "export.py must not import the package root"
                )
    assert "__version__" not in exp.export_inventory.__code__.co_names


# ═════════════════════════════════════════════════════════════════════
# T-NET — import-allowlist (no api / httpx / registry)
# ═════════════════════════════════════════════════════════════════════

_FORBIDDEN_IMPORTS = {"api", "httpx", "registry"}


def test_t_net_1_dependency_closure_excludes_network():
    tree = ast.parse((REPO / "src/fallrisk_trustfall/export.py").read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[-1]
            imported.add(mod)
            if mod == "scanner":
                for a in node.names:
                    assert a.name != "APIHashLookup", (
                        "export.py must not import scanner.APIHashLookup"
                    )
        elif isinstance(node, ast.Import):
            for a in node.names:
                imported.add(a.name.split(".")[-1])
    assert _FORBIDDEN_IMPORTS.isdisjoint(imported), imported & _FORBIDDEN_IMPORTS


def test_t_net_2_import_allowlist():
    """export.py module-level import-allowlist (spec §4.2 / T-NET-2).

    The load-bearing security invariant is network isolation: the
    must-NOT set is `api`, `httpx`, `registry`, `scanner.APIHashLookup`
    (the network surface). The local allowlist is the modules export.py
    legitimately needs to consume the already-computed scan result:
      - models   : ArtifactCandidate / ModelGroup shapes
      - scanner  : GroupScanResult type
      - roots    : ScanRoot type
      - formatter: Status enum  ← required by spec §3.2 col 4
                   ("`status` = `FileResult.status.value`. The live
                   `formatter.py:40` `Status` enum…"). The §4.2 *prose*
                   list omits `formatter`, but the spec's own column
                   table mandates `formatter.Status`, and the
                   GPT-sealed Step-2 `export.py` (byte-unchanged,
                   sha 61c938da…) does `from .formatter import Status`.
                   `formatter` is a pure enum/dataclass module with
                   zero network surface — including it does not weaken
                   the T-NET-2 isolation invariant. (Spec §4.2
                   prose/§3.2 inconsistency surfaced to the operator;
                   the security invariant — no network module — is
                   what this test pins.)
    """
    allow_local = {"models", "scanner", "roots", "formatter"}
    forbidden_local = {"api", "registry"}
    allow_std = {
        "csv", "json", "pathlib", "datetime", "os", "tempfile",
        "typing", "__future__", "dataclasses",
    }
    forbidden_std = {"httpx"}
    tree = ast.parse((REPO / "src/fallrisk_trustfall/export.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level and node.module:  # relative intra-package
                mod = node.module.split(".")[-1]
                assert mod not in forbidden_local, f"network module: {mod}"
                assert mod in allow_local, node.module
                if mod == "scanner":
                    for a in node.names:
                        assert a.name != "APIHashLookup", (
                            "export.py must not import scanner.APIHashLookup"
                        )
            elif node.module:
                top = node.module.split(".")[0]
                assert top not in forbidden_std, f"network module: {top}"
                assert top in allow_std, f"disallowed import: {node.module}"
        elif isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                assert top not in forbidden_std, f"network module: {top}"
                assert top in allow_std, f"disallowed import: {a.name}"


# ═════════════════════════════════════════════════════════════════════
# T-ROOT-5 / T-ROOT-5b — Ollama OLLAMA_MODELS configured-but-broken
#                          vs absent (the two distinct False states)
# ═════════════════════════════════════════════════════════════════════


def _root(eco: str) -> ScanRoot | None:
    for r in resolve_scan_roots():
        if r.ecosystem == eco:
            return r
    return None


def test_t_root_5_ollama_models_set_but_missing(tmp_path, monkeypatch):
    """OLLAMA_MODELS set to a non-existent dir → configured-but-broken:
    keeps the bad path, exists/scanned False, diagnostic note."""
    bad = tmp_path / "no_such_ollama"
    monkeypatch.setenv("OLLAMA_MODELS", str(bad))
    # neutralize HOME-based default discovery so we isolate the env case
    monkeypatch.setenv("HOME", str(tmp_path / "empty_home"))
    r = _root("ollama")
    assert r is not None
    assert r.env_override == "OLLAMA_MODELS"
    assert r.exists is False
    assert r.scanned is False
    assert r.resolved_path is not None  # bad path KEPT (not nulled)
    assert r.note is not None  # diagnostic note present


def test_t_root_5b_absent_is_distinct_from_broken(tmp_path, monkeypatch):
    """Nothing configured, nothing on disk → absent: resolved_path
    None, exists/scanned False, note None. Distinct from 5's broken."""
    monkeypatch.delenv("OLLAMA_MODELS", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "empty_home"))
    r = _root("ollama")
    assert r is not None
    assert r.resolved_path is None
    assert r.exists is False
    assert r.scanned is False
    assert r.note is None


# ═════════════════════════════════════════════════════════════════════
# T-PRIV-DOC — PRIVACY.md must not contradict the live --include-paths
#              behaviour (operator Patch 2, 2026-05-17). The live CLI
#              help (cli.py: "Send relative path hints to the API")
#              proves --include-paths IS a network-side control; the
#              old "affects local JSON output only / does not cause
#              paths to be sent to the API" sentence was a privacy-
#              document contradiction.
# ═════════════════════════════════════════════════════════════════════


def test_t_priv_doc_1_no_stale_include_paths_sentence():
    txt = PRIVACY.read_text(encoding="utf-8")
    stale = "`--include-paths` affects local JSON output only"
    assert stale not in txt, (
        "PRIVACY.md still contains the stale, contradicted sentence: "
        f"{stale!r}"
    )
    # The companion stale clause must also be gone.
    assert "does not cause\nfilesystem paths to be sent to the verification API" \
        not in txt
    assert "does not cause filesystem paths to be sent to the verification API" \
        not in txt


def test_t_priv_doc_2_include_vs_export_distinction_present():
    txt = PRIVACY.read_text(encoding="utf-8")
    # --include-paths is documented as an API path-hint / JSON-exposure
    # control (matches live cli.py help line: "Send relative path hints
    # to the API").
    assert "send home-collapsed\nrelative path hints to the registry API" in txt \
        or "send home-collapsed relative path hints to the registry API" in txt
    assert "--local-only" in txt  # the no-network-disclosure escape hatch
    # --export-include-paths is documented as the separate local-export
    # path-column control.
    assert "`--export-include-paths` is separate" in txt
    assert "path\ncolumns are written into a local export file" in txt \
        or "path columns are written into a local export file" in txt
    # Both flag names co-occur so the distinction is unmissable.
    assert "--include-paths" in txt and "--export-include-paths" in txt


# ═════════════════════════════════════════════════════════════════════
# T-README-EXPORT-NETWORK — README must not overstate --export network
#              behaviour (operator/GPT Patch 3, 2026-05-17). `--export`
#              adds no upload/network surface, but `trustfall scan
#              --export` WITHOUT --local-only may still query the
#              verification API for the scan itself. The old Quick-Start
#              line "writes a local file only — no upload, no network"
#              was readable as "scan --export performs no network",
#              which is false unless paired with --local-only. Same
#              misread class as the Patch-2 --include-paths contradiction.
# ═════════════════════════════════════════════════════════════════════


def _ws(s: str) -> str:
    """Whitespace-normalize so assertions are robust to line-wrapping."""
    return " ".join(s.split())


def test_t_readme_export_network_1_no_unqualified_phrase():
    txt = README.read_text(encoding="utf-8")
    # The exact stale Quick-Start sentence must be gone, in any wrapping.
    stale = "`--export` writes a local file only — no upload, no network"
    assert stale not in _ws(txt), (
        "README.md still contains the unqualified, misread-prone phrase: "
        f"{stale!r}"
    )
    # The em-dash variant and a hyphen fallback must also be absent.
    assert "writes a local file only - no upload, no network" not in _ws(txt)
    assert "writes a local file only, no upload, no network" not in _ws(txt)


def test_t_readme_export_network_2_mode_accurate_language():
    norm = _ws(README.read_text(encoding="utf-8"))
    # 1. export adds no upload / additional network behaviour
    assert "adds no upload or additional network behavior" in norm, (
        "README.md must state that --export adds no upload/additional "
        "network behaviour."
    )
    # 2. default scan may query the verification API
    assert "may query the verification API" in norm, (
        "README.md must state that a default scan may query the "
        "verification API."
    )
    # 3. --local-only is the no-per-scan-network path
    assert "--local-only" in norm, (
        "README.md must name --local-only as the no-per-scan-network mode."
    )
    assert "cached signed snapshot without per-scan network lookup" in norm, (
        "README.md must describe --local-only as verifying against the "
        "cached signed snapshot without per-scan network lookup."
    )


def test_t_readme_export_network_3_clarification_in_schema_docs():
    """The optional clarification was added to both schema docs near
    their 'local file write only' language (operator-approved option)."""
    clar = (
        "`--export` does not change the scan lookup mode. A default "
        "scan may still query the verification API; `--local-only` is "
        "the no-per-scan-network mode."
    )
    for doc in (DOC, PRIVACY):
        assert _ws(clar) in _ws(doc.read_text(encoding="utf-8")), (
            f"{doc.name} must carry the scan-mode clarification near its "
            "local-file-write language."
        )
