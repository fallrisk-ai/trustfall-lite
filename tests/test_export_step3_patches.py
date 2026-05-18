"""
GPT Step-3 blocking-patch regression tests.

These pin the three patches the adversarial Step-3 review required and
that were proven by execution before being committed here:

  Patch 1  — invocation-aware scan roots (cli._resolve_scan_roots_for_invocation)
  Patch 2  — containment join for the export cache_root_path
             (export._scan_root_for, GPT tests T-ROOT-MATCH-1/2/3)
  Patch 3  — no-groups branch resolves roots BEFORE exiting and can
             still emit a 0-row export

New file only — no byte-locked existing test file is modified.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from click.testing import CliRunner

import fallrisk_trustfall.cli as climod
import fallrisk_trustfall.export as exp
import fallrisk_trustfall.roots as rootsmod
from fallrisk_trustfall.cli import (
    _resolve_scan_roots_for_invocation,
    main,
)
from fallrisk_trustfall.roots import ScanRoot
from fallrisk_trustfall.scanner import HashLookup


class _FakeLookup(HashLookup):
    """Status-agnostic stub: every artifact resolves not_enrolled.

    The Step-3 wiring is status-independent, so an empty lookup is a
    sufficient fixture and keeps these tests offline + deterministic.
    """

    def lookup_many(self, sha256s: list[str]) -> dict:
        return {}


def _runner(monkeypatch):
    monkeypatch.setattr(climod, "_build_local_lookup_or_die", lambda: _FakeLookup())
    return CliRunner()


# ─────────────────────────────────────────────────────────────────────
# Patch 1 — invocation-aware scan roots
# ─────────────────────────────────────────────────────────────────────


def test_patch1_no_paths_delegates_to_default_resolver():
    """No explicit paths → identical to resolve_scan_roots() (Step-1
    doctrine intact: no standing `path` root, default/env roots only)."""
    assert _resolve_scan_roots_for_invocation(()) == rootsmod.resolve_scan_roots()


def test_patch1_explicit_paths_classified_like_discover_groups(tmp_path):
    """Explicit paths classified with _discover_groups' EXACT detection
    order: ollama (manifests/registry.ollama.ai) → hf_cache (models--*)
    → path. The roots view can never disagree with the dispatched
    adapter."""
    oroot = tmp_path / "ostore"
    (oroot / "manifests" / "registry.ollama.ai").mkdir(parents=True)
    hroot = tmp_path / "hfcache"
    (hroot / "models--a--b").mkdir(parents=True)
    groot = tmp_path / "loose"
    groot.mkdir()
    missing = tmp_path / "gone"

    res = _resolve_scan_roots_for_invocation((oroot, hroot, groot, missing))

    assert [s.ecosystem for s in res] == ["ollama", "hf_cache", "path", "path"]
    assert res[0].exists and res[0].scanned and res[0].note == "explicit path"
    assert res[3].exists is False
    assert res[3].scanned is False
    assert res[3].note == "explicit path does not exist"


def test_patch1_unreadable_dir_falls_back_to_path(tmp_path, monkeypatch):
    """An OSError while probing models--* must NOT abort the scan; the
    path is classified `path` (the same fallback _discover_groups itself
    reaches via PathAdapter). Crash-safety hardening over the draft."""
    d = tmp_path / "weird"
    d.mkdir()

    real_iterdir = Path.iterdir

    def boom(self):
        if self == d:
            raise PermissionError("no")
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", boom)
    res = _resolve_scan_roots_for_invocation((d,))
    assert len(res) == 1
    assert res[0].ecosystem == "path"


# ─────────────────────────────────────────────────────────────────────
# Patch 2 — containment join (GPT T-ROOT-MATCH-1/2/3)
# ─────────────────────────────────────────────────────────────────────


def test_t_root_match_1_two_hf_roots_artifact_under_second(tmp_path):
    """T-ROOT-MATCH-1: two hf_cache roots, group artifact under the
    SECOND → that second root is chosen (the first-match bug fixed)."""
    hf1 = str(tmp_path / "hf_root_1")
    hf2 = str(tmp_path / "hf_root_2")
    sr1 = ScanRoot("hf_cache", hf1, True, True, None, None)
    sr2 = ScanRoot("hf_cache", hf2, True, True, None, None)
    art = os.path.join(hf2, "models--x--y", "blobs", "abc")
    assert exp._scan_root_for("hf_cache", [sr1, sr2], [art]) is sr2


def test_t_root_match_2_explicit_ollama_root_contains_artifact(tmp_path):
    """T-ROOT-MATCH-2: explicit Ollama root whose subtree contains the
    group's artifact → that explicit root is chosen."""
    oroot = str(tmp_path / "ollama_store")
    osr = ScanRoot("ollama", oroot, True, True, None, "explicit path")
    art = os.path.join(oroot, "blobs", "sha256-deadbeef")
    assert exp._scan_root_for("ollama", [osr], [art]) is osr


def test_t_root_match_3_path_source_requires_no_scan_root(tmp_path):
    """T-ROOT-MATCH-3: a generic `path` source has no standing ScanRoot
    (resolve_scan_roots has no `path` ecosystem) → None, and the
    _row_for_group path branch handles None without ever calling here."""
    hf = ScanRoot("hf_cache", str(tmp_path / "hf"), True, True, None, None)
    assert exp._scan_root_for("path", [hf], ["/tmp/loose/x.gguf"]) is None


def test_patch2_fallback_to_first_when_no_containment(tmp_path):
    """No containment match among same-ecosystem candidates → fall back
    to the FIRST candidate (identical to prior Step-2 behavior; never
    worse)."""
    sr1 = ScanRoot("hf_cache", str(tmp_path / "a"), True, True, None, None)
    sr2 = ScanRoot("hf_cache", str(tmp_path / "b"), True, True, None, None)
    assert exp._scan_root_for("hf_cache", [sr1, sr2], ["/elsewhere/z"]) is sr1


def test_patch2_single_root_back_compat(tmp_path):
    """Single same-ecosystem root → that root, regardless of
    containment. The Step-2 single-root behavior is unchanged."""
    sr1 = ScanRoot("hf_cache", str(tmp_path / "only"), True, True, None, None)
    art = os.path.join(str(tmp_path / "different"), "blob")
    assert exp._scan_root_for("hf_cache", [sr1], [art]) is sr1


def test_patch2_no_candidates_returns_none():
    """No same-ecosystem candidate at all → None (path-source norm)."""
    assert exp._scan_root_for("hf_cache", [], ["/x"]) is None


# ─────────────────────────────────────────────────────────────────────
# Patch 3 — no-groups branch resolves roots BEFORE exit; 0-row export
# ─────────────────────────────────────────────────────────────────────


def test_patch3_no_groups_text_emits_roots_then_message(tmp_path, monkeypatch):
    """Empty scan, text mode: the roots block (the answer to 'what did
    we look at?') is emitted, then the existing no-artifacts message,
    exit 0."""
    r = _runner(monkeypatch)
    empty = tmp_path / "empty"
    empty.mkdir()
    res = r.invoke(main, ["scan", str(empty), "--local-only"])
    assert res.exit_code == 0
    assert "Scan roots:" in res.output
    assert "No model artifacts found" in res.output


def test_patch3_no_groups_json_has_structural_scan_roots(tmp_path, monkeypatch):
    """Empty scan, --json: the error object carries the structural
    `scan_roots` key (NOT a stderr side-channel), exit 0."""
    r = _runner(monkeypatch)
    empty = tmp_path / "empty"
    empty.mkdir()
    res = r.invoke(main, ["scan", str(empty), "--local-only", "--json"])
    assert res.exit_code == 0
    obj = json.loads(res.output)
    assert obj["error"] == "no model artifacts found"
    assert "scan_roots" in obj
    assert obj["scan_roots"][0]["ecosystem"] == "path"


def test_patch3_no_groups_csv_export_is_header_only(tmp_path, monkeypatch):
    """Empty scan with --export inv.csv → a well-formed header-only CSV
    (1 line) and a `Wrote 0 rows` confirmation. Empty scans stay
    pipeline-safe."""
    r = _runner(monkeypatch)
    empty = tmp_path / "empty"
    empty.mkdir()
    out = tmp_path / "inv.csv"
    res = r.invoke(
        main, ["scan", str(empty), "--local-only", "--export", str(out)]
    )
    assert res.exit_code == 0
    assert out.is_file()
    assert len(out.read_text().splitlines()) == 1  # header only
    assert "Wrote 0 rows" in res.output


def test_patch3_no_groups_jsonl_export_is_empty(tmp_path, monkeypatch):
    """Empty scan with --export inv.jsonl → an empty file (0 rows) and
    a `Wrote 0 rows` confirmation."""
    r = _runner(monkeypatch)
    empty = tmp_path / "empty"
    empty.mkdir()
    out = tmp_path / "inv.jsonl"
    res = r.invoke(
        main, ["scan", str(empty), "--local-only", "--export", str(out)]
    )
    assert res.exit_code == 0
    assert out.is_file()
    assert out.read_text() == ""
    assert "Wrote 0 rows" in res.output


# ─────────────────────────────────────────────────────────────────────
# GPT Step-3 RE-REVIEW blocker — one shared explicit-path classifier
# ─────────────────────────────────────────────────────────────────────


def test_explicit_classify_shared_helper_used_by_both_surfaces():
    """The v0.4 invariant: explicit-path ROOTS DISPLAY and explicit-path
    ADAPTER DISPATCH consume ONE classifier. Proven structurally (the
    function is referenced in both code objects), not by coincidence of
    output."""
    assert (
        "_classify_explicit_scan_path"
        in climod._resolve_scan_roots_for_invocation.__code__.co_names
    )
    assert (
        "_classify_explicit_scan_path"
        in climod._discover_groups.__code__.co_names
    )


def test_explicit_classify_display_equals_dispatch(tmp_path):
    """For every explicit path, the ecosystem the roots view reports
    equals the kind discovery dispatches on — by construction, since
    both call the same classifier."""
    oroot = tmp_path / "ostore"
    (oroot / "manifests" / "registry.ollama.ai").mkdir(parents=True)
    hroot = tmp_path / "hf"
    (hroot / "models--a--b").mkdir(parents=True)
    groot = tmp_path / "loose"
    groot.mkdir()

    roots = climod._resolve_scan_roots_for_invocation((oroot, hroot, groot))
    for sr, p in zip(roots, (oroot, hroot, groot)):
        assert sr.ecosystem == climod._classify_explicit_scan_path(p)


def test_explicit_classify_1_unreadable_dir_does_not_crash_discovery(
    tmp_path, monkeypatch
):
    """GPT T-EXPLICIT-CLASSIFY-1: an unreadable explicit directory must
    NOT raise out of _discover_groups (it did, pre-patch — the probe
    was unguarded there) and must degrade to PathAdapter behavior. The
    roots view degrades to `path` identically."""
    weird = tmp_path / "weird"
    weird.mkdir()
    real_iterdir = Path.iterdir

    def boom(self):
        if self == weird:
            raise PermissionError("denied")
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", boom)

    # Must not raise:
    groups = climod._discover_groups((weird,))
    assert isinstance(groups, list)

    assert climod._classify_explicit_scan_path(weird) == "path"
    roots = climod._resolve_scan_roots_for_invocation((weird,))
    assert roots[0].ecosystem == "path"


def test_explicit_classify_nonexisting_and_nondir_are_path(tmp_path):
    """Non-existing path and a plain file both classify `path` on the
    single shared classifier (rule 1)."""
    missing = tmp_path / "gone"
    f = tmp_path / "x.gguf"
    f.write_bytes(b"\0")
    assert climod._classify_explicit_scan_path(missing) == "path"
    assert climod._classify_explicit_scan_path(f) == "path"
