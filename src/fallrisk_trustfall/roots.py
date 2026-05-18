"""
Scan-root resolution — the single source of truth for *where* the
scanner looks.

Why this module exists (spec §2.1):

  Before v0.4, root resolution was private and duplicated-by-knowledge.
  `adapters/hf_cache.py` knew the Hugging Face cache precedence chain;
  `adapters/ollama.py:OllamaAdapter._resolve_root()` knew the Ollama
  precedence; the F1 display had no resolver at all. If the display
  computed roots independently it could disagree with what discovery
  actually used — a correctness bug, not a cosmetic one ("the scanner
  says it looked here, but it actually looked there").

  v0.4 introduces ONE shared public resolver. The HF and Ollama
  adapters consume the resolution *primitives* defined here, and the
  F1 display consumes `resolve_scan_roots()`, which is built from the
  same primitives. The display therefore can never disagree with what
  discovery used, because they read the same code.

Refactor invariant (spec §2.1, operator hard constraint):

  The existing adapter public surface is UNCHANGED. The module-level
  helpers the adapters and tests import by name
  (`adapters.hf_cache._resolve_hf_cache_roots`,
  `OllamaAdapter._resolve_root`) keep their exact names and behavior;
  they now delegate to the primitives here. `tests/test_adapters.py`
  and `tests/test_ollama_adapter.py` must pass byte-unchanged. If an
  adapter test breaks, the refactor changed behavior and is wrong.

Vocabulary (operator ruling 2026-05-16, Option 1; spec §2.1 / §3.2 /
§4.3):

  `ScanRoot.ecosystem` carries the INTERNAL token —
  "hf_cache" | "ollama" | "lmstudio" | "path" — identical to the live
  adapter `.source` attribute and identical to the export's
  `cache_root_type` column. The F1<->export join is identity:
  `cache_root_type == ScanRoot.ecosystem == r.group.source`. No
  reverse-map. The public `provider` label is derived only at the
  rendering boundary, via the existing live `cli.py` `source_label_map`
  (`huggingface_cache` / `ollama` / `path`). The public label never
  appears inside this module.

Purity (spec §2.1):

  `resolve_scan_roots()` is pure: no network, no hashing, no discovery
  side effects. The only filesystem interaction is `stat()`-class
  probing (`Path.is_dir()` / `Path.resolve()`) to populate `exists`.
  It NEVER calls any adapter `.discover()`. Claiming a scan we do not
  perform is a trust violation (this is why the LM Studio entry sets
  `scanned=False` and carries an explicit honesty marker — §2.5).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


# ════════════════════════════════════════════════════════════════════
# Public dataclass — what the F1 display and the export join consume
# ════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class ScanRoot:
    """
    One resolved (or unresolved) scan location for one ecosystem.

    Fields (spec §2.1):

      ecosystem      Internal token: "hf_cache" | "ollama" |
                     "lmstudio" | "path". Identical to the live
                     adapter `.source` and to the export
                     `cache_root_type` column. This is the F1<->export
                     identity join key — never a public label.

      resolved_path  Absolute path string the resolver *selected*, or
                     None. None means nothing was selected — the
                     ecosystem is simply absent (not installed, no
                     cache). A configured-but-broken state is the
                     opposite: it KEEPS its path so the user can see
                     what they misconfigured (e.g. a typo'd
                     OLLAMA_MODELS retains the bad value with
                     exists=False + a diagnostic note). "Absent" and
                     "configured-but-broken" are distinct states and
                     only the latter carries a path. Full path (not
                     home-collapsed); the F1 display and
                     `--json scan_roots` apply home-collapse at the
                     rendering boundary, not here.

      exists         True iff `resolved_path` is an existing directory
                     on disk at resolution time. Always False when
                     resolved_path is None.

      scanned        True iff this run can actually inspect this
                     resolved root. False when the root is missing or
                     when the ecosystem is display-only / unsupported
                     (LM Studio). Use `exists` + `note` to distinguish
                     "missing" (exists=False, note=None) from
                     "detected-but-not-scanned" (exists=True,
                     note=honesty marker) from "configured-but-broken"
                     (exists=False, note=diagnostic). A not-found root
                     is never scanned=True — claiming we inspected a
                     root we never found is a trust violation.

                     Full (exists, scanned, note) truth table:
                       HF/Ollama root exists  → True,  True,  None
                       HF/Ollama not found    → False, False, None
                       OLLAMA_MODELS set+bad  → False, False, diag
                       LM Studio detected     → True,  False, honesty
                       LM Studio absent       → entry omitted entirely

      env_override   Name of the environment variable that won the
                     precedence (e.g. "OLLAMA_MODELS", "HF_HUB_CACHE"),
                     or None when the default location was used.

      note           Human-facing honesty / diagnostic marker, or
                     None. Used for: LM Studio "detected, not scanned",
                     and the diagnostic "OLLAMA_MODELS is set but does
                     not resolve to an existing directory" state (§2.3
                     state 3 — the most diagnostic case).
    """

    ecosystem: str
    resolved_path: str | None
    exists: bool
    scanned: bool
    env_override: str | None
    note: str | None


# ════════════════════════════════════════════════════════════════════
# Resolution primitives — the single source of truth
#
# These are the canonical precedence chains. The adapters delegate to
# them (keeping their own public function names for test stability);
# `resolve_scan_roots()` consumes them for the F1 display. One chain,
# two consumers, zero duplication-by-knowledge.
# ════════════════════════════════════════════════════════════════════


def _hf_candidate_chain() -> list[tuple[Path, str | None]]:
    """
    The Hugging Face cache precedence chain, in priority order, as
    (candidate_path, env_var_name_or_None) pairs — BEFORE existence
    filtering or de-duplication.

    Precedence (spec §2.2; byte-for-byte the pre-v0.4
    `adapters/hf_cache.py:_resolve_hf_cache_roots` order):

      1. HF_HUB_CACHE                       (HF's documented primary)
      2. HF_HOME/hub
      3. XDG_CACHE_HOME/huggingface/hub
      4. ~/.cache/huggingface/hub           (default; no env override)
      5. %USERPROFILE%/.cache/huggingface/hub  (Windows)

    The env-var name is carried alongside each candidate so the
    winning root can report which override (if any) selected it.
    """
    chain: list[tuple[Path, str | None]] = []

    if hub_cache := os.environ.get("HF_HUB_CACHE"):
        chain.append((Path(hub_cache).expanduser(), "HF_HUB_CACHE"))

    if hf_home := os.environ.get("HF_HOME"):
        chain.append((Path(hf_home).expanduser() / "hub", "HF_HOME"))

    if xdg := os.environ.get("XDG_CACHE_HOME"):
        chain.append(
            (Path(xdg).expanduser() / "huggingface" / "hub", "XDG_CACHE_HOME")
        )

    chain.append((Path("~/.cache/huggingface/hub").expanduser(), None))

    if userprofile := os.environ.get("USERPROFILE"):
        chain.append(
            (Path(userprofile) / ".cache" / "huggingface" / "hub", "USERPROFILE")
        )

    return chain


def resolve_hf_cache_roots() -> list[Path]:
    """
    Canonical HF cache resolution. Returns every DISTINCT EXISTING
    cache root, in precedence order, de-duplicated by resolved path.

    This is the exact behavior of the pre-v0.4
    `adapters/hf_cache.py:_resolve_hf_cache_roots`. That function is
    now a one-line delegator to this one (so `test_adapters.py`,
    which exercises the adapter through `HFCacheAdapter(roots=...)`
    explicit-roots path AND production auto-resolution, sees identical
    behavior).

    Multiple roots can resolve simultaneously (e.g. both
    `HF_HUB_CACHE` and `HF_HOME` set and existing) — all are returned,
    in precedence order, which is why the adapter walks a list.
    """
    seen: set[Path] = set()
    existing: list[Path] = []
    for candidate, _env in _hf_candidate_chain():
        try:
            resolved = candidate.resolve()
        except (OSError, RuntimeError):
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_dir():
            existing.append(resolved)
    return existing


def _hf_scan_roots() -> list[ScanRoot]:
    """
    F1 view of the HF cache. One ScanRoot per DISTINCT EXISTING root
    (mirrors `resolve_hf_cache_roots()` exactly — same primitive), or
    exactly one `not found` ScanRoot when none exist.

    The `env_override` of each existing root is the env var of the
    FIRST candidate in the precedence chain that resolves to that
    path (the override that "won" it). The default location reports
    `env_override=None`.
    """
    seen: set[Path] = set()
    out: list[ScanRoot] = []
    for candidate, env in _hf_candidate_chain():
        try:
            resolved = candidate.resolve()
        except (OSError, RuntimeError):
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_dir():
            out.append(
                ScanRoot(
                    ecosystem="hf_cache",
                    resolved_path=str(resolved),
                    exists=True,
                    scanned=True,
                    env_override=env,
                    note=None,
                )
            )

    if out:
        return out

    # Nothing resolved — emit one explicit "not found" row.
    #
    # State semantics (operator ruling 2026-05-16, GPT review):
    #   - resolved_path = None  (nothing was *selected*; "absent" is
    #     distinct from "configured-but-broken" which keeps its path)
    #   - exists = False
    #   - scanned = False       (a root we did not find is a root we
    #     did not inspect; scanned=True here would be a trust lie in
    #     --json scan_roots)
    #   - note = None           (nothing diagnostic to say — there is
    #     simply no HF cache; the absence is not an error state)
    return [
        ScanRoot(
            ecosystem="hf_cache",
            resolved_path=None,
            exists=False,
            scanned=False,
            env_override=None,
            note=None,
        )
    ]


# --- Ollama -----------------------------------------------------------

# Mirror of `adapters/ollama.py:_DEFAULT_PATHS`. Kept here as the
# canonical default so the resolver and the adapter agree by reading
# the same constant. The adapter imports this rather than redefining.
OLLAMA_DEFAULT_PATHS: tuple[str, ...] = ("~/.ollama/models",)


def resolve_ollama_root(explicit_root: Path | None) -> Path | None:
    """
    Canonical Ollama models-root resolution. Returns the resolved
    existing directory, or None if no Ollama install is detected.

    Precedence (spec §2.3; byte-for-byte the pre-v0.4
    `OllamaAdapter._resolve_root()`):

      1. explicit constructor/discover argument  (wins; returned only
         if it is an existing directory, else None)
      2. OLLAMA_MODELS env var                    (expanduser; None if
         not an existing directory)
      3. platform default(s) in OLLAMA_DEFAULT_PATHS

    `OllamaAdapter._resolve_root()` is now a one-line delegator to
    this. The Ollama adapter test suite
    (`test_ollama_adapter.py::test_explicit_root_overrides_default`,
    `::test_env_var_resolution`, `::test_discover_root_argument_overrides`,
    `::test_no_ollama_install_returns_empty`) pins this exact ladder
    and must pass unchanged.
    """
    # 1. Explicit argument wins.
    if explicit_root is not None:
        return explicit_root if explicit_root.is_dir() else None

    # 2. OLLAMA_MODELS env var.
    env_path = os.environ.get("OLLAMA_MODELS")
    if env_path:
        p = Path(env_path).expanduser()
        return p if p.is_dir() else None

    # 3. Platform default(s).
    for default in OLLAMA_DEFAULT_PATHS:
        p = Path(default).expanduser()
        if p.is_dir():
            return p
    return None


def _ollama_scan_root() -> ScanRoot:
    """
    F1 view of Ollama. Has THREE display states (spec §2.3 — the v1
    spec missed state 3, which is the most diagnostic one):

      1. OLLAMA_MODELS not set    → resolved from a platform default;
                                    env_override=None.
      2. OLLAMA_MODELS set + ok   → env_override="OLLAMA_MODELS",
                                    resolved_path=<value>,
                                    exists per stat.
      3. OLLAMA_MODELS set + bad  → env_override="OLLAMA_MODELS",
                                    resolved_path=<value>,
                                    exists=False, note=<diagnostic>.
                                    This is the silent-find-nothing
                                    case F1 exists to surface.

    NOTE: state 3 is NOT reachable via `resolve_ollama_root()` alone
    — that function returns None for a bad OLLAMA_MODELS, discarding
    *why*. The F1 display must distinguish "no Ollama anywhere" from
    "OLLAMA_MODELS is set but wrong", so this function inspects the
    env var directly. The actual *scan* still uses
    `resolve_ollama_root()` (the adapter path); this function only
    adds diagnostic visibility on top, never changes what is scanned.
    """
    env_path = os.environ.get("OLLAMA_MODELS")

    if env_path:
        p = Path(env_path).expanduser()
        if p.is_dir():
            # State 2: set and resolvable.
            return ScanRoot(
                ecosystem="ollama",
                resolved_path=str(p),
                exists=True,
                scanned=True,
                env_override="OLLAMA_MODELS",
                note=None,
            )
        # State 3: set but does not resolve to an existing directory.
        # scanned=False: the user pointed us at a directory that does
        # not exist, so nothing was inspected (GPT 1 truth table).
        # resolved_path is KEPT (the bad value) + diagnostic note so
        # the user can see exactly what they misconfigured — this is
        # the "configured-but-broken" state, distinct from "absent"
        # (which carries resolved_path=None).
        return ScanRoot(
            ecosystem="ollama",
            resolved_path=str(p),
            exists=False,
            scanned=False,
            env_override="OLLAMA_MODELS",
            note=(
                "OLLAMA_MODELS is set but does not resolve to an "
                "existing directory"
            ),
        )

    # State 1: not set — platform default.
    for default in OLLAMA_DEFAULT_PATHS:
        p = Path(default).expanduser()
        if p.is_dir():
            return ScanRoot(
                ecosystem="ollama",
                resolved_path=str(p),
                exists=True,
                scanned=True,
                env_override=None,
                note=None,
            )

    # Not set and no default exists → not found.
    #
    # State semantics (operator ruling 2026-05-16, GPT review):
    # this is the "Ollama is not installed" case — distinct from
    # state 3 above ("OLLAMA_MODELS is set but points nowhere"). The
    # absent case carries NO path (resolved_path=None) and is NOT
    # scanned; the configured-but-broken case above keeps its bad
    # path + diagnostic note so the user can see *what* they typo'd.
    return ScanRoot(
        ecosystem="ollama",
        resolved_path=None,
        exists=False,
        scanned=False,
        env_override=None,
        note=None,
    )


# --- LM Studio (root-display-only honesty marker; spec §2.5) ---------

# Conventional LM Studio models location. The LM Studio adapter is a
# stub (`adapters/lmstudio.py` raises NotImplementedError for
# discovery). `resolve_scan_roots()` resolves where the directory
# *would* be and reports it with an explicit honesty marker; it MUST
# NOT call any LM Studio `.discover()`. Claiming a scan we do not
# perform is a trust violation.
_LMSTUDIO_DEFAULT = "~/.cache/lm-studio/models"

_LMSTUDIO_NOT_SCANNED_NOTE = (
    "detected, not scanned — LM Studio support not yet implemented"
)


def _lmstudio_scan_root() -> ScanRoot | None:
    """
    F1 view of LM Studio (spec §2.5):

      - directory exists → ScanRoot(scanned=False,
        note="detected, not scanned — LM Studio support not yet
        implemented"). The display prints the root WITH the honesty
        marker.
      - directory absent → return None. The caller renders this as
        `lmstudio: not found` (no honesty marker needed — nothing to
        be honest about; there is no scan being withheld).

    Never calls `LMStudioAdapter.discover()`.
    """
    p = Path(_LMSTUDIO_DEFAULT).expanduser()
    if p.is_dir():
        return ScanRoot(
            ecosystem="lmstudio",
            resolved_path=str(p),
            exists=True,
            scanned=False,
            env_override=None,
            note=_LMSTUDIO_NOT_SCANNED_NOTE,
        )
    return None


# ════════════════════════════════════════════════════════════════════
# Public resolver — the single function the F1 display consumes
# ════════════════════════════════════════════════════════════════════


def resolve_scan_roots() -> list[ScanRoot]:
    """
    Single source of truth for *where* the scanner looks.

    Returns the F1 display model: a list of `ScanRoot`, in a stable
    ecosystem order (hf_cache, then ollama, then lmstudio). Built
    from the SAME resolution primitives the HF and Ollama adapters
    consume, so the F1 display can never disagree with what discovery
    actually used (spec §2.1 invariant).

    Pure (spec §2.1): no network, no hashing, no discovery side
    effects, no adapter `.discover()` calls. The only filesystem
    interaction is `is_dir()` / `resolve()` probing to populate
    `exists`. Stable across calls on an unchanged machine (the F1
    block is deterministic).

    Ecosystems:
      - hf_cache:  one ScanRoot per distinct existing cache root, or
                   exactly one `not found` ScanRoot if none exist
                   (§2.2). May therefore contribute >1 entry.
      - ollama:    exactly one ScanRoot, three display states (§2.3).
      - lmstudio:  exactly one display-only ScanRoot if the
                   conventional directory exists; omitted entirely if
                   it does not (the caller renders `lmstudio: not
                   found`). Never scanned (§2.5).

    The `path` ecosystem is intentionally NOT enumerated here: there
    is no fixed `path` root to resolve — `path` roots are whatever
    explicit arguments the user passes on the command line, known
    only at scan time, not resolvable in the abstract. `path` appears
    in the export as a `cache_root_type` value (from `r.group.source`)
    but has no standing F1 root entry. This asymmetry is by design,
    not an omission.
    """
    roots: list[ScanRoot] = []
    roots.extend(_hf_scan_roots())
    roots.append(_ollama_scan_root())
    lms = _lmstudio_scan_root()
    if lms is not None:
        roots.append(lms)
    return roots
