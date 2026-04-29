"""
Status formatting for Trustfall Lite output.

This module enforces two locked spec contracts:

1. The four status states are exactly:
     ✓ verified artifact
     ⚠ unknown variant
     ? not enrolled
     → pilot enrollment available

   No other status values are permitted. Any attempt to introduce a
   fifth state must amend the spec and the formatter together.

2. Forbidden phrases must not appear in any output text:
     "compromised", "fake", "identity verified", "tampered",
     "malicious", "trojan"

   These phrases would imply runtime structural verification, which
   Lite does not perform. Lite proves artifact integrity (the bytes
   on disk match a signed enrollment record). It does not prove the
   model running in memory is the model the artifact describes. The
   forbidden phrases enforcement is what keeps Lite honest.

Both contracts are tested in tests/test_formatter.py. Modifying either
without updating both the spec and the tests is a doctrinal violation.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Final


# ════════════════════════════════════════════════════════════════════
# Locked status states (per trustfall_lite_spec_v0_1_FROZEN.md)
# ════════════════════════════════════════════════════════════════════


class Status(str, Enum):
    """The four — and only four — status states Lite may emit."""

    VERIFIED = "verified"
    UNKNOWN_VARIANT = "unknown_variant"
    NOT_ENROLLED = "not_enrolled"
    PILOT_AVAILABLE = "pilot_available"


_STATUS_ICONS: Final[dict[Status, str]] = {
    Status.VERIFIED: "✓",
    Status.UNKNOWN_VARIANT: "⚠",
    Status.NOT_ENROLLED: "?",
    Status.PILOT_AVAILABLE: "→",
}

_STATUS_LABELS: Final[dict[Status, str]] = {
    Status.VERIFIED: "verified artifact",
    Status.UNKNOWN_VARIANT: "unknown variant",
    Status.NOT_ENROLLED: "not enrolled",
    Status.PILOT_AVAILABLE: "pilot enrollment available",
}

# Rich color names for the icons, used when colored output is enabled.
_STATUS_COLORS: Final[dict[Status, str]] = {
    Status.VERIFIED: "green",
    Status.UNKNOWN_VARIANT: "yellow",
    Status.NOT_ENROLLED: "dim",
    Status.PILOT_AVAILABLE: "cyan",
}


# ════════════════════════════════════════════════════════════════════
# Forbidden phrases
# ════════════════════════════════════════════════════════════════════
#
# Lite proves artifact integrity. It does NOT prove that the model
# running in memory matches the artifact on disk. Phrases that would
# imply runtime model identity verification are forbidden in any output
# string. The check is case-insensitive and applies to substrings as
# well as whole words ("compromised state" is forbidden because
# "compromised" is forbidden).


FORBIDDEN_PHRASES: Final[tuple[str, ...]] = (
    # Per trustfall_lite_spec_v0_1_FROZEN.md §7 — exact phrasings:
    "identity verified",
    "runtime verified",
    "model is genuine",
    "structural identity confirmed",
    "the model is what it claims",
    "compromised",
    "fake",
    "unsafe",
    "malicious",
    "poisoned",
    "tampered",
    # Defensible additions under spec §7's "or any close synonym" clause:
    "trojan",
    # Add to this list as language drift is detected. Removing from this
    # list requires a spec amendment.
)


_FORBIDDEN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"|".join(re.escape(p) for p in FORBIDDEN_PHRASES),
    re.IGNORECASE,
)


class ForbiddenPhraseError(Exception):
    """
    Raised by emit() when an output string contains a forbidden phrase.

    This is a fail-loud assertion. It indicates a code path that
    constructed a string with language Lite is not allowed to use. The
    fix is at the call site: rephrase to use only spec-allowed
    vocabulary.
    """

    def __init__(self, text: str, found: str) -> None:
        self.text = text
        self.found = found
        super().__init__(
            f"forbidden phrase in output: {found!r} appeared in: {text!r}. "
            f"Trustfall Lite proves artifact integrity, not runtime model "
            f"identity. Rephrase to use only spec-allowed status vocabulary."
        )


def assert_no_forbidden_phrases(text: str) -> None:
    """
    Raise ForbiddenPhraseError if `text` contains any forbidden phrase.

    Call this on every string Lite is about to emit to a user. The cost
    is one regex match against a small alternation; the value is that
    Lite's output cannot drift into runtime-verification language even
    by accident.
    """
    match = _FORBIDDEN_PATTERN.search(text)
    if match:
        raise ForbiddenPhraseError(text, match.group(0))


# ════════════════════════════════════════════════════════════════════
# Per-file result
# ════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class FileResult:
    """
    Outcome of verifying one file (or one model group) against the registry.

    Holds enough context to render a per-file status line and to
    aggregate into a session-level summary.

    `claim_source` is set when status is UNKNOWN_VARIANT (and may be set
    when status is VERIFIED, for completeness). It tells the formatter
    *why* we believe this artifact corresponds to a particular model_id,
    so the rendered output can say "claimed by Hugging Face cache path"
    rather than the misleading "closest match: ...".

    `n_artifacts` and `display_name` are used when this FileResult
    represents a ModelGroup with multiple shards. The formatter leads
    with `display_name` (typically the claimed model_id) so the user
    sees what they recognize, not a shard filename.
    """

    path: str  # Filename or display label; NOT a logged absolute path
    sha256: str  # Lowercase 64-char hex (representative for the group)
    size_bytes: int
    status: Status
    model_id: str | None = None  # Set when status is VERIFIED or UNKNOWN_VARIANT
    publisher: str | None = None  # Set when status is VERIFIED
    license: str | None = None  # Set when status is VERIFIED
    claim_source: str | None = None  # e.g. "hf_cache_path" (set on UNKNOWN_VARIANT)
    n_artifacts: int = 1  # Number of underlying artifacts (shards) in this group
    display_name: str | None = None  # Preferred human label (overrides path when set)


# ════════════════════════════════════════════════════════════════════
# Rendering
# ════════════════════════════════════════════════════════════════════


def status_icon(status: Status, colored: bool = True) -> str:
    """
    Return the locked icon for a status. With colored=True, wraps the
    icon in Rich color markup; with False, returns the plain glyph.
    """
    icon = _STATUS_ICONS[status]
    if colored:
        color = _STATUS_COLORS[status]
        return f"[{color}]{icon}[/{color}]"
    return icon


def status_label(status: Status) -> str:
    """Return the locked label for a status."""
    return _STATUS_LABELS[status]


def render_file_line(result: FileResult, colored: bool = True) -> str:
    """
    Render a single file (or group) result as a multi-line status report.

    The primary label is `display_name` if set (typically the claimed
    model_id from the HF cache path), falling back to `path` (filename)
    when no claim is available. This reads as "what the user
    recognizes" rather than "the first shard's filename."

    Format examples:

        ✓ verified artifact  meta-llama/Llama-3.2-1B-Instruct
                             Meta · Llama-3.2-Community
                             4 shards verified

        ⚠ unknown variant    google/gemma-2-9b
                             claimed by Hugging Face cache path
                             artifact hash does not match signed registry record
                             possible reasons: alternate revision, conversion,
                             fine-tune, or unenrolled variant

        ? not enrolled       random_model.gguf
                             artifact not in Fall Risk registry

    Raises ForbiddenPhraseError if any constructed string would emit
    forbidden vocabulary.
    """
    icon = status_icon(result.status, colored=colored)
    label = status_label(result.status)

    # Lead with display_name when available; fall back to filename
    primary = result.display_name or result.path
    line = f"{icon} {label}  {primary}"

    detail_parts: list[str] = []
    if result.status is Status.VERIFIED:
        verified_meta: list[str] = []
        # If display_name was the model_id, don't repeat it; otherwise show it
        if result.model_id and result.display_name != result.model_id:
            verified_meta.append(result.model_id)
        if result.publisher:
            verified_meta.append(result.publisher)
        if result.license:
            verified_meta.append(result.license)
        if verified_meta:
            detail_parts.append(" · ".join(verified_meta))
        if result.n_artifacts > 1:
            detail_parts.append(f"{result.n_artifacts} shards verified")

    elif result.status is Status.UNKNOWN_VARIANT:
        # Tell the user how we inferred the claimed model_id, and explain
        # what unknown_variant means in terms specific to that source.
        if result.claim_source == "hf_cache_path":
            detail_parts.append("claimed by Hugging Face cache path")
            detail_parts.append("artifact hash does not match signed registry record")
            detail_parts.append(
                "possible reasons: alternate revision, conversion, fine-tune, "
                "or unenrolled variant"
            )
        elif result.claim_source == "ollama_manifest":
            # Ollama unknown_variant explanation is materially different
            # from HF: the registry typically has no canonical Ollama
            # artifact record at all, because Ollama re-quantizes and
            # re-packages weights for its own runtime. Saying "hash
            # does not match signed registry record" implies we expected
            # to find one and this differs — misleading. The correct
            # framing is "this blob isn't enrolled yet" plus the
            # Ollama-specific reasons it might not be.
            detail_parts.append("claimed by Ollama manifest")
            detail_parts.append(
                "model blob digest is not in the signed Fall Risk registry"
            )
            detail_parts.append(
                "possible reasons: Ollama quantization, custom Modelfile, "
                "adapter, conversion, or unenrolled artifact"
            )
        elif result.claim_source == "filename":
            detail_parts.append("claimed by filename pattern")
            detail_parts.append("artifact hash does not match signed registry record")
            detail_parts.append(
                "possible reasons: alternate revision, conversion, fine-tune, "
                "or unenrolled variant"
            )
        elif result.claim_source:
            detail_parts.append(f"claimed by {result.claim_source.replace('_', ' ')}")
            detail_parts.append("artifact hash does not match signed registry record")
            detail_parts.append(
                "possible reasons: alternate revision, conversion, fine-tune, "
                "or unenrolled variant"
            )
        else:
            detail_parts.append("artifact hash does not match signed registry record")
            detail_parts.append(
                "possible reasons: alternate revision, conversion, fine-tune, "
                "or unenrolled variant"
            )

    elif result.status is Status.NOT_ENROLLED:
        detail_parts.append("artifact not in Fall Risk registry")

    elif result.status is Status.PILOT_AVAILABLE:
        detail_parts.append("enroll: integrations@fallrisk.ai")

    if detail_parts:
        # Two-space + indent for hanging continuation
        indent = " " * (len(label) + 4)
        for part in detail_parts:
            line = f"{line}\n{indent}{part}"

    # Final guard: assert nothing forbidden crept in via record fields.
    assert_no_forbidden_phrases(line)
    return line


def render_summary(
    results: list[FileResult],
    colored: bool = True,
    total_artifacts: int | None = None,
) -> str:
    """
    Render a session-level summary of per-group outcomes.

    Each FileResult represents one *model group* (which may contain
    multiple shards). The summary uses model-group language rather than
    file language, matching the discovery banner the user saw at the
    start of the scan.

    `total_artifacts` is the total count of artifacts (shards) across
    all groups. When None, the summary infers it from FileResult
    `n_artifacts` fields (which default to 1 if scanner didn't set
    them — backward compatible with old callers).

    Format:
      Scanned N model groups (M artifacts, X.X GB).
        ✓ A verified
        ⚠ B unknown variant
        ? C not enrolled
        → D pilot available
    """
    if not results:
        return "No model artifacts scanned."

    n_groups = len(results)
    if total_artifacts is None:
        total_artifacts = sum(r.n_artifacts for r in results)
    total_bytes = sum(r.size_bytes for r in results)

    counts: dict[Status, int] = {s: 0 for s in Status}
    for r in results:
        counts[r.status] += 1

    # Tighter copy: "model groups" matches the discovery banner
    if n_groups == total_artifacts:
        # No sharding — a "group" and an "artifact" are the same thing
        header = f"Scanned {n_groups} model groups ({_format_bytes(total_bytes)})."
    else:
        header = (
            f"Scanned {n_groups} model groups "
            f"({total_artifacts} artifacts, {_format_bytes(total_bytes)})."
        )

    summary_lines = [header]
    for s in Status:
        n = counts[s]
        if n == 0:
            continue
        icon = status_icon(s, colored=colored)
        label = status_label(s)
        summary_lines.append(f"  {icon} {n} {label}")

    text = "\n".join(summary_lines)
    assert_no_forbidden_phrases(text)
    return text


def _format_bytes(n: int) -> str:
    """Human-readable byte count: 1.23 GB, 456 MB, etc."""
    units = [("PB", 10**15), ("TB", 10**12), ("GB", 10**9), ("MB", 10**6), ("KB", 10**3)]
    for unit, divisor in units:
        if n >= divisor:
            return f"{n / divisor:.2f} {unit}"
    return f"{n} B"


# ════════════════════════════════════════════════════════════════════
# JSON output mode (for --json)
# ════════════════════════════════════════════════════════════════════


def render_results_as_dict(
    results: list[FileResult],
    total_artifacts: int | None = None,
) -> dict:
    """
    Return the results as a JSON-serializable dict for `--json` mode.

    Each FileResult corresponds to one *model group* (per spec §5
    sharded-model rule). The summary uses group/artifact language to
    match the human-readable output. The `files_scanned` field is
    retained as an alias for backward compatibility with any
    downstream consumer that built against v0.1.0; new consumers
    should read `groups_scanned`.

    Schema:
      {
        "scan_summary": {
          "groups_scanned": N,
          "artifacts_scanned": M,
          "files_scanned": N,           # alias for groups_scanned (deprecated)
          "total_bytes": X,
          "counts": {"verified": A, "unknown_variant": B, ...}
        },
        "results": [
          {
            "path": "...",              # filename or display label
            "display_name": "..." | null,
            "sha256": "...",
            "size_bytes": N,
            "n_artifacts": 1,
            "status": "verified" | "unknown_variant" | "not_enrolled" | "pilot_available",
            "model_id": "..." | null,
            "claim_source": "..." | null,
            "publisher": "..." | null,
            "license": "..." | null
          },
          ...
        ]
      }
    """
    counts = {s.value: 0 for s in Status}
    for r in results:
        counts[r.status.value] += 1

    n_groups = len(results)
    if total_artifacts is None:
        total_artifacts = sum(r.n_artifacts for r in results)

    return {
        "scan_summary": {
            "groups_scanned": n_groups,
            "artifacts_scanned": total_artifacts,
            "files_scanned": n_groups,  # deprecated alias; equals groups_scanned
            "total_bytes": sum(r.size_bytes for r in results),
            "counts": counts,
        },
        "results": [
            {
                "path": r.path,
                "display_name": r.display_name,
                "sha256": r.sha256,
                "size_bytes": r.size_bytes,
                "n_artifacts": r.n_artifacts,
                "status": r.status.value,
                "model_id": r.model_id,
                "claim_source": r.claim_source,
                "publisher": r.publisher,
                "license": r.license,
            }
            for r in results
        ],
    }
