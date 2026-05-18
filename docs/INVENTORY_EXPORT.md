# Trustfall Lite — Inventory Export Schema

This document is the authoritative schema for the CSV and JSONL files
produced by `trustfall scan --export`. A consumer reading an exported
file should read this document; this is the single source of truth for
column names, order, types, null behaviour, and derivation.

The schema is frozen. The default export is **fifteen columns**, in the
order given below. Two additional path columns are appended **only**
when `--export-include-paths` is explicitly passed (see
[Path columns](#path-columns-explicit-opt-in-only)).

This document is reachable from the test suite: a test
(`T-SCHEMA-DOC-1`) parses the canonical column block below and asserts
it is byte-equal to the produced default CSV header and to the default
JSONL key set. If this document and the produced output ever disagree,
that test fails. Schema-doc drift is itself a bug.

---

## What export is, and is not

`trustfall scan --export PATH` writes a flat tabular inventory of the
scan result to a **local file**. It is an additional sink: the normal
human/JSON scan output is unaffected and still goes to stdout/stderr.

Export is a **local file write only**. It performs no upload, opens no
network connection, starts no daemon, and renders no dashboard. The
export writer is a pure function of the already-computed scan result
plus run metadata; it triggers no new discovery, hashing, or registry
lookup. It does not import any network module (enforced by an
import-allowlist test).

`--export` does not change the scan lookup mode. A default scan may
still query the verification API; `--local-only` is the
no-per-scan-network mode.

Export adds **no** new claim. It does not evaluate model safety, does
not inspect tokenizer contents, does not render any safe/unsafe
verdict, and does not verify runtime identity. Those are outside the
scope of Trustfall Lite entirely (runtime structural identity is
Trustfall Deep, a separate product). See
[`LIMITATIONS.md`](../LIMITATIONS.md) and
[`TRUST_MODEL.md`](../TRUST_MODEL.md).

---

## Canonical column list

The default export is exactly these fifteen columns, in exactly this
order. The block below is the machine-parseable schema of record (one
column name per line, between the markers):

```text
TRUSTFALL_EXPORT_COLUMNS_V0_4_BEGIN
provider
model_id
model_id_source
status
registry_match
registry_bound_digest
registry_manifest_digest
artifact_count
license
publisher
deep_runtime_claim_applicable
tokenizer_surface_coverage
cache_root_type
trustfall_version
scanned_at
TRUSTFALL_EXPORT_COLUMNS_V0_4_END
```

For CSV this is the header row, comma-joined, in this order. For JSONL
this is the key set present on every line, with the same names.

---

## Column reference

| # | Column | Type | Null / empty rule | Derivation |
|---|---|---|---|---|
| 1 | `provider` | string | Never empty. | The ecosystem that produced the group: `huggingface_cache`, `ollama`, or `path`. The public label form; mirrors the existing source-label mapping in the JSON renderer. |
| 2 | `model_id` | string | Empty string if no claim and not verified (loose `path` files). | The verified record's `model_id` claim when verified; else the group's claimed model id; else empty. |
| 3 | `model_id_source` | enum | Never empty; always one of the three values. | `registry_record` when a registry record matched; `local_metadata` when no record matched but a local claim source is set (`hf_cache_path`, `ollama_manifest`, `filename`); `none` otherwise. |
| 4 | `status` | enum | Never empty. | The scan status: `verified`, `unknown_variant`, `not_enrolled`, or `pilot_available`. The frozen status vocabulary; the export maps over all four members defensively and never hard-errors on `pilot_available`. |
| 5 | `registry_match` | enum | Never empty. | Total function of `status`: `verified` → `exact`; `unknown_variant` → `name_only`; `not_enrolled` → `none`; `pilot_available` → `none`. |
| 6 | `registry_bound_digest` | string | Empty for non-verified groups. Never a locally computed hash. | The digest bound by the signed registry record, copied verbatim. Lane B (`evidence_class == "artifact_identity"`): the record's `artifact_manifest_digest`. Lane A (`itpuf_structural_identity` or absent): the record's `evidence_digest`. Non-verified: empty. The locally computed SHA-256 is never placed here (use `--json` for that). |
| 7 | `registry_manifest_digest` | string | Empty only if no signed snapshot was loaded at all. Never recomputed; never substituted with a timestamp or a local hash. | The `manifest_digest` of the signed registry snapshot the lookup resolved against, copied verbatim from the verified snapshot metadata. Primary source: the offline snapshot's signature-gated `manifest_digest` (a manifest whose signature fails never yields a snapshot, so this can only ever carry a cryptographically verified digest). Secondary source: the live-API verified-record envelope. Threaded into the export as a run-scalar by the CLI caller — the export layer never reads the registry or API itself. Format propagated verbatim: no prefix added, none stripped (Trustfall API Authority Doctrine — serve signed claims, never recompute). |
| 8 | `artifact_count` | int | Never empty; ≥ 1. | Number of artifacts in the group. |
| 9 | `license` | string | Empty for non-verified. Local context never fabricates a license. | The verified record's `license` claim (from the locally verified signed payload), else empty. |
| 10 | `publisher` | string | Empty for non-verified. | The verified record's `publisher` claim, else empty. |
| 11 | `deep_runtime_claim_applicable` | bool | `false` for any non-verified group; `false` for verified Lane-B records; `false` for any verified record of any other or future evidence class. | A boolean fact about the registry record's evidence class — **not** a statement about the running process, and **not** a passthrough of any record field of a similar name. `true` **only** when `status == verified` **and** the matched record is a Lane-A structural-identity record by the conservative predicate `evidence_class in ("itpuf_structural_identity", None) and bool(evidence_digest)`. "Applicable" means a Trustfall Deep runtime-identity claim *could* be made about this enrolled model **if you ran Deep**. It does **not** mean Lite checked runtime identity. Lite never does. |
| 12 | `tokenizer_surface_coverage` | enum | Never empty; always one of the four enum values. | One of `covered_by_verified_container`, `opaque_structural_evidence_binding`, `not_covered`, `unknown_unverified`. A pure function of the verified record's status, artifact format, evidence class, and presence-of-`evidence_digest`. It reads nothing from local tokenizer files. An **artifact-identity coverage signal, not a tokenizer security verdict** (see the non-claim block below). |
| 13 | `cache_root_type` | enum | Never empty. | Which root family the group came from: `hf_cache`, `ollama`, or `path`. This is the internal token and the identity join key to the scan-roots display (`ScanRoot.ecosystem`). Kept separate from `provider` (the public label) to future-proof against provider/root divergence. |
| 14 | `trustfall_version` | string | Never empty. | The running Trustfall Lite version. Injected by the CLI caller into the export, exactly like `scanned_at`; never read inside the export layer (which would break the pure-sink and determinism properties). Identical for every row. |
| 15 | `scanned_at` | string | Never empty. | ISO 8601 UTC timestamp of the scan invocation. One value, identical for every row in a single export — a property of the run, not the row. Injected by the caller; never read from the clock inside the export layer (so two exports of the same machine with the same injected timestamp are byte-identical). |

### `registry_bound_digest` — per-lane rule (precise)

```text
Lane B  (evidence_class == "artifact_identity")
    registry_bound_digest = record.claims["artifact_manifest_digest"]   (verbatim)

Lane A  (evidence_class == "itpuf_structural_identity"  OR  absent)
    registry_bound_digest = record.claims["evidence_digest"]            (verbatim)

non-verified (unknown_variant, not_enrolled, pilot_available)
    registry_bound_digest = ""   (CSV)  /  null  (JSONL)
```

The export adds no `sha256:` prefix and strips none. Whatever the
signed record carries is what the column carries.

### `deep_runtime_claim_applicable` — predicate (precise)

```text
true   iff   status == verified
        and  evidence_class in ("itpuf_structural_identity", None)
        and  bool(evidence_digest)

false  in every other case:
        - any non-verified status
        - verified Lane-B (artifact_identity)
        - verified record of any other / future evidence class
        - verified Lane-A-looking record missing its evidence_digest
        - no matched record
```

This column is a fact about a registry record's evidence class. It is
**never** a statement that Trustfall Lite verified runtime identity.
Lite never verifies runtime identity — that is Trustfall Deep, a
separate product.

---

## `tokenizer_surface_coverage` — non-claim block (load-bearing)

The following text is load-bearing and is reproduced verbatim,
byte-for-byte, here and in [`PRIVACY.md`](../PRIVACY.md) and
[`LIMITATIONS.md`](../LIMITATIONS.md). A test (`T-TOK-6`) asserts it is
an exact substring of all three files.

> This column does not mean the tokenizer is safe. It does not mean Trustfall Lite inspected tokenizer contents. For Lane A structural records, `opaque_structural_evidence_binding` means only that the row is bound to a signed structural evidence commitment; the public Lite payload does not enumerate tokenizer files. For Lane B container records, `covered_by_verified_container` means the verified artifact container is the identity surface. This is an artifact-identity coverage signal, not a tokenizer security verdict.

Reaffirmed: this column adds **no** semantic tokenizer scanning, **no**
suspicious-token heuristics, **no** malware verdict, **no** policy
enforcement, and **no** safe/unsafe language. It is a coverage
*report*, not a scanner. It reads nothing from local tokenizer files.

---

## Provenance columns

`registry_manifest_digest` (column 7) and `trustfall_version`
(column 14) exist so a detached export handed to an auditor records
*which signed registry snapshot* and *which Trustfall version*
produced it. Without them, two exports a month apart are
indistinguishable even though the registry and tool may have changed.

Both are **run-scalars**: identical on every row of a single export.
Neither is derived from local file content. Neither is recomputed by
the export layer.

`registry_manifest_digest` is **copied verbatim from the signed local
snapshot metadata when a snapshot is available, not recomputed**. The
primary source is the offline snapshot's `manifest_digest`, which is
read only *after* the snapshot manifest's signature is verified against
the bundled keys — so the column can only ever carry a digest from a
cryptographically verified manifest. The export layer receives this
value as an argument from the CLI caller; it never reads the registry
or API itself.

**`created_at` / `snapshot_at` null behaviour is out of scope.** The
production registry manifest observed during v0.4 development carries a
populated `manifest_digest` but a null `created_at`, so the registry's
internal `snapshot_at` resolves to an empty string. That is
pre-existing behaviour of the registry layer, **out of scope for
v0.4, and intentionally not changed by this lane**. It is recorded
here only so a future reader does not misattribute it to the export
feature. There is no `registry_snapshot_at` column in the schema; the
empty timestamp corrupts nothing this feature produces.
`registry_manifest_digest` is wholly independent of any timestamp
field: it reads the manifest content digest, full stop.

---

## Path columns (explicit opt-in only)

By default the export contains **no filesystem paths**. The fifteen
columns above carry no path data.

Passing `--export-include-paths` appends exactly two more columns,
making seventeen:

| Column | Type | Notes |
|---|---|---|
| `cache_root_path` | string | The full absolute path of the root this group's artifacts came from. Present only with `--export-include-paths`. |
| `artifact_paths` | string (CSV) / array (JSONL) | CSV: absolute paths joined by `;` (semicolon — `,` is the CSV delimiter; the field is still quoted defensively). JSONL: a native JSON array of strings. Present only with `--export-include-paths`. |

Without `--export-include-paths` these two columns **do not appear at
all** — they are *absent*, not present-but-empty. A column that does
not exist cannot leak; an existing-but-empty column invites a future
bug that populates it. The header row reflects the actual columns
present.

### `--include-paths` and `--export-include-paths` are separate flags

These are two independent, separately-named flags with different
purposes:

- `--include-paths` controls whether local filesystem path *hints*
  are sent to the **registry API** during a scan (an existing,
  pre-v0.4 flag, a network-side privacy control).
- `--export-include-paths` controls whether the two path *columns*
  above are written into the **local export file** (a v0.4 flag, a
  file-content control; no network involvement).

Passing one does not imply the other. The export path columns require
`--export-include-paths` specifically; `--include-paths` alone never
adds path columns to an export, and `--export-include-paths` alone
never sends paths to the API.

### Display-vs-export path asymmetry (intentional)

The scan-roots display and the `--json` `scan_roots` key
**home-collapse** paths (they show a `~/` prefix instead of your home
directory). The `--export-include-paths` columns do **not**
home-collapse — they carry **full absolute paths**.

This asymmetry is intentional. The terminal/JSON display defaults to
the privacy-preserving home-collapsed form. A user who explicitly
passes `--export-include-paths` is asking for full-fidelity auditable
paths; home-collapsing them in the export would be a silently-lossy
file (a different bug). Display privacy default is not the same
decision as an explicit export opt-in.

Practical consequence: if you see `~/models/...` in the terminal but
`/Users/alice/models/...` in the exported file, that is correct and
expected — not a discrepancy.

---

## Determinism

For the same scan result and the same injected `scanned_at`, two
exports produce **byte-identical** files (both CSV and JSONL). Rows
are emitted in a deterministic order. `scanned_at` is the one
intentionally run-varying field, and it is injected by the caller (not
read from the clock inside the export layer) precisely so byte-stable
comparison is possible.

CSV and JSONL are produced by one shared row builder, so for the same
scan result they carry identical logical content (modulo CSV
string-encoding of int/bool/null and the `;`-join vs JSON-array form
of `artifact_paths`).

---

## File extension

`--export` requires a `.csv` or `.jsonl` target (case-insensitive on
the extension). An unrecognised or missing extension is an error: no
file is written and the command exits with the export I/O failure
code. The format is chosen from the extension; there is no separate
format flag, and `--export -` (stdout) is not supported in v0.4.

---

## Authority

Where this document and the project doctrine files conflict on
doctrine, the doctrine files win: [`TRUST_MODEL.md`](../TRUST_MODEL.md),
[`PRIVACY.md`](../PRIVACY.md), [`LIMITATIONS.md`](../LIMITATIONS.md).
This document specifies a file format; it does not relitigate the
trust model.
