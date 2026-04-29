# Trustfall Lite

**Verify that local model artifacts match signed records in the Fall Risk
registry.**

Trustfall Lite is a local command-line tool. It scans your machine for
model artifacts (Hugging Face cache, Ollama blobs, individual paths),
computes their SHA-256 hashes, and compares them to a cryptographically
signed registry of enrolled models published by Fall Risk AI. Each
match is verified under a public JWS signature; mismatches are surfaced
as `unknown_variant` so the user can decide what to do. It can also
compare a current scan against a previous JSON report to show what
changed.

It is small, self-contained, and runs entirely from the command line.
There is no daemon, no account, no telemetry, no analytics, no model
bytes collected.

---

## Quick start

Requires Python 3.10 or later.

```bash
pipx install fallrisk-trustfall

# or, if you prefer pip:
pip install fallrisk-trustfall
```

`pipx` is recommended for command-line tools because it isolates
Trustfall Lite's dependencies from your other Python environments.

```bash
trustfall scan                       # scan default cache locations
trustfall scan ~/models              # scan a specific path
trustfall scan --json                # machine-readable output
trustfall scan --local-only          # no network — verify against a cached registry snapshot
```

To compare a current scan against a prior one (for example, to detect
new or removed model artifacts since you last looked):

```bash
trustfall scan --json > baseline.json
# ... time passes, you install or remove some models ...
trustfall diff baseline.json                       # implicit current scan
trustfall diff baseline.json current.json          # explicit comparison
```

The implicit form (one argument) is allowed only when the baseline
was taken with default-scope scan. If the baseline used explicit
paths, pass an explicit current scan from those same paths instead.

By default, `trustfall diff` prints the diff and exits 0 regardless
of what changed. For CI use, two opt-in flags are available:
`--exit-code` (exit 1 on any change) and
`--exit-code-on-status-regression` (exit 2 only when a previously
verified artifact is no longer verified). Errors take precedence
over both flags.

For the local-only flow:

```bash
trustfall registry --refresh         # download and cache the signed snapshot
trustfall scan --local-only          # verify against the cached snapshot, no network
```

Local-only mode is for users who do not want artifact hashes leaving
the machine. The registry snapshot is signed and verifiable
independently — see `VERIFYING.md`.

---

## Example output

```
Discovered 88 model group(s) (380 artifacts, 600.45 GB). Hashing...

  ✓ verified artifact  Qwen/Qwen2.5-1.5B-Instruct
                       Alibaba · Apache-2.0
                       2 shards verified

  ✓ verified artifact  TinyLlama/TinyLlama-1.1B-Chat-v1.0
                       TinyLlama Project · Apache-2.0

  ⚠ unknown variant    EleutherAI/pythia-410m
                       claimed by Hugging Face cache path
                       artifact hash does not match signed registry record
                       possible reasons: alternate revision, conversion,
                       fine-tune, or unenrolled variant

  ⚠ unknown variant    google/gemma-2-9b
                       claimed by Hugging Face cache path
                       8 shards · artifact hashes do not match signed
                       registry records

  ⚠ unknown variant    llama3:8b
                       claimed by Ollama manifest

  [...]

Scanned 88 model groups (380 artifacts, 600.45 GB).
  ✓ 8 verified artifact
  ⚠ 80 unknown variant
```

The summary uses model-group language, matching the discovery banner. JSON
output (`--json`) provides the same data with stable group identifiers,
per-artifact hash records, and verification metadata. The schema is
documented in `VERIFYING.md` §7.

---

## What the statuses mean

- **`verified`** — the local artifact's SHA-256 matches a signed Fall
  Risk registry record. The match was verified under the published
  JWKS at `attest.fallrisk.ai/.well-known/jwks.json`.
- **`unknown_variant`** — the artifact's hash is not in the registry,
  but a model identifier is inferred from the local cache layout
  (e.g. the Hugging Face cache directory name, or an Ollama
  manifest). This is not unsafe — common reasons include
  quantization, alternate revisions, or repackaging of a known model.
- **`not_enrolled`** — the artifact has no registry record and no
  recoverable claim from the local cache layout. The hash is unknown
  to the registry.
- **`pilot_available`** — the model family or artifact is
  in scope for Fall Risk's enrollment pilot but the specific artifact
  has not yet been signed. Contact Fall Risk for enrollment review.

`verified` does **not** mean the model is safe, free of malware, or
appropriate for any specific deployment. See `LIMITATIONS.md` for the
full list of non-claims.

---

## Privacy

By default, Trustfall Lite sends artifact SHA-256 hashes to the Fall
Risk verification API for lookup. No model bytes, file contents,
filesystem paths, environment, or process state leave the machine.

Artifact hashes can reveal model inventory; use `--local-only` mode
for sensitive environments. In local-only mode, the signed registry
snapshot is downloaded once and verified locally; no per-hash
queries are sent.

See `PRIVACY.md` for the complete privacy posture, including how
Ollama blob handling works under the two trust modes.

---

## Verification

The cryptographic claims Trustfall Lite makes can be checked
independently. `VERIFYING.md` walks through fetching the JWKS,
verifying per-record JWS signatures, recomputing the manifest digest
from record dicts, and confirming the API returns the same data as
the static signed registry.

If you do not trust the CLI to report verification correctly, every
step it performs is reproducible from the public JWKS and the public
signed registry, with documented commands.

---

## Limitations

Trustfall Lite is scoped to a single class of claim: artifact-hash
verification against the Fall Risk registry. It does not verify model
safety, model behavior, runtime model identity, legal provenance, or
publisher signatures. See `LIMITATIONS.md` for the full list.

---

## Reporting security issues

Security reports go to `security@fallrisk.ai` with subject prefix
`[trustfall-security]`. For sensitive reports (working
verification-bypass proofs-of-concept, etc.) use the Fall Risk
security OpenPGP key — fingerprint and publish location are in
`SECURITY.md`. The canonical reporting address is
`security@fallrisk.ai`; `anthony@fallrisk.ai` is a fallback if the
primary address is unreachable for any reason.

Do **not** report security issues via public GitHub issues.

For non-security bugs (registry coverage, CLI usability, JSON output
issues), normal GitHub issues are the right path.

---

## Documentation

- `TRUST_MODEL.md` — what the cryptographic claims are
- `VERIFYING.md` — how to verify them independently
- `LIMITATIONS.md` — what the tool does not claim
- `PRIVACY.md` — what data is and is not sent
- `SECURITY.md` — how to report security issues
- `LICENSE` — Apache 2.0
- `CHANGELOG.md` — version history

---

## License

Apache License 2.0. See `LICENSE`.

Copyright 2026 Fall Risk AI, LLC.

---

## About

Trustfall Lite is published by Fall Risk AI, LLC. It is the local-scan
component of a broader runtime model identity stack — see
[fallrisk.ai](https://fallrisk.ai) for the full set of products and
the research program behind them.

Trustfall Lite answers: *Is this local artifact known and signed?*
Trustfall Deep answers: *Is this running model structurally the
enrolled model?*

Both are part of the same identity surface; they answer different
questions about it.
