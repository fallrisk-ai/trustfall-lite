# Privacy

Trustfall Lite is a local utility that scans model artifacts on the
user's machine and verifies them against the Fall Risk signed registry.
This document describes exactly what data the tool sends, when, and to
whom; what it stores; and what it does not collect.

The defaults are designed to disclose the minimum information needed to
answer the user's question. A local-only mode is available for users
with stronger privacy requirements.

---

## Default behavior

By default, when a user runs `trustfall scan`:

- **Artifact SHA-256 hashes** are sent to the Fall Risk verification API
  at `https://api.attest.fallrisk.ai/v1/` for lookup against the
  registry, unless the scan is run in local-only mode.
- **No model bytes** leave the machine.
- **No filesystem paths** leave the machine.
- **No filenames** are sent to the verification API.
- **No environment variables, process information, or system metadata**
  leave the machine.

The single class of data sent over the network in default mode is the
list of SHA-256 digests of files Trustfall identified as model
artifacts. These are sent in a single batch POST request to the
verification API's manifest endpoint, not as individual per-hash GET
queries.

---

## Local-only mode

Users who do not want hashes to leave the machine can use local-only
mode. The signed registry snapshot is downloaded once; subsequent scans
verify against the local copy:

```bash
trustfall registry --refresh
trustfall scan --local-only
```

In local-only mode, no hashes are sent over the network during the
scan itself. The only network access is the initial signed snapshot
download — an HTTPS GET of a static signed JSON document from
`https://attest.fallrisk.ai/`, not the per-hash verification API at
`https://api.attest.fallrisk.ai/v1/`.

Users may refresh the snapshot on whatever cadence they prefer. Older
snapshots remain valid; the JWS signature is verified against the
JWKS at scan time.

---

## Ollama scan modes

Trustfall Lite handles Ollama blobs in one of two modes.

**Default (verify):** every Ollama blob is content-hashed locally
during the scan. The computed SHA-256 is compared to the registry. JSON
output records `digest_verified: true` and `digest_source:
"content_hash"` for each Ollama artifact.

**Fast path (`--trust-ollama-filenames`):** the SHA-256 embedded in
the Ollama blob's content-addressed filename is trusted instead of
recomputing the hash. JSON output records `digest_verified: false` and
`digest_source: "ollama_blob_filename"` for each Ollama artifact. This
mode is faster on large Ollama installs but assumes the local
filesystem is honest about filename↔content mapping.

The mode is the user's choice. The JSON output makes the choice
explicit and machine-readable so downstream tooling can decide whether
to treat fast-path results as equivalent to verified results.

---

## JSON output and path exposure

By default, JSON output does not contain filesystem paths.

Group identifiers in the JSON are stable logical strings (e.g.
`hf_cache:Qwen/Qwen2.5-1.5B-Instruct:abc123def456`,
`ollama/library/llama3:8b`), not paths. The `scan_paths` field lists
how many path arguments were given but does not echo them. The per-
artifact `path` field is omitted unless the user explicitly opts in
with `--include-paths`.

When the user passes `--include-paths`, JSON output may include:

- the absolute filesystem path of each scanned artifact,
- the literal command-line `scan_paths` arguments.

`--include-paths` affects local JSON output only. It does not cause
filesystem paths to be sent to the verification API.

If the user has opted in, the user is responsible for redacting the
JSON before sharing it externally (in bug reports, audit submissions,
support tickets, or any other context where local home directory
exposure is undesirable).

The opt-in flag exists because some workflows genuinely need path
information for diagnostics. The default behavior assumes most users
do not.

---

## API logging

The Fall Risk verification API logs only the operational information
needed to run the service. Specifically:

- **Model bytes:** never collected. The API never receives them.
- **Hash queries:** the API receives SHA-256 digests for lookup. The
  CLI uses the manifest POST endpoint (`POST /v1/verify/manifest`)
  by default, which sends the hash list in the request body rather
  than as URL path components — so hash values do not appear in URL-
  level access logs at all in the default flow. A separate per-hash
  GET endpoint (`GET /v1/verify/hash/{sha256}`) exists for ad-hoc
  use; for that endpoint, hash values in URL paths are redacted in
  operational access logs to prevent local correlation across log
  lines. Aggregate request counts and response codes may be retained
  for service operation and abuse detection. Fall Risk does not
  retain raw hash-query values in operational access logs by default.
- **IP addresses:** may appear in standard infrastructure logs for
  rate-limiting and abuse prevention and are not intentionally
  correlated with scan contents.
- **No user identification:** no account is required to use the API.
  No persistent user identifier is collected, assigned, or stored.

Users who want to avoid hash-in-URL semantics entirely can rely on
the default CLI behavior (which uses POST manifest) or use local-only
mode (which sends no hashes at all during scans).

The API surface is documented separately in `API.md` (forthcoming).

---

## What Trustfall does not collect

Trustfall Lite does not transmit to Fall Risk, and the Fall Risk
verification API does not collect, the following by default:

- user accounts or persistent user identifiers,
- telemetry of any kind,
- analytics,
- model contents (weights, configurations, tokenizer files),
- prompts, generations, or any model inputs/outputs,
- environment variables,
- process lists or running model state,
- filenames, except where the user explicitly passes
  `--include-paths`,
- absolute or relative filesystem paths, except where the user
  explicitly passes `--include-paths`,
- usage frequency or scan timing patterns at the user-attributable
  level.

In `--trust-ollama-filenames` mode, Trustfall reads Ollama's content-
addressed blob filenames locally to derive digests; those filenames
are not transmitted.

If a future Trustfall version begins collecting any data not listed
above, this document will be updated in the same release as the
collection change, and the change will be flagged in `CHANGELOG.md`.

---

## A note on hash leakage

Artifact hashes are not model bytes, but they can still reveal which
model artifacts a user may have. A SHA-256 digest, when looked up
against a public registry, identifies the specific artifact whose hash
it is. Users with stronger privacy requirements should use local-only
mode.

This is not a hypothetical concern. A user running `trustfall scan` on
a corporate machine, against the default API, is sending the API a
fingerprint of the model artifacts on that machine — sufficient to
identify which models the user has, including artifacts whose hashes
are unique to the user's organization or can be correlated with
private model inventories.

The default behavior is designed for the common case (an individual
developer scanning a personal or development machine, accepting that
the API will see hashes in exchange for the convenience of registry
lookup). The local-only mode is designed for the case where this
tradeoff is not acceptable.

---

## Versioning

This privacy posture applies to Trustfall Lite v0.3.0. Changes to
default behavior, data collection, or logging will be:

- documented in `CHANGELOG.md` under the relevant version,
- announced as a privacy change rather than a feature change,
- noted in this document with the version they took effect.

The current posture is the posture of v0.3.0.
