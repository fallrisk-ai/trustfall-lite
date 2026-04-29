# Trust Model

Trustfall Lite verifies that local model artifacts match signed records in
the Fall Risk registry. It does not verify model safety, model behavior,
legal provenance, or runtime model identity.

This document defines:

- the exact claim a Trustfall Lite scan supports,
- the exact claims it does not support,
- what a signed Fall Risk registry record means,
- the boundary between Trustfall Lite and Trustfall Deep,
- the trust assumptions a user accepts when running the tool.

Every status, every signature, and every claim emitted by Trustfall Lite is
defined here. The behavior of the tool follows this document. Where this
document and the tool disagree, the discrepancy is a bug and must be
resolved before the affected behavior is relied on.

---

## Core doctrine

Six sentences. They appear in this order throughout the rest of the
document, the registry surface, and the public docs. They are the
canonical doctrine.

1. **Lite verifies artifacts. Deep verifies runtime structural identity.**
2. **The Fall Risk registry signs records. `record_jws` is authoritative.**
3. **A signed registry record is not a safety certification.**
4. **A signed registry record is not legal provenance.**
5. **A signed registry record is not a runtime identity proof.**
6. **Unknown variant does not mean unsafe.**

---

## What Trustfall Lite verifies

A scan produces, for each model artifact found on disk, a SHA-256 hash
of the artifact's bytes. The hash is compared against the Fall Risk
signed registry. The comparison answers exactly one question:

> Does this local artifact's hash match a signed record in the Fall Risk
> registry?

That question has four possible answers, surfaced as four statuses.

### `verified`

The local SHA-256 matches a signed record in the Fall Risk registry under
the issuer key `fallrisk-96cd5e6a01e1`. The signed record commits the
issuer to a model identifier, an enrollment timestamp, and a set of
content digests. The local bytes match the enrolled artifact exactly.

What this means: at the moment of enrollment, Fall Risk observed the
artifact, computed its hash, and signed a record associating that hash
with the stated model identifier. The local artifact is byte-identical
to that observation.

What this does not mean: that the model is safe, that the model behaves
as expected, that the publisher signed the artifact, that the artifact is
legally licensed for any particular use, or that the model loaded into a
running process is structurally the same as the artifact on disk.

### `unknown_variant`

A model identifier could be inferred from the artifact's location (the
Hugging Face cache directory name, the Ollama manifest, or a filename
pattern) but its SHA-256 does not match any signed record in the
registry. The artifact's identity by name is recognizable; its identity
by content is not enrolled.

Common reasons:

- A quantized or repackaged version, including Ollama, GGUF, GPTQ, or
  AWQ. The same model can produce different bytes under different
  packaging.
- An alternate revision of an enrolled model.
- A custom Ollama Modelfile composition that produced different bytes.
- A fine-tune or merge published under a name resembling the base
  model.
- An artifact that simply has not been enrolled yet.

What `unknown_variant` does not mean: unsafe, malicious, compromised,
fake, poisoned, or invalid. It means: not enrolled. The status is
informational. The interpretation belongs to the user.

### `not_enrolled`

The local file is recognizable as a model artifact, but Trustfall Lite
cannot derive a supported model claim from its source context, and the
SHA-256 is not in the registry. This typically means a loose model file
outside any standard cache layout.

### `pilot_available`

An informational escalation path for artifacts that require deeper
review. Reserved for cases where Fall Risk has identified a route toward
a controlled enrollment workflow. Not a self-serve mechanism. Trustfall
Lite v0.3 does not include an enrollment command; pilot enrollment is
handled out-of-band through Fall Risk. Contact information is in the
README.

---

## What Trustfall Lite does not verify

The tool's scope is narrow by design. The following claims are out of
scope and are not made by any Trustfall Lite output.

| Claim | Trustfall Lite supports? | Notes |
|---|---|---|
| This local artifact hash matches a signed Fall Risk record | Yes | Core claim. Status `verified`. |
| This local model is safe | No | Out of scope. Use a safety evaluation tool. |
| This model behaves as documented | No | Out of scope. Use behavioral evaluation. |
| This model is the publisher's original artifact | Not by itself | A registry record may include source metadata, but Lite verifies local bytes against Fall Risk's signed record, not the publisher's independent release process. |
| This artifact is legally sourced or licensed for a particular use | No | Out of scope. License metadata in registry records is informational. |
| This running process is using the enrolled model | No | This is what Trustfall Deep addresses. |
| This local model surface changed since a prior scan | Yes | Use `trustfall diff` against a prior scan's JSON output. |
| This model has not been modified post-publication | No | A `verified` status confirms hash match against the enrolled artifact, not the absence of upstream modification. |
| This model is free of safety-alignment removal (abliteration) | No | Detection of safety-alignment removal requires structural measurement (Trustfall Deep). |

The pattern: Trustfall Lite makes one claim cleanly. Every other claim
that could be confused for it is denied here, in writing, before a user
or a journalist or a regulator has the opportunity to make the
confusion themselves.

---

## What a signed registry record means

A Fall Risk registry record is a JWS-signed JSON object asserting that,
at the time of enrollment, a particular SHA-256 hash corresponded to a
particular model identifier under the issuer's stated metadata.

The signature commits Fall Risk to the record's contents. It does not
commit anyone else. In particular, it does not commit:

- the upstream publisher of the model,
- any third-party safety evaluator,
- any legal authority on licensing,
- the model's behavior in any deployment context.

Each record contains:

- `model_id` — the identifier under which the artifact was enrolled
- `enrollment_id` — Fall Risk's internal identifier for this enrollment
- `enrollment_date` — when the artifact was observed and enrolled
- `evidence_digest` — SHA-256 of the underlying enrollment evidence
  artifact (committed without disclosing the evidence)
- `contract_version` — the version of the measurement contract used
  (currently `itpuf-v0.1.0`)
- `architecture` — the model's architecture as observed at enrollment
- `n_layers` — layer count
- `trust_mode` — currently `standard`, reserved for future registry
  modes with different issuer or custody semantics
- `status` — `active`, with rotation/revocation semantics defined in
  `KEYS.md`
- `issuer` — `https://attest.fallrisk.ai`

`evidence_digest` is a commitment, not a public reproduction path.
External users cannot recompute it unless Fall Risk discloses the
underlying evidence artifact. Its purpose is to bind Fall Risk to a
specific enrollment evidence object without publishing measurement
internals. The commitment is meaningful because Fall Risk has
cryptographically committed to a specific evidence artifact that it
can be asked to produce under an appropriate review, dispute, or audit
process; it is not meaningful as an independently reproducible
verification path.

The record does not contain the prompt bank, the per-seed measurements,
the hooking protocol, or any information that would allow an external
party to reproduce the structural fingerprint computation. Those
details are protected implementation material and are not part of the
Lite trust claim. The record commits the issuer to having performed
the measurement; it does not disclose how.

`record_jws` is authoritative. Decoded record fields are convenience.

The JWKS is published at `https://attest.fallrisk.ai/.well-known/jwks.json`
under the kid `fallrisk-96cd5e6a01e1`. The fingerprint is
`sha256:FlqonYOsEwXi5eaLuhjMKmHzbKxtM0MrM7yGg2xW-2M`. Verification
recipes are in `VERIFYING.md`.

---

## The boundary between Lite and Deep

Trustfall Lite verifies artifacts. Trustfall Deep verifies runtime
structural identity. They answer different questions.

| Question | Tool |
|---|---|
| What model artifacts are on this machine? | Trustfall Lite (`scan`) |
| Which of those artifacts have signed Fall Risk records? | Trustfall Lite (`scan`) |
| What changed since a prior scan? | Trustfall Lite (`diff`) |
| Is the model loaded into this running process structurally the model that was enrolled? | Trustfall Deep (pilot) |
| Has the model been modified to remove safety alignment? | Trustfall Deep (pilot) |
| Has the model been distilled from a different teacher than declared? | Trustfall Deep (pilot) |

A `verified` status from Trustfall Lite tells you what is on disk. It
does not tell you what is running in your process. The model loaded into
a serving framework can differ from the artifact on disk through
quantization at load time, through an unintended adapter merge, through
a Modelfile composition that changed the system prompt or template, or
through any of the post-publication modification techniques the Fall
Risk research program documents.

Catching those gaps requires measuring the running model. That is
Trustfall Deep, the runtime structural identity layer behind the Fall
Risk research program. It is in pilot with selected partners and is not
part of the Trustfall Lite release.

The two tools compose. Lite is necessary for the artifact-on-disk claim.
Deep is necessary for the runtime claim. Neither replaces the other.

---

## Trust assumptions

A user running Trustfall Lite implicitly accepts the following
assumptions. They are listed here so they can be evaluated and rejected
where they do not hold.

1. **The local operating system is not actively lying.** A compromised
   OS can lie to local tools about file contents, process state, or
   network behavior. Defending against a compromised local operating
   system requires a hardware-rooted or remote attestation model
   outside the scope of a local Python utility.

2. **The user obtains the Fall Risk JWKS through an authentic
   channel.** By default, Trustfall Lite relies on HTTPS to retrieve
   the JWKS at `attest.fallrisk.ai/.well-known/jwks.json` and on the
   documented fingerprint
   `sha256:FlqonYOsEwXi5eaLuhjMKmHzbKxtM0MrM7yGg2xW-2M` as the
   verification anchor. Users with stronger requirements should pin
   the JWKS fingerprint out of band.

3. **SHA-256 is preimage-resistant.** Standard cryptographic assumption.
   If SHA-256 is broken, Trustfall Lite's hash-match claims become
   unreliable, as do most current software supply-chain tools.

4. **The Trustfall Lite binary itself has not been tampered with.** The
   release pipeline uses PyPI Trusted Publishing with GitHub Actions
   attestations; verification recipes are in `VERIFYING.md`. Users who
   install from PyPI without verifying provenance are implicitly
   trusting the PyPI package distribution path and the published
   release workflow.

These assumptions are listed so a user, security architect, or auditor
can read them and decide whether they hold for their context. Tools
that hide their trust assumptions are harder to audit than tools that
state them.

---

## Network and privacy posture

By default, Trustfall Lite sends artifact SHA-256 hashes to the Fall Risk
verification API at `api.attest.fallrisk.ai/v1/` for lookup. No model
bytes leave the machine. No filesystem paths leave the machine unless
`--include-paths` is passed.

A local-only verification mode is available:

```
trustfall registry --refresh   # one-time download of signed registry
trustfall scan --local-only    # verify against local snapshot, no API
```

In local-only mode, no hashes are sent over the network during scan.
Full details are in `PRIVACY.md`.

---

## Limitations

Limitations are documented separately in `LIMITATIONS.md`. The
limitations document is short by design and should be read alongside
this trust model. Together they define the scope.

---

## Versioning of this document

This document defines doctrine, not features. The doctrine is expected
to be stable across minor versions. If the doctrine changes, the change
will be:

- documented in `CHANGELOG.md` under the relevant version,
- accompanied by a clear statement of what changed and why,
- announced as a doctrine change rather than a feature change.

Doctrine changes do not silently rewrite prior signed records. Existing
records remain interpretable under the `contract_version`, schema
version, and registry status in force when they were issued, unless a
later registry entry explicitly revokes, supersedes, or deprecates them.

The current doctrine is the doctrine of v0.3.0.
