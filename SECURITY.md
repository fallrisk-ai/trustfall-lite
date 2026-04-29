# Security Policy

Trustfall Lite is a security-relevant tool: its output is consumed by
people deciding whether to trust local model artifacts. Bugs in
Trustfall Lite — particularly bugs that cause it to report
`verified` for a hash that should not be verified, or to silently
accept a tampered registry — are security issues.

This document describes how to report security vulnerabilities, what
qualifies as one, and what to expect after reporting.

---

## Supported versions

Security fixes are issued only for the most recent published version
on PyPI. Older versions are not patched.

| Version | Status |
|---------|--------|
| 0.3.x   | Supported — security fixes issued as patch releases |
| < 0.3   | Not supported — these were internal builds, not public releases |

If you are running an older version, please upgrade to the latest
0.3.x before reporting an issue. If the issue persists in the latest
version, the report is in scope.

---

## Safe harbor

Fall Risk will not pursue legal action against good-faith security
researchers who follow this policy, avoid accessing or modifying data
that is not their own, avoid privacy violations, and make a reasonable
effort to prevent harm while reporting the issue.

Testing must not degrade, disrupt, or abuse Fall Risk services or
third-party services. Rate-limiting, fuzzing at scale, and similar
high-volume techniques should be coordinated with Fall Risk in advance
via `security@fallrisk.ai`.

If you are uncertain whether your planned testing falls within this
safe harbor, email `security@fallrisk.ai` describing what you intend to
do, and Fall Risk will provide written confirmation where feasible.

---

## How to report a vulnerability

Send security reports by email to:

```
security@fallrisk.ai
```

Subject line: `[trustfall-security] <short description>`.

`security@fallrisk.ai` is the canonical reporting address and is the
preferred channel. Reports may also be sent to `anthony@fallrisk.ai`
if for any reason the primary address is unreachable.

Please do **not** report security issues via public GitHub issues,
public discussion forums, or social media until the issue has been
acknowledged and a coordinated disclosure window has been agreed.

A useful security report includes:

- the version of Trustfall Lite (`trustfall version`),
- the platform (OS, architecture, Python version),
- a description of the issue,
- a proof-of-concept or reproducer if available,
- the impact you believe the issue has,
- whether you intend to publish details, and on what timeline.

Reports without a proof-of-concept or reproducer will still be
investigated, but the response time is likely to be slower because
verification takes longer.

---

## What counts as security-sensitive

The following classes of bugs are in scope:

- **Verification bypass.** Any input that causes Trustfall Lite to
  report `verified` for a hash that does not appear in the signed
  registry under that hash, or to accept a registry whose signatures
  do not actually verify under the published JWKS.
- **Registry tampering acceptance.** Any modification to a local copy
  of `registry.json` (per-record or manifest) that Trustfall Lite
  accepts without raising a verification failure.
- **Signature confusion.** Any case where Trustfall Lite verifies a
  signature against a key other than the kid declared in the JWS
  header, or accepts a signature signed by a key not in the JWKS.
- **JWKS handling.** Any case where Trustfall Lite trusts a JWKS
  served from an unexpected URL, fails to validate the TLS
  certificate, or accepts a JWKS whose embedded keys do not match the
  documented format.
- **Local data exfiltration.** Any case where Trustfall Lite sends
  data to the verification API beyond what is documented in
  `PRIVACY.md` (model bytes, file contents, environment, paths
  without `--include-paths`, etc.).
- **Code execution from registry data.** Any case where parsing a
  signed registry, an API response, or a local model file causes
  arbitrary code execution.
- **Credential or key leakage.** Any case where Trustfall Lite logs,
  transmits, or stores cryptographic private keys, release tokens,
  API credentials, signing material, or other secrets.
- **Package or release compromise.** Any evidence that the PyPI
  package, GitHub release artifact, signed checksums, SBOM, or
  release attestation does not correspond to the published source or
  expected release workflow.

If you are uncertain whether something is in scope, send the report
anyway and let it be triaged.

---

## What to report through normal channels instead

The following are not security issues and should be reported as
regular bugs via GitHub issues:

- Trustfall Lite reports `unknown_variant` for an artifact you
  believe should be verified. (This is a registry coverage issue, not
  a security failure.)
- Trustfall Lite reports `verified` for an artifact that you believe
  is unsafe, malicious, or unwanted. (Verification is artifact-hash
  correspondence, not safety. See `LIMITATIONS.md`.)
- Trustfall Lite is slow on large scans, has a confusing error
  message, or produces unexpected JSON output that is not a verification
  bypass.
- The CLI has a usability issue with `--include-paths`, output
  formatting, or progress display.
- The signed registry is missing a model you want enrolled. (Send to
  `anthony@fallrisk.ai` with `[trustfall-enroll]` in the subject.)

These are real issues but they are not security issues.

---

## Expected response process

Fall Risk is a founder-run project. The response process is honest
about that.

- **Acknowledgment.** Fall Risk will acknowledge credible security
  reports within 7 days where possible. If the report arrives during
  a known unavailability window (vacations, conferences) the
  acknowledgment may take longer. If no acknowledgment arrives within
  14 days, please send a follow-up; the original report may have
  been filtered or missed.
- **Triage.** After acknowledgment, the report is triaged into one of
  three buckets: confirmed vulnerability, under investigation, or
  not-a-vulnerability with explanation.
- **Fix.** Confirmed vulnerabilities are addressed in a patch release
  on a timeline proportional to severity. Critical issues
  (verification bypass, registry tampering acceptance) are addressed
  with priority over feature work.
- **Disclosure.** A fix is published as a patch release on PyPI. A
  short advisory will be published on the Fall Risk advisory surface,
  with the canonical location documented in the repository, citing
  the issue, the affected versions, and the fix. Reporters who
  request acknowledgment in the advisory will be named unless they
  request otherwise.

There is no commitment to a specific bug-bounty program at this
time.

---

## Disclosure policy

Fall Risk requests a coordinated disclosure window of 90 days from
acknowledgment, extendable by mutual agreement if the fix requires
infrastructure changes (key rotation, registry re-signing, schema
revision) that take time. Reporters who require a shorter window are
asked to say so explicitly in the initial report; the response will
explain whether the requested window is achievable.

Once a fix is released and the disclosure window expires, Fall Risk
expects reporters to be free to publish details of the vulnerability.

---

## Encrypted reports

For sensitive reports, use the Fall Risk security OpenPGP key:

- User ID: `Fall Risk Security <security@fallrisk.ai>`
- Fingerprint: `AED5 4253 466E E5F1 D435  FE32 8B2C 5DFB B12F F0F2`
- Published at: `https://fallrisk.ai/security.asc` and on
  `keys.openpgp.org`

This key is **only** for encrypted vulnerability reports. Do not use
it for verifying:

- Trustfall Lite software releases (use PyPI Trusted Publishing
  attestations and GitHub release artifact signatures instead),
- registry records (use the JWKS at
  `attest.fallrisk.ai/.well-known/jwks.json`),
- JWKS material (the JWKS is itself the trust root for registry
  signatures),
- API responses or any other Fall Risk attestation surface.

Those trust systems remain separate by design. The PGP key exists
only to encrypt sensitive vulnerability reports in transit between
researchers and Fall Risk.

---

## Scope reminders

For full context on what Trustfall Lite does and does not claim, see:

- `TRUST_MODEL.md` — what the cryptographic claims are
- `LIMITATIONS.md` — what the tool does not claim
- `VERIFYING.md` — how to independently verify claims

A bug that violates a stated claim is in scope. A bug that violates
something the tool does not claim is, by definition, out of scope —
though the report is still welcome as a documentation improvement.
