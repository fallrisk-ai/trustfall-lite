# Contributing to Trustfall Lite

Trustfall Lite is young and security-relevant. Small, focused
contributions are easier to review than broad rewrites, and easier to
audit later when someone is asking *why is this here?*

This document describes what kinds of contributions are welcome at
this stage, what kinds need discussion before implementation, how to
sign off on your commits under the Developer Certificate of Origin
(DCO), and how to handle the case where a documentation issue is
actually a security issue.

---

## What's welcome now

These contributions can be opened as pull requests directly without
prior discussion.

- **Bug fixes.** A reproducible defect with a test that demonstrates
  the fix is the easiest contribution to review and merge.
- **Tests.** Coverage improvements, regression tests for issues you
  encountered, edge cases the existing suite does not exercise.
- **Documentation corrections.** Typos, broken links, factual errors,
  out-of-date version numbers, command examples that no longer work,
  unclear phrasing. (See "Documentation as security surface" below
  for one important exception.)
- **Installation fixes.** Cases where `pipx install fallrisk-trustfall`
  or `pip install fallrisk-trustfall` fails on a platform we should
  support, or where a clearly-documented install path produces an
  unexpected error.
- **Platform compatibility fixes.** Linux, macOS, and Windows are
  supported; if you find a Python 3.10+ environment where Trustfall
  Lite misbehaves, a fix is welcome.
- **Small adapter improvements.** Edge cases in the Hugging Face cache
  adapter or the Ollama adapter — for example, handling a manifest
  format we missed, or recognizing a cache layout variation. Discuss
  first if the change is more than incremental.

### Before opening a pull request

Code changes should include tests where practical. If a test is not
practical, explain why in the pull request.

Do not include the following in issues, pull requests, commit
messages, or attached files:

- private keys, API tokens, or other credentials,
- unpublished registry material (private records, signed records that
  have not been published, JWS blobs from private registries),
- model weights or model artifacts that you do not have the right to
  share publicly,
- proprietary measurement artifacts (anchor files, prompt banks,
  per-seed measurements, contract hashes from non-public contracts),
- internal Fall Risk operational artifacts (run logs, gate outputs,
  internal nomenclature).

If you encounter a bug whose reproduction requires private material,
describe the problem in general terms in the public issue and send
the supporting material to `security@fallrisk.ai` referencing the
issue number.

---

## What needs discussion first

Open an issue before opening a pull request for any of the following.
This is not gatekeeping; it protects both the project and your time.
Substantial work in any of these areas could land in a state that is
inconsistent with the trust model or with planned future work, and
either outcome wastes your effort.

- **New commands.** `trustfall scan`, `trustfall verify`,
  `trustfall diff`, and `trustfall registry` are the current command
  surface. New commands change the user-facing contract.
- **New source adapters.** LM Studio, custom Ollama registries,
  alternative model stores, and similar are on the v0.4+ roadmap and
  need to land in a coordinated way.
- **Registry schema changes.** The signed registry record format is a
  cryptographic commitment surface. Schema changes have downstream
  consequences for every consumer.
- **Signature or JWKS behavior changes.** Anything affecting how
  records are signed, how signatures are verified, or how the JWKS is
  consumed.
- **API behavior changes.** The verification API at
  `api.attest.fallrisk.ai/v1/` is a stable interface; client behavior
  against it should not change unilaterally.
- **Enrollment flows.** Pilot enrollment is currently handled
  out-of-band (see the README). Self-serve enrollment is a deliberate
  future-roadmap item, not a community-built feature.
- **Runtime identity features.** Anything resembling structural
  fingerprinting of running processes belongs to Trustfall Deep, not
  Trustfall Lite, and is not a community contribution surface.
- **Large refactors.** A 2,000-line PR that "cleans up" something is
  almost always harder to review than a series of small focused
  changes.

If you are unsure whether a contribution falls into "welcome now" or
"discuss first," err toward opening a brief issue describing what you
want to do. We would rather spend ten minutes confirming a direction
than have you build the wrong thing.

---

## Developer Certificate of Origin (DCO)

All contributions must be signed off under the Developer Certificate
of Origin. The DCO is a lightweight per-commit attestation that you
have the right to submit the work under the project's license
(Apache 2.0).

### Why DCO and not a CLA?

A Contributor License Agreement (CLA) is a separate signed document
that grants additional rights to the project. It is appropriate for
some projects but creates friction for the one-off contributor who
wants to fix a typo. The DCO achieves the legal clarity needed for
an Apache 2.0 project without that friction. Trustfall Lite may
adopt a CLA in the future for specific cases (large code donations,
employer-assigned contributions); the DCO is the baseline for now.

### How to sign off

Add a `Signed-off-by` line to your commit message:

```
git commit -s -m "Fix typo in INSTALL.md"
```

The `-s` flag adds the line automatically using the name and email
configured in your git settings. The line looks like:

```
Signed-off-by: Your Name <you@example.com>
```

The full text of what the sign-off attests to is at
[developercertificate.org](https://developercertificate.org/). In
plain language: you wrote the contribution, or you have permission
from whoever did, and you are submitting it under the project's
license.

Pull requests with unsigned commits will be flagged for sign-off
before review.

---

## Documentation as security surface

For most projects, documentation issues are not security issues. For
Trustfall Lite, this is sometimes not true.

Trustfall Lite makes specific cryptographic and verification claims
in its documentation: what `verified` means, what a signed registry
record commits to, what the trust assumptions are. Documentation
that misrepresents any of these claims is, for the purposes of this
project, a security issue. A user reading the docs and then running
the tool is relying on the docs being accurate; a doc bug in this
class can cause a user to misinterpret what the tool actually
guarantees.

If a documentation issue affects the meaning of a security or
verification claim — for example, a doc says the tool verifies
something it does not, or describes a registry record claim
incorrectly — treat it as security-sensitive and report it via
`security@fallrisk.ai` rather than a public issue. See `SECURITY.md`
for the full reporting process.

If you are uncertain whether a doc issue rises to this bar, the safe
choice is to send it to `security@fallrisk.ai`. Over-reporting in
this category is welcome.

---

## Response expectations

This is a small project run by a small team. Realistic timing:

- **Issues** acknowledged within a week, typically sooner.
- **Pull requests** for clearly-scoped welcome-now contributions
  reviewed within two weeks, typically sooner.
- **Discussion threads** on roadmap-affecting work may take longer,
  particularly when they overlap with active research sprints.

If a pull request has been waiting more than three weeks without a
response, leave a polite comment on it; it has likely been missed.

---

## Code of conduct

Trustfall Lite follows the
[Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
See `CODE_OF_CONDUCT.md` for the full text and the enforcement
process. Conduct issues are reported to `conduct@fallrisk.ai` with
subject prefix `[trustfall-conduct]`. This is a separate channel
from `security@fallrisk.ai` (vulnerability reports) and from public
GitHub Issues (bug reports and feature discussion).

Bug reports and feature discussion go in GitHub Issues unless they
are security-sensitive (see `SECURITY.md` and the documentation-as-
security-surface section above).
