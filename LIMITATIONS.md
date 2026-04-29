# Limitations

Trustfall Lite is scoped to a single class of claim: artifact-hash
verification against the Fall Risk registry. This document states what
is outside that scope. The full trust model is in `TRUST_MODEL.md`;
this document is the short version, written so it can be read in under
two minutes.

If a use case requires any claim listed below, Trustfall Lite alone
cannot provide it. Other tools, controls, or Fall Risk systems may be
needed depending on the claim.

---

## What Trustfall Lite does not claim

**A verified artifact is not a safe model.** A `verified` status from
Trustfall Lite means the local artifact's SHA-256 matches a signed Fall
Risk registry record. It does not mean the model is malware-free, safe
to use, behaves as documented, or is appropriate for any particular
deployment. Safety evaluation is a separate discipline with its own
tools.

**A verified artifact is not a verified runtime model.** Trustfall
Lite scans files on disk. It does not measure the model loaded into a
running process. The model that gets loaded into a serving framework
can differ from the artifact on disk through quantization at load
time, through an unintended adapter merge, through a Modelfile
composition that swapped the system prompt or template, or through
other post-load modifications. Catching those gaps requires runtime
structural measurement, which is the role of Trustfall Deep, not
Trustfall Lite.

**An unknown variant is not an unsafe model.** The `unknown_variant`
status means the local artifact's hash is not in the Fall Risk
registry. It does not mean the artifact is malicious, fake,
compromised, or invalid. A common reason for `unknown_variant`,
especially with Ollama, is that the artifact is a quantization or
repackaging of a model the registry has enrolled at a different
revision or in a different format. Registry coverage is not exhaustive
and is not intended to be.

**A signed Fall Risk record is not a publisher signature.** Many
upstream model publishers do not cryptographically sign their
artifacts, and publisher signing practices vary. A signed Fall Risk
registry record commits Fall Risk to having observed and enrolled a
specific artifact. It does not commit the upstream publisher to
anything, and it does not assert that the publisher would endorse the
enrollment.

**A signed Fall Risk record is not legal provenance.** License
metadata in a registry record is informational only. It does not
constitute a legal opinion, a chain-of-custody attestation, or a
license-grant assertion. Users with legal requirements about model
sourcing must verify those requirements independently.

**A local OS compromise is out of scope.** A compromised operating
system can lie about file contents, network behavior, or process
state. Defending against that requires a hardware-rooted or remote
attestation model outside the scope of a local Python utility.

---

## Appropriate use cases

Use Trustfall Lite when the questions are:

- *What model artifacts are on this machine?*
- *Which of those artifacts have signed Fall Risk records?*
- *Has my local model surface changed since a prior scan?*

These are real and useful questions. Trustfall Lite answers them
precisely. The limitations above exist so that precision is not
mistaken for broader claims the tool does not make.

For the full trust model behind these limitations, see `TRUST_MODEL.md`.
