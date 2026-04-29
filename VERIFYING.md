# Verifying Trustfall Lite Claims

This document explains how to check the public keys, signatures,
registry digests, and hash membership that underlie Trustfall Lite
output, without treating the CLI output as self-authenticating.

The goal is to make every cryptographic claim falsifiable. If
something in this document is wrong, or a verification command does
not produce the documented result, that is a bug.

For the trust model behind these claims, see `TRUST_MODEL.md`. For
what Trustfall Lite does not claim, see `LIMITATIONS.md`.

---

## What can be verified

Trustfall Lite's claims reduce to four cryptographic statements:

1. **The signing key is the one Fall Risk published.** The JWKS at
   `attest.fallrisk.ai/.well-known/jwks.json` contains the public key
   under kid `fallrisk-96cd5e6a01e1`.

2. **The signed registry was signed by that key.** Both the per-record
   JWS signatures and the manifest JWS in `registry.json` verify
   against the JWKS.

3. **The registry record set has not been tampered with.** The
   manifest digest commits to the canonical JSON of all decoded
   record payloads. Per-record JWS signatures verify the individual
   signed records.

4. **A specific artifact's hash is in the signed registry.** If
   Trustfall Lite says a hash is `verified`, that hash appears in a
   signed record under a stated model identifier.

Everything else is downstream of these four. If they hold, the
"verified" status means what it claims. If any of them fails, do not
trust the tool's output for that scan.

---

## Quick verification path

For a minimal check, run these five steps in order:

1. **Fetch the JWKS** and confirm the kid is `fallrisk-96cd5e6a01e1`
   and the RFC 7638 thumbprint matches the documented value (§1).
2. **Fetch `registry.json`** and confirm its embedded JWKS byte-matches
   the live JWKS (§2).
3. **Verify one per-record JWS** against the public key (§3).
4. **Recompute `manifest_digest`** from the record dicts and confirm
   it matches the declared value (§4).
5. **Query the API** for one known hash and confirm the returned
   `record_jws` byte-matches the local registry's signature (§6).

Each step takes seconds and is independently falsifiable. The sections
below give the full commands, expected output, and discussion of edge
cases.

---

## 1. Fetch and inspect the JWKS

The JWKS is a static, publicly served JSON document retrieved over
HTTPS. Anyone can fetch it at any time:

```bash
curl -sSL https://attest.fallrisk.ai/.well-known/jwks.json -o jwks.json
python3 -m json.tool jwks.json
```

Expected structure:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "kid": "fallrisk-96cd5e6a01e1",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

The canonical issuer kid is `fallrisk-96cd5e6a01e1`. If a different
kid appears in the JWKS without a documented rotation announcement,
something is wrong — stop and investigate.

You can compute the RFC 7638 thumbprint of the key independently:

```bash
python3 -c "
import json, hashlib, base64
jwks = json.load(open('jwks.json'))
# Find the canonical issuer key by kid
key = next(
    k for k in jwks['keys']
    if k['kid'] == 'fallrisk-96cd5e6a01e1'
)
canon = json.dumps(
    {'e': key['e'], 'kty': key['kty'], 'n': key['n']},
    separators=(',', ':'), sort_keys=True,
).encode()
thumb = hashlib.sha256(canon).digest()
print('sha256:' + base64.urlsafe_b64encode(thumb).decode().rstrip('='))
"
```

The expected RFC 7638 thumbprint as of April 28, 2026 is:

```
sha256:FlqonYOsEwXi5eaLuhjMKmHzbKxtM0MrM7yGg2xW-2M
```

If a future version of this document changes that thumbprint without a
documented key rotation, the document is wrong, the JWKS has been
tampered with, or the key has been rotated. All three are situations a
skeptical verifier should care about.

---

## 2. Fetch the signed registry

The signed registry is also a static, publicly-served JSON document:

```bash
curl -sSL https://attest.fallrisk.ai/registry.json -o registry.json
```

Inspect its top-level structure:

```bash
python3 -c "
import json
r = json.load(open('registry.json'))
m = r['manifest']
print('format:          ', r['format'])
print('n_models:        ', m['n_models'])
print('issuer_kid:      ', m['issuer_kid'])
print('contract_version:', m['contract_version'])
print('manifest_digest: ', m['manifest_digest'])
print('models signed:   ', len(r['models']))
print('jwks keys:       ', len(r['jwks']['keys']))
"
```

Expected:

- `issuer_kid` is `fallrisk-96cd5e6a01e1`
- `contract_version` is `itpuf-v0.1.0`
- `manifest_digest` is a 64-character hex string
- `len(models)` matches `n_models` (note: `models` is a dict keyed by
  model_id, not a list)
- `len(jwks.keys)` is at least 1

The registry embeds its own JWKS as a convenience. Verify that the
embedded JWKS semantically matches the JWKS at the well-known URL.
Use a structured comparison rather than a text diff to avoid false
mismatches from whitespace or key-ordering differences:

```bash
python3 << 'EOF'
import json
import sys
import urllib.request

registry = json.load(open("registry.json"))
embedded = registry["jwks"]

with urllib.request.urlopen("https://attest.fallrisk.ai/.well-known/jwks.json") as r:
    live = json.load(r)

if embedded == live:
    print("JWKS MATCH")
else:
    print("JWKS MISMATCH")
    sys.exit(1)
EOF
```

If the JWKS does not match, the registry is signed by a key that is
not the publicly-published key. Every per-record signature in the
registry will fail to verify against the published JWKS. This is the
silent-fail mode that breaks verifiers without raising any obvious
errors locally — the registry will look syntactically valid, but
nothing in it will verify under the key a relying party would fetch.
Do not trust a registry whose embedded JWKS does not semantically
match the published JWKS.

---

## 3. Verify a per-record signature

Each model in the registry is stored as a `{record, signature}` pair,
where `signature` is a JWS whose payload is the registry `record`.
The verifier checks that the decoded JWS payload equals the adjacent
`record`. Modifying any field in the record without re-signing breaks
this equality.

The `models` field at the top of `registry.json` is a dict keyed by
`model_id`, not a list. Pick any model and verify its signature:

```bash
pip install PyJWT cryptography

python3 << 'EOF'
import json
import jwt
from jwt.algorithms import RSAAlgorithm

# Load registry
r = json.load(open('registry.json'))

# Load JWKS and convert to PEM (find the canonical key by kid)
jwk_data = next(
    k for k in r['jwks']['keys']
    if k['kid'] == 'fallrisk-96cd5e6a01e1'
)
public_key = RSAAlgorithm.from_jwk(json.dumps(jwk_data))

# Pick the first model (models is a dict keyed by model_id)
model_id, entry = next(iter(r['models'].items()))
record = entry['record']
signature = entry['signature']

# Verify the JWS signature
try:
    decoded = jwt.decode(
        signature,
        public_key,
        algorithms=['RS256'],
        options={'verify_aud': False, 'verify_iss': False, 'verify_exp': False},
    )
    print(f"Signature VERIFIED for: {model_id}")
    print(f"  Enrollment ID:   {decoded.get('enrollment_id')}")
    print(f"  Evidence digest: {decoded.get('evidence_digest')}")
    # Sanity check: the decoded payload should match record
    assert decoded == record, "Decoded JWS payload != record"
    print(f"  Decoded payload matches record exactly")
except jwt.InvalidSignatureError:
    print("Signature INVALID — record was tampered with")
EOF
```

Repeat for as many records as you wish to verify. Every record signs
independently. A failure on any one record invalidates that record but
does not invalidate others.

To prove tampering detection works, modify one byte of any field in
the registry and re-run verification. For example, this script flips
one character of the `model_id` field on the first record before
verifying:

```bash
python3 << 'EOF'
import json
import jwt
from jwt.algorithms import RSAAlgorithm

r = json.load(open('registry.json'))
jwk_data = next(
    k for k in r['jwks']['keys']
    if k['kid'] == 'fallrisk-96cd5e6a01e1'
)
public_key = RSAAlgorithm.from_jwk(json.dumps(jwk_data))

# Tamper: change the model_id in the record (but leave the signature alone)
model_id, entry = next(iter(r['models'].items()))
tampered_record = dict(entry['record'])
tampered_record['model_id'] = 'tampered-model-id'

# The signature was computed over the original record — it cannot match
# the tampered record. Verifying the signature still works (because the
# signature itself is unchanged), but the decoded payload will differ.
decoded = jwt.decode(
    entry['signature'], public_key, algorithms=['RS256'],
    options={'verify_aud': False, 'verify_iss': False, 'verify_exp': False},
)
if decoded != tampered_record:
    print(f"TAMPERING DETECTED: signature payload does not match tampered record")
    print(f"  Original model_id (from signature): {decoded['model_id']}")
    print(f"  Tampered model_id (in registry):    {tampered_record['model_id']}")
EOF
```

The tampering-detection model here is: a verifier always treats the
signed JWS payload as authoritative, not the record stored alongside
it. If those two ever disagree, the registry has been tampered with
between signing and serving.

---

## 4. Verify the manifest digest commits to the record set

The `manifest_digest` commits to the canonical JSON of all decoded
record payloads. Per-record JWS signatures remain the authoritative
signatures for individual records — the manifest digest does not
include the signatures themselves, only the record dicts they sign.

Concretely, the digest is computed as:

```python
hashlib.sha256(json.dumps(
    {model_id: entry["record"] for model_id, entry in models.items()},
    sort_keys=True,
    separators=(',', ':'),
).encode()).hexdigest()
```

There are two distinct tampering-detection paths in this design, and
they catch different attacks:

- **Tampering with a decoded `record` field changes the manifest
  digest.** This is detected by recomputing the manifest digest and
  comparing to the declared value (and by verifying the manifest
  signature, which signs over the manifest including the digest).
- **Tampering with a per-record `signature` field is detected by
  per-record JWS verification, not by the manifest digest.** A
  forger could leave the `record` dicts unchanged and only modify
  signature bytes — the manifest digest would still match, but the
  per-record signatures would fail to verify.

Both checks should pass on a clean registry. Either failing on its
own is sufficient to invalidate the registry; both must pass for the
registry to be trusted.

Reproduce the manifest digest from the records:

```bash
python3 << 'EOF'
import json
import hashlib

r = json.load(open('registry.json'))

# Build the dict the manifest_digest commits to:
# { model_id : record_dict }
records_dict = {
    model_id: entry['record']
    for model_id, entry in r['models'].items()
}

# Canonical JSON: sort_keys=True, no whitespace
canon = json.dumps(records_dict, sort_keys=True, separators=(',', ':'))
computed = hashlib.sha256(canon.encode()).hexdigest()

declared = r['manifest']['manifest_digest']

print(f"Computed: {computed}")
print(f"Declared: {declared}")
print(f"MATCH" if computed == declared else "MISMATCH")
EOF
```

Then verify that the manifest itself is signed under the same key.
The `manifest_signature` is a JWS over the entire `manifest` dict
(including the `manifest_digest` field):

```bash
python3 << 'EOF'
import json
import jwt
from jwt.algorithms import RSAAlgorithm

r = json.load(open('registry.json'))
jwk_data = next(
    k for k in r['jwks']['keys']
    if k['kid'] == 'fallrisk-96cd5e6a01e1'
)
public_key = RSAAlgorithm.from_jwk(json.dumps(jwk_data))

manifest_jws = r['manifest_signature']
decoded = jwt.decode(
    manifest_jws,
    public_key,
    algorithms=['RS256'],
    options={'verify_aud': False, 'verify_iss': False, 'verify_exp': False},
)
print(f"Manifest signature VERIFIED")
print(f"Decoded manifest_digest: {decoded.get('manifest_digest')}")
print(f"Stored manifest_digest:  {r['manifest']['manifest_digest']}")
assert decoded.get('manifest_digest') == r['manifest']['manifest_digest']
assert decoded == r['manifest'], "Decoded manifest payload != stored manifest"
print(f"Decoded manifest payload exactly equals stored manifest")
EOF
```

If the computed digest matches the declared digest, AND the manifest
signature verifies, AND the digest in the signed manifest matches the
digest in the stored manifest, the chain is intact at the manifest
layer. Combine this with §3 per-record signature verification for the
full guarantee.

---

## 5. The `evidence_digest` limitation

Each signed record contains an `evidence_digest` field. This is a
SHA-256 commitment to the full anchor file used to enroll the model.
The anchor file is not public.

This means `evidence_digest` is a **commitment**, not a
**reproduction path**. You can verify that the digest in the signed
record matches a fixed value, but you cannot recompute the digest
yourself unless Fall Risk gives you the anchor file.

The commitment binds Fall Risk to a specific anchor at signing time. If
Fall Risk later produces an anchor file that does not match the
committed digest, that mismatch is detectable. The commitment does not
let an outside party verify what is inside the anchor.

This is a deliberate trust tradeoff:

- The IT-PUF measurement protocol, prompt bank, and per-anchor τ
  vectors are not in the registry, by design (the prompt bank is part
  of the security credential and is not public).
- The signed `evidence_digest` lets Fall Risk be challenged on
  consistency — if anyone produces an anchor whose digest does not
  match the signed value, that proves Fall Risk's records are
  inconsistent with their measurements.
- The signed `evidence_digest` does not let an outside party reproduce
  the measurement without access to the anchor.

For verification purposes: the `evidence_digest` is a static field
under the per-record signature. If the per-record signature verifies,
the digest is the digest Fall Risk committed to at signing time.

For deeper verification of the underlying measurement, runtime
attestation (Trustfall Deep) is the relevant product surface. That is
documented separately.

---

## 6. Verify the API independently

The Fall Risk verification API is a separate surface from the static
registry. It accepts a manifest of SHA-256 hashes and returns lookup
results, each containing a JWS that should match the corresponding
record in the static signed registry.

The request body shape is:

```json
{
  "hashes": [{"sha256": "abc123..."}, ...],
  "client": {"name": "...", "version": "..."}
}
```

The response shape is:

```json
{
  "results": [
    {"sha256": "abc123...", "status": "verified", "record_jws": "eyJ..."},
    {"sha256": "def456...", "status": "not_enrolled"}
  ],
  "registry_kid": "fallrisk-96cd5e6a01e1",
  "registry_snapshot_at": "2026-04-...",
  "registry_manifest_digest": "5f159f7f6408e476..."
}
```

The `registry_manifest_digest` field is the
`manifest.manifest_digest` value from the registry snapshot the API
used for the lookup. A verifier comparing the API's response to a
local static registry should compare digests, not just timestamps —
digest equality proves the two snapshots are byte-equivalent in
their record set.

To verify the API independently, send a manifest containing a hash you
know is in the signed registry, and confirm the response's
`record_jws` matches the signature in the local registry, and the
manifest digests align:

```bash
# Pick a verified artifact hash from the local signed registry
KNOWN_HASH=$(python3 -c "
import json
r = json.load(open('registry.json'))
for model_id, entry in r['models'].items():
    artifacts = entry['record'].get('artifact_hashes', [])
    if artifacts:
        a = artifacts[0]
        h = a['sha256'] if isinstance(a, dict) else a
        print(h)
        break
")
echo "Querying API for: $KNOWN_HASH"

curl -sSL -X POST https://api.attest.fallrisk.ai/v1/verify/manifest \
    -H "Content-Type: application/json" \
    -d "{\"hashes\": [{\"sha256\": \"$KNOWN_HASH\"}], \"client\": {\"name\": \"verify-doc\", \"version\": \"1.0\"}}" \
    > api_response.json

python3 << 'EOF'
import json, sys

resp = json.load(open('api_response.json'))
local = json.load(open('registry.json'))

# Print API response summary
print(f"API registry_kid:             {resp.get('registry_kid')}")
print(f"API registry_snapshot_at:     {resp.get('registry_snapshot_at')}")
print(f"API registry_manifest_digest: {resp.get('registry_manifest_digest')}")
print(f"Local manifest_digest:        {local['manifest']['manifest_digest']}")

# Compare manifest digests (the strong check)
api_digest = resp.get('registry_manifest_digest')
local_digest = local['manifest']['manifest_digest']
if api_digest and local_digest:
    if api_digest == local_digest:
        print("Manifest digests MATCH — API and local registry are the same snapshot")
    else:
        print("Manifest digests DIFFER — API and local registry are different snapshots")
        print("(this can be normal during a registry rollout)")

results = resp.get('results', [])
if not results:
    print("API returned no results — abort")
    sys.exit(1)

result = results[0]
target_hash = result['sha256']
status = result.get('status')
print(f"API status for hash:          {status}")

if status != 'verified':
    print("Hash not verified by API — check that the hash is actually in the local registry")
    sys.exit(0)

api_jws = result.get('record_jws')

# Find the model whose record contains target_hash, then compare signatures
local_signature = None
matched_model_id = None
for model_id, entry in local['models'].items():
    artifacts = entry['record'].get('artifact_hashes', [])
    for art in artifacts:
        h = art['sha256'] if isinstance(art, dict) else art
        if h == target_hash:
            local_signature = entry['signature']
            matched_model_id = model_id
            break
    if local_signature is not None:
        break

if local_signature is None:
    print("Hash not found in local registry — possible registry version mismatch")
    sys.exit(0)

if api_jws == local_signature:
    print(f"API record_jws byte-matches local registry signature for {matched_model_id}")
else:
    print(f"API record_jws DIFFERS from local registry signature for {matched_model_id}")
    print(f"  API:   {api_jws[:60]}...")
    print(f"  Local: {local_signature[:60]}...")
EOF
```

If the API's `record_jws` byte-matches the signature in the local
static registry, the API is serving the same registry that is
published at `attest.fallrisk.ai/registry.json`.

If they differ, the API may have been updated to a newer registry
version that has not yet been published as a static file (or vice
versa). Either situation is worth investigating; the static signed
registry is the authoritative source.

A byte mismatch between API `record_jws` and local registry
`signature` is not automatically a cryptographic failure. Compare the
API response's `registry_manifest_digest` to the static registry's
`manifest.manifest_digest`. If those digests differ, the API and the
local registry refer to different snapshots — the mismatch reflects a
normal registry rollout in progress, not a verification failure. Both
snapshots' signatures should still verify under the same JWKS.

If the API and the static registry have the **same**
`registry_manifest_digest` but disagree about the same hash within
that snapshot, that is a bug worth reporting.

The API is convenient for batch lookups but is not authoritative. The
authoritative source is the signed registry at
`attest.fallrisk.ai/registry.json`.

---

## 7. End-to-end CLI sanity check

The CLI is the user's normal interface to all of the above. To verify
the CLI is doing what it claims, run a scan with JSON output and
confirm that every `verified` group corresponds to a hash that
actually appears in the static signed registry:

```bash
trustfall scan --json ~/.cache/huggingface/hub/ > scan.json
```

Inspect the top-level shape:

```bash
python3 << 'EOF'
import json
scan = json.load(open('scan.json'))
print(f"Tool version:      {scan['trustfall_lite_version']}")
print(f"Groups scanned:    {scan['summary']['groups_scanned']}")
print(f"Artifacts scanned: {scan['summary']['artifacts_scanned']}")
print(f"Status counts:     {scan['summary']['counts']}")
print()
print("First three verified groups:")
verified = [g for g in scan['groups'] if g['status'] == 'verified']
for g in verified[:3]:
    enroll = g.get('enrollment_id', '(none)')
    label = g.get('model_id') or g.get('claimed_model_id') or g.get('group_id')
    print(f"  - {label}  enrollment={enroll}")
EOF
```

Then independently look up each verified hash in the static signed
registry to confirm the CLI is not asserting verification of a hash
the registry does not actually contain. A scan group can contain
multiple artifacts (e.g. sharded models); every artifact's hash
should appear in the static registry under the matched record:

```bash
python3 << 'EOF'
import json
scan = json.load(open('scan.json'))
registry = json.load(open('registry.json'))

# Build a set of all artifact hashes in the static signed registry
known_hashes = set()
for model_id, entry in registry['models'].items():
    for art in entry['record'].get('artifact_hashes', []):
        h = art['sha256'] if isinstance(art, dict) else art
        known_hashes.add(h)

print(f"Static registry contains {len(known_hashes)} artifact hashes")
print()

verified_groups = [g for g in scan['groups'] if g['status'] == 'verified']
mismatched = []
for g in verified_groups:
    for art in g.get('artifacts', []):
        if art['sha256'] not in known_hashes:
            artifact_label = (
                art.get('filename')
                or art.get('artifact_kind')
                or '(artifact)'
            )
            mismatched.append((g['group_id'], artifact_label, art['sha256']))

if mismatched:
    print(f"WARNING: {len(mismatched)} verified-group artifact(s) have hashes")
    print("NOT in the static registry. The CLI is asserting verification of")
    print("a hash the static registry does not contain.")
    for group_id, label, sha in mismatched[:5]:
        print(f"  - {group_id} / {label}  ({sha})")
else:
    n = sum(len(g.get('artifacts', [])) for g in verified_groups)
    print(f"OK: all {n} artifact hashes in {len(verified_groups)} verified")
    print(f"groups are present in the static signed registry.")
EOF
```

For Ollama groups, also confirm that the verification provenance
fields (`digest_verified`, `digest_source`) match the trust posture
the user asked for. In default mode every Ollama artifact should have
`digest_verified: true` and `digest_source: "content_hash"`. In
`--trust-ollama-filenames` mode they have `digest_verified: false`
and `digest_source: "ollama_blob_filename"`.

If every verified hash is present in the static signed registry, the
provenance fields match the requested trust posture, and the static
signed registry verifies under the public JWKS (per §2-§4), the chain
is end-to-end intact: from local file → content hash → registry
record → cryptographic signature → published public key.

These examples are for the v0.3.x JSON schema. If a command fails
after a version update, run `trustfall scan --json` and inspect the
top-level keys before assuming the registry verification failed —
schema drift between minor versions is a documentation-update issue,
not a cryptographic one. See `CHANGELOG.md` for any schema changes
between versions.

---

## What this does not verify

This document covers verification of the cryptographic claims
Trustfall Lite makes. It does not address:

- whether the model artifact is safe to use,
- whether the model artifact behaves as documented,
- whether the running model in any process is the same model whose
  hash matches the registry,
- whether the upstream publisher endorses the registry enrollment.

Those are out of scope by design. See `LIMITATIONS.md` for the full
list of non-claims.

---

## Reporting verification failures

If any command in this document produces output other than what is
documented, that is a bug and should be reported.

- Repository: `github.com/fallrisk-ai/trustfall-lite`
- Email: `anthony@fallrisk.ai`

Please include:

- the command that failed,
- the output you received,
- the expected output per this document,
- the version of Trustfall Lite (`trustfall version`),
- whether the JWKS thumbprint matches the published value.

A failure of any command in this document is a higher-priority report
than a failure in any other surface, because it affects the
verifiability of every other claim.
