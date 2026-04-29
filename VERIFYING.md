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

Trustfall Lite's claims reduce to five cryptographic statements:

1. **The signing key is the one Fall Risk published.** The JWKS at
   `attest.fallrisk.ai/.well-known/jwks.json` contains the public key
   under kid `fallrisk-96cd5e6a01e1`.

2. **The signed registry was signed by that key.** Both the per-record
   JWS signatures and the manifest JWS in `registry.json` verify
   against the JWKS.

3. **The registry record set matches the signed manifest.** The
   manifest digest commits to the canonical JSON of all decoded
   record payloads. Per-record JWS signatures verify the individual
   signed records. A modification to any field changes the digest or
   breaks the per-record signature.

4. **A specific artifact's hash is in the signed registry.** If
   Trustfall Lite says a hash is `verified`, that hash appears in a
   signed record under a stated model identifier.

5. **The verification API is a faithful propagation of the static
   authority.** The API at `api.attest.fallrisk.ai/v1/` does not
   recompute or re-derive any signed value. Signed registry fields it
   returns — including `registry_manifest_digest`, `record_jws`, and
   `manifest_signature` — are propagated verbatim from the loaded
   static registry. The API may add transport metadata such as
   `registry_snapshot_at`, but it does not redefine registry identity.
   Drift between the API and the static registry on any signed value
   is a verification failure for the system.

Everything else is downstream of these five. If they hold, the
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

For an additional cryptographic check that does not require fetching
the static registry, query `/v1/registry/manifest_digest` and verify
the returned JWS-signed `manifest_signature` against the published
JWKS (§6.5). This is the most direct way to confirm the API is
serving a registry snapshot signed by the canonical issuer.

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
documented key rotation, the document is wrong, the JWKS has changed,
or the key has been rotated. All three are situations a skeptical
verifier should care about.

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

If the embedded JWKS does not match the published JWKS, the registry
and the public trust anchor disagree. Do not proceed until the key-set
mismatch is resolved. Always verify per-record signatures against the
published JWKS, not merely against the embedded JWKS. The mismatch may
indicate a partial key rotation, a stale embedded copy, or a registry
served by a non-canonical issuer; in any of those cases the publicly-
verifiable trust path is what determines whether records are trusted.

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
    print("Signature INVALID — record does not verify under the published key")
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
it. If those two ever disagree, the registry's stored record has been
modified after signing and the registry should be treated as
unverified for that record.

---

## 4. Verify the manifest digest commits to the record set

The `manifest_digest` commits to the canonical JSON of all decoded
record payloads. Per-record JWS signatures remain the authoritative
signatures for individual records — the manifest digest does not
include the signatures themselves, only the record dicts they sign.

**Doctrine note.** A verifier recomputes the manifest digest from the
records as a cross-check that the registry's record set matches the
signed manifest. The Fall Risk verification API does **not** recompute
this digest at request time. The API propagates
`registry.manifest.manifest_digest` verbatim from the static signed
registry. This is intentional: the canonical source of truth for the
manifest digest is the value the issuer signed inside
`manifest_signature`. Recomputation is a verifier-side cross-check, not
a server-side authority. The static registry's signed manifest is the
authority; the API is a propagation/lookup layer; the verifier
recomputes locally to confirm the chain.

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
registry. It exposes five endpoints under
`https://api.attest.fallrisk.ai/v1/`:

```text
GET  /v1/verify/hash/{sha256}       — single-hash lookup
POST /v1/verify/manifest            — batch lookup (max 1000 hashes)
GET  /v1/health                     — liveness probe
GET  /v1/registry/status            — registry snapshot metadata
GET  /v1/registry/manifest_digest   — registry manifest identity + signature
```

The API is a propagation/lookup layer over the static signed registry.
**It does not recompute or re-derive any signed value.** Signed
registry fields returned by the API, including
`registry_manifest_digest`, `record_jws`, and `manifest_signature`,
are propagated verbatim from the loaded static registry at
`https://attest.fallrisk.ai/registry.json`. The API may add transport
metadata such as `registry_snapshot_at` (the timestamp when this API
instance loaded the registry), but it does not redefine registry
identity. The API exists for batch-lookup ergonomics and does not
substitute for the static registry's authority.

Verifying the API therefore reduces to two questions:

1. Is the API serving the same registry snapshot as the static
   registry? (Compare `registry_manifest_digest` byte-for-byte against
   `manifest.manifest_digest` in the static registry.)
2. Are the per-record signatures the API returns identical to those in
   the static registry? (Compare `record_jws` byte-for-byte against
   the local `signature` field.)

If both hold, the API is a faithful propagation of the static
authority. If either fails, treat the static registry as
authoritative and do not rely on the API for that snapshot.

At the time of writing (April 29, 2026), the canonical manifest
digest was:

```
251d5b648ee7533c6e0064308c1491403b561619759485ed4f0f32d6c2870cd3
```

This is shown as an illustration. The authoritative current value is
whatever `manifest.manifest_digest` says inside the live signed
registry at `https://attest.fallrisk.ai/registry.json`; the
verification commands below compute or fetch it directly. If the value
in this document falls behind a registry update, the registry is
authoritative.

The format is locked: 64-character lowercase raw hex, no `sha256:`
prefix. The API's `registry_manifest_digest` field returns the same
format, and the new `/v1/registry/manifest_digest` endpoint exposes
the same value along with the JWS-signed `manifest_signature` so
clients can independently verify the digest against the published JWKS
without relying on any other API surface.

The request body shape for `/v1/verify/manifest` is:

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
  "registry_manifest_digest": "251d5b648ee7533c6e0064308c1491403b561619759485ed4f0f32d6c2870cd3"
}
```

(The digest shown above is the value at the time of writing. Live
responses return whatever `manifest.manifest_digest` is in the
currently-loaded registry snapshot.)

The `registry_manifest_digest` is the canonical raw-hex value from
`registry.manifest.manifest_digest` at the static authority. It is
propagated verbatim across every API response — there is no
recomputation step in the API. Format is locked: 64 lowercase hex
characters, no `sha256:` prefix.

The `registry_manifest_digest` field is the
`manifest.manifest_digest` value from the registry snapshot the API
used for the lookup. A verifier comparing the API's response to a
local static registry should compare digests, not just timestamps —
digest equality proves the two snapshots commit to the same canonical
record set. (The same record set may be represented by JSON files that
differ in whitespace, key ordering, or other surfaces the digest does
not commit to; digest equality binds the records, not the file bytes.)

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

## 6.5. Verify the manifest digest endpoint independently

The `/v1/registry/manifest_digest` endpoint returns the registry's
manifest digest along with the JWS-signed `manifest_signature` that
proves the issuer attested to that digest. This is the single most
direct path to verify the API is serving an authentic registry without
fetching the registry itself.

```bash
curl -sSL https://api.attest.fallrisk.ai/v1/registry/manifest_digest \
    -o digest_response.json

python3 -m json.tool digest_response.json
```

Expected response (the `manifest_digest` value below is the value at
the time of writing; live responses return whatever
`manifest.manifest_digest` is in the currently-loaded registry):

```json
{
  "manifest_digest": "251d5b648ee7533c6e0064308c1491403b561619759485ed4f0f32d6c2870cd3",
  "manifest_signature": "eyJhbGciOiJSUzI1NiIs...",
  "registry_kid": "fallrisk-96cd5e6a01e1",
  "registry_snapshot_at": "2026-04-29T..."
}
```

Verify the JWS signature against the published JWKS and confirm the
signed payload contains the same digest the API returned:

```bash
python3 << 'EOF'
import json
import jwt
from jwt.algorithms import RSAAlgorithm
import urllib.request

# Load the API response
resp = json.load(open('digest_response.json'))
api_digest = resp['manifest_digest']
manifest_signature = resp['manifest_signature']
api_kid = resp['registry_kid']

# Fetch the published JWKS (or use the one from §1)
with urllib.request.urlopen(
    'https://attest.fallrisk.ai/.well-known/jwks.json'
) as f:
    jwks = json.load(f)

# Find the matching public key
jwk_data = next(
    k for k in jwks['keys']
    if k.get('kid') == api_kid
)
public_key = RSAAlgorithm.from_jwk(json.dumps(jwk_data))

# Verify the JWS signature
try:
    payload = jwt.decode(
        manifest_signature,
        public_key,
        algorithms=['RS256'],
        options={'verify_aud': False, 'verify_iss': False, 'verify_exp': False},
    )
    print("Manifest signature VERIFIED")
except jwt.InvalidSignatureError:
    print("Manifest signature INVALID — do not trust this API instance")
    raise SystemExit(1)

# The signed payload should contain a manifest_digest field that
# matches what the API claimed. This is the anti-tampering check.
signed_digest = payload.get('manifest_digest', '')
# Defensive: strip a "sha256:" prefix if the signer ever emits one;
# the API normalizes to raw hex so we compare like-for-like.
signed_digest = signed_digest.removeprefix('sha256:')

print(f"API claim:    {api_digest}")
print(f"Signed value: {signed_digest}")

if api_digest == signed_digest:
    print("Digest in JWS payload matches API claim — chain intact")
else:
    print("MISMATCH: API is reporting a digest the issuer did not sign")
    print("This is a P0 verification failure; do not trust this API instance")
    raise SystemExit(1)
EOF
```

If both the JWS verifies and the signed payload's `manifest_digest`
matches the API's claim, the API is provably serving a registry
snapshot whose manifest digest was signed by the canonical issuer. No
other API endpoint or verification step is needed to establish the
manifest digest's authenticity.

This is the test class that catches the manifest-digest drift bug
class (where an API recomputes a digest the issuer never signed). If
the API's `manifest_digest` differs from the digest inside the verified
JWS payload, the API is reporting an unsigned value — verification
fails closed.

The full set of digest sources that must agree byte-for-byte:

```text
1. Static registry → manifest.manifest_digest
2. /v1/registry/manifest_digest → manifest_digest
3. /v1/registry/status → registry_manifest_digest
4. /v1/verify/hash/{sha256} → registry_manifest_digest
5. /v1/verify/manifest → registry_manifest_digest
6. JWS payload of manifest_signature → manifest_digest (after stripping any sha256: prefix)
```

A discrepancy between any two of these is a verification failure for
the system as a whole. Report immediately to `security@fallrisk.ai`.

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

## Verification failure categories

A failure of any verification step in this document falls into one of
the following categories. The category determines the impact and the
appropriate response.

| Category | Meaning | Response |
|---|---|---|
| JWKS mismatch | Embedded JWKS in registry differs from published JWKS, or bundled JWKS in Trustfall Lite differs from published JWKS | Do not proceed. The registry's key set and the public trust anchor disagree. Verify per-record signatures against the published JWKS, not the embedded JWKS, before drawing any conclusion. Report to `security@fallrisk.ai`. |
| Issuer fingerprint mismatch | Computed RFC 7638 thumbprint does not match the documented value | Do not proceed. The key has rotated, the JWKS has changed, or the documentation is stale. Report. |
| Manifest signature verification failure | `manifest_signature` does not verify under the published JWKS | Do not proceed. Treat the registry as untrusted. Report. |
| Per-record JWS verification failure | A specific `signature` field does not verify under the published JWKS | The affected record is untrusted. Other records in the registry are unaffected. Report. |
| Manifest digest mismatch | Recomputed manifest digest does not match the value stored in the manifest | Do not proceed. The registry's record set has been modified after signing. Report. |
| API/static registry mismatch | API's `registry_manifest_digest` differs from static registry's `manifest.manifest_digest` | If both digests verify under the JWKS, this is a registry rollout in progress; the static registry is authoritative. If only one digest verifies, treat the unverified side as untrusted. |
| Local artifact not enrolled | A scanned hash does not appear in any signed registry record | Not a verification failure. The artifact is not in the signed registry; this is a reportable scan outcome, not a security event. |

Use neutral language when reporting:

- "verification failed" — a documented check did not produce the expected result
- "do not proceed" — do not treat the unverified surface as authoritative
- "report to `security@fallrisk.ai`" — escalate the finding

Avoid attribution language ("tampered," "compromised," "malicious,"
"fake") unless the evidence directly supports it. A failed verification
is a verification failure first. Attribution requires additional
investigation.

---

## Reporting verification failures

If any command in this document produces output other than what is
documented, that is a bug and should be reported.

- Repository: `github.com/fallrisk-ai/trustfall-lite`
- Email: `security@fallrisk.ai` (canonical for verification-chain failures)
- Fallback: `anthony@fallrisk.ai`

Please include:

- the command that failed,
- the output you received,
- the expected output per this document,
- the version of Trustfall Lite (`trustfall version`),
- whether the JWKS thumbprint matches the published value.

A failure of any command in this document is a higher-priority report
than a failure in any other surface, because it affects the
verifiability of every other claim.
