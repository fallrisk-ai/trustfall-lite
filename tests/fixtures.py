"""
Test fixtures.

Two important fixtures are captured from the live Fall Risk
production registry as of April 8, 2026:

1. PROD_JWKS — the public key set published at
   https://attest.fallrisk.ai/.well-known/jwks.json

2. PROD_LLAMA_JWS — a real signed enrollment record for
   meta-llama/Llama-3.1-8B-Instruct, taken from the registry
   at https://attest.fallrisk.ai/registry.json

Embedding these as test fixtures means the JWS verification path
is tested against actual production output, not a self-signed
test key. This catches regressions in the signing pipeline early.

Both values are public artifacts, intentionally inspectable, and
appear unredacted in the live website source. Reproducing them
here is not a security concern.
"""

import copy
import json
from typing import Any


# Captured from https://attest.fallrisk.ai/.well-known/jwks.json
PROD_JWKS: dict[str, Any] = {
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "fallrisk-96cd5e6a01e1",
            "n": "oYwBUy1rtISAbJNZJ6p8QoFK678smQLaKl4s1SZ9gYl_-mfsi7JVsBGbuaUVgFKxVaaTzYXyZo4WxXLxDxOt8xICjSIqP62G8sw-Y5v6ZbtDO8MkHsQNYjRfbb5xV6hPFz4ramYyC4d61Pa_l3JrmEu-oluEHU9Op8qR-FT7-1Qvlnjpz5xuYpeE-EAkx2Bh2UcvBZH6cdpcr8KTCEjxba-B5JwQ3E3J4pje4Xe9HW6x3cGA0Zi9AT-pqMZcpq_7KZzNccfLlWoD6S7hXKacZrzIUnx5NcPMoy9lPSNwEwqp6nj2OH9C1zF6XnTYjjs9ZBIwVmp-lwu_6vqL0iWb7Q",
            "e": "AQAB",
        }
    ]
}


# Real signed enrollment record for meta-llama/Llama-3.1-8B-Instruct
# captured from the live registry on April 8, 2026.
PROD_LLAMA_JWS = (
    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZhbGxyaXNrLTk2Y2Q1ZTZhMDFlMSIsInR5cCI6"
    "ImZhbGxyaXNrLWVucm9sbG1lbnQrand0In0."
    "eyJtb2RlbF9pZCI6Im1ldGEtbGxhbWEvTGxhbWEtMy4xLThCLUluc3RydWN0Iiwi"
    "ZW5yb2xsbWVudF9pZCI6ImVucm9sbC0yMDQ2YzFiZmVhMjEiLCJlbnJvbGxtZW50"
    "X2RhdGUiOiIyMDI2LTA0LTA4VDAwOjA0OjQzWiIsImNvbnRyYWN0X3ZlcnNpb24i"
    "OiJpdHB1Zi12MC4xLjAiLCJhcmNoaXRlY3R1cmUiOiJ0cmFuc2Zvcm1lciIsIm5f"
    "bGF5ZXJzIjozMiwiZmluZ2VycHJpbnRfZGltcyI6NjQsIm5fc2VlZHMiOjQsInRy"
    "dXN0X21vZGUiOiJzdGFuZGFyZCIsImV2aWRlbmNlX2RpZ2VzdCI6InNoYTI1Njoy"
    "MDQ2YzFiZmVhMjE4MGQwZjA2Y2I2N2Y2OTJkMTU4YWEyNTFhZDk4MWI0NGJjYWEy"
    "NmM1NmVhZTFmNmI4NmI5Iiwic3RhdHVzIjoiYWN0aXZlIiwiaXNzdWVyIjoiaHR0"
    "cHM6Ly9hdHRlc3QuZmFsbHJpc2suYWkifQ."
    "GoOT50Akq6pmts2xQKxM-1j2m2iKwHTwQkS-2g-mNE9vDpJQP7M1z7j4DepY_E6d"
    "2VPqlgMoRyoUugQ_D4ro-d7KasVCc8_7al22a4hIivMdEDWIsAbm2tZN2bpf8wI4"
    "oNLI1-c9KFSjSle0ePgtM4BRPuEQgy8My83yY2YubMW7-69hWXXPO5pZQ61tBhei"
    "fJM4ztdZkc3emjVYzftWIU7B2mIdc4RHwA2mSRBMaGG-NPcgN1RshdbAmFrxYWEk"
    "YCxtfK__I98p25j_LwNj_UYQThvOmv5Xc6xoNqalVkSLOeIiZuVrzhyYcYuXOuAz"
    "4sZeYJ781GPf_z5dFAzcEw"
)


# Decoded payload of PROD_LLAMA_JWS, for assertion comparison
PROD_LLAMA_CLAIMS: dict[str, Any] = {
    "model_id": "meta-llama/Llama-3.1-8B-Instruct",
    "enrollment_id": "enroll-2046c1bfea21",
    "enrollment_date": "2026-04-08T00:04:43Z",
    "contract_version": "itpuf-v0.1.0",
    "architecture": "transformer",
    "n_layers": 32,
    "fingerprint_dims": 64,
    "n_seeds": 4,
    "trust_mode": "standard",
    "evidence_digest": "sha256:2046c1bfea2180d0f06cb67f692d158aa251ad981b44bcaa26c56eae1f6b86b9",
    "status": "active",
    "issuer": "https://attest.fallrisk.ai",
}


def jwks_copy() -> dict[str, Any]:
    """Return a fresh deep copy of PROD_JWKS for tests that mutate it."""
    return copy.deepcopy(PROD_JWKS)


def synthetic_hash(seed: str = "synth") -> str:
    """Deterministic pseudo-hash for tests that don't care about content."""
    import hashlib
    return hashlib.sha256(seed.encode()).hexdigest()
