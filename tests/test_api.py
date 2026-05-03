"""
Tests for the API client.

Two layers of testing:

1. Mock-based wire-format tests using respx. Cover:
   - request shape (URL, method, headers, body)
   - retry/backoff on 429, 503
   - response parsing for verified/not_enrolled/error status

2. JWS verification path tested against the captured production
   PROD_LLAMA_JWS, signed by the real production key. This proves
   the client's verification path matches what the real signing
   pipeline produces. Includes a tamper test that mutates the JWS
   and asserts verification FAILS — proves the client is actually
   verifying, not just decoding (per Decision 3 in the build plan).
"""

import json

import httpx
import pytest
import respx

from fallrisk_trustfall.api import (
    APILookupResult,
    DEFAULT_BASE_URL,
    MAX_BATCH_SIZE,
    TrustfallAPI,
    VerifiedRecord,
    _is_valid_hex_sha256,
)
from fallrisk_trustfall import __version__

from tests.fixtures import (
    PROD_JWKS,
    PROD_LLAMA_CLAIMS,
    PROD_LLAMA_JWS,
    jwks_copy,
    synthetic_hash,
)


# ════════════════════════════════════════════════════════════════════
# Hash validation
# ════════════════════════════════════════════════════════════════════


class TestHashValidation:
    def test_valid_lowercase_hex(self):
        assert _is_valid_hex_sha256("a" * 64)
        assert _is_valid_hex_sha256("0" * 64)
        assert _is_valid_hex_sha256(
            "b477be7572f0ab3ae3cbba38d508cc33e70600b2045669c4ad848051c3432094"
        )

    def test_rejects_uppercase(self):
        # Per spec §6.1: lowercase 64-char hex string
        assert not _is_valid_hex_sha256("A" * 64)

    def test_rejects_wrong_length(self):
        assert not _is_valid_hex_sha256("a" * 63)
        assert not _is_valid_hex_sha256("a" * 65)
        assert not _is_valid_hex_sha256("")

    def test_rejects_non_hex(self):
        assert not _is_valid_hex_sha256("z" * 64)
        assert not _is_valid_hex_sha256("g" * 64)


# ════════════════════════════════════════════════════════════════════
# JWS verification — the heart of the trust contract
# ════════════════════════════════════════════════════════════════════


class TestJWSVerificationAgainstProductionFixture:
    """
    Decision 3 implementation: prove the verification path works
    against a real production JWS, and prove that mutation breaks
    verification (so the client is actually verifying, not decoding).
    """

    def test_verifies_real_production_jws(self):
        """The captured production JWS verifies against the captured JWKS."""
        api = TrustfallAPI(jwks=PROD_JWKS, base_url=DEFAULT_BASE_URL)
        claims = api._verify_jws(PROD_LLAMA_JWS)

        assert claims is not None
        # Spot-check the claims match what we expect from the registry
        assert claims["model_id"] == "meta-llama/Llama-3.1-8B-Instruct"
        assert claims["enrollment_id"] == "enroll-2046c1bfea21"
        assert claims["issuer"] == "https://attest.fallrisk.ai"
        assert claims["contract_version"] == "itpuf-v0.1.0"
        # All expected fields present
        assert claims == PROD_LLAMA_CLAIMS

    def test_mutated_payload_fails_verification(self):
        """
        TAMPER TEST: a payload byte change must invalidate the signature.

        This is the proof that the client actually verifies the
        signature instead of just b64-decoding. Without this guarantee,
        a hostile API could return any payload and the client would
        treat it as authoritative.
        """
        # Mutate one base64 char in the payload section (middle of three parts)
        parts = PROD_LLAMA_JWS.split(".")
        assert len(parts) == 3
        header, payload, signature = parts

        # Flip one character in the payload — but keep it valid base64
        # so the JWS is still parseable (we want signature failure, not parse failure)
        payload_chars = list(payload)
        # Find a position that is not '_' or '-' to swap with another safe char
        for i, c in enumerate(payload_chars):
            if c.isalpha() and c.lower() != c.upper():
                payload_chars[i] = c.lower() if c.isupper() else c.upper()
                break
        mutated_payload = "".join(payload_chars)
        mutated_jws = f"{header}.{mutated_payload}.{signature}"

        # The mutated JWS should fail verification cleanly (return None)
        api = TrustfallAPI(jwks=PROD_JWKS, base_url=DEFAULT_BASE_URL)
        assert api._verify_jws(mutated_jws) is None

    def test_mutated_signature_fails_verification(self):
        """A signature byte change must invalidate the signature."""
        parts = PROD_LLAMA_JWS.split(".")
        header, payload, signature = parts

        # Flip one character in the signature
        sig_chars = list(signature)
        for i, c in enumerate(sig_chars):
            if c.isalpha():
                sig_chars[i] = c.lower() if c.isupper() else c.upper()
                break
        mutated_jws = f"{header}.{payload}.{''.join(sig_chars)}"

        api = TrustfallAPI(jwks=PROD_JWKS, base_url=DEFAULT_BASE_URL)
        assert api._verify_jws(mutated_jws) is None

    def test_wrong_jwks_fails_verification(self):
        """A JWKS with a different key must fail to verify."""
        # Swap the n parameter for an invalid one
        bad_jwks = jwks_copy()
        bad_jwks["keys"][0]["n"] = (
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        api = TrustfallAPI(jwks=bad_jwks, base_url=DEFAULT_BASE_URL)
        assert api._verify_jws(PROD_LLAMA_JWS) is None

    def test_garbage_input_fails_verification(self):
        """Random non-JWS strings must not verify."""
        api = TrustfallAPI(jwks=PROD_JWKS, base_url=DEFAULT_BASE_URL)
        assert api._verify_jws("") is None
        assert api._verify_jws("not.a.jws") is None
        assert api._verify_jws("eyJhbGciOiJSUzI1NiJ9.foo.bar") is None


# ════════════════════════════════════════════════════════════════════
# Single endpoint — GET /v1/verify/hash/{sha256}
# ════════════════════════════════════════════════════════════════════


@pytest.fixture
def api():
    """Fresh TrustfallAPI instance using PROD_JWKS for verification."""
    return TrustfallAPI(jwks=PROD_JWKS, base_url=DEFAULT_BASE_URL)


class TestVerifyHashEndpoint:
    @respx.mock
    def test_verified_response(self, api):
        """Successful single-hash lookup with a real verified JWS."""
        sha256 = "b477be7572f0ab3ae3cbba38d508cc33e70600b2045669c4ad848051c3432094"
        respx.get(f"{DEFAULT_BASE_URL}/verify/hash/{sha256}").mock(
            return_value=httpx.Response(200, json={
                "record_jws": PROD_LLAMA_JWS,
                "record": PROD_LLAMA_CLAIMS,
                "registry_kid": "fallrisk-96cd5e6a01e1",
                "registry_snapshot_at": "2026-04-26T22:45:45+00:00",
                "registry_manifest_digest": "sha256:5f159f7f6408e476",
            })
        )

        result = api.verify_hash(sha256)
        assert result.status == "verified"
        assert result.record is not None
        # Crucially: the claims come from the locally-verified JWS, not the convenience field
        assert result.record.claims["model_id"] == "meta-llama/Llama-3.1-8B-Instruct"
        assert result.record.registry_kid == "fallrisk-96cd5e6a01e1"

    @respx.mock
    def test_not_enrolled_404(self, api):
        sha256 = synthetic_hash("nonexistent")
        respx.get(f"{DEFAULT_BASE_URL}/verify/hash/{sha256}").mock(
            return_value=httpx.Response(404)
        )

        result = api.verify_hash(sha256)
        assert result.status == "not_enrolled"
        assert result.record is None

    def test_malformed_hash_rejected_locally(self, api):
        """The client validates the hash before sending; bad input never goes over the wire."""
        result = api.verify_hash("not-a-hash")
        assert result.status == "error"
        assert result.error_message and "malformed" in result.error_message.lower()

    @respx.mock
    def test_429_retries_then_succeeds(self, api):
        sha256 = "b477be7572f0ab3ae3cbba38d508cc33e70600b2045669c4ad848051c3432094"

        # Set up two 429s followed by a success
        route = respx.get(f"{DEFAULT_BASE_URL}/verify/hash/{sha256}")
        route.mock(side_effect=[
            httpx.Response(429, headers={"Retry-After": "0"}),
            httpx.Response(429, headers={"Retry-After": "0"}),
            httpx.Response(200, json={
                "record_jws": PROD_LLAMA_JWS,
                "record": PROD_LLAMA_CLAIMS,
            }),
        ])

        result = api.verify_hash(sha256)
        assert result.status == "verified"
        assert route.call_count == 3

    @respx.mock
    def test_signature_mismatch_returns_error(self, api):
        """If the API returns a JWS that doesn't verify, status is error, NOT verified."""
        sha256 = "b477be7572f0ab3ae3cbba38d508cc33e70600b2045669c4ad848051c3432094"
        # Mutate the signature on the production JWS
        mutated = PROD_LLAMA_JWS[:-3] + "AAA"
        respx.get(f"{DEFAULT_BASE_URL}/verify/hash/{sha256}").mock(
            return_value=httpx.Response(200, json={
                "record_jws": mutated,
                "record": PROD_LLAMA_CLAIMS,  # convenience copy is irrelevant
            })
        )

        result = api.verify_hash(sha256)
        # CRITICAL: a signature mismatch must NOT produce a "verified" result
        # even though the API returned a 200 with a (compromised) record.
        assert result.status == "error"
        assert result.error_message and "signature" in result.error_message.lower()


# ════════════════════════════════════════════════════════════════════
# Batch endpoint — POST /v1/verify/manifest
# ════════════════════════════════════════════════════════════════════


class TestVerifyManifestEndpoint:
    @respx.mock
    def test_batch_request_shape(self, api):
        """Verify the POST body shape matches spec §6.2."""
        sha256 = "b477be7572f0ab3ae3cbba38d508cc33e70600b2045669c4ad848051c3432094"

        captured: dict = {}

        def handler(request: httpx.Request):
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={
                "results": [{"sha256": sha256, "status": "verified",
                             "record_jws": PROD_LLAMA_JWS}],
                "registry_kid": "fallrisk-96cd5e6a01e1",
                "registry_snapshot_at": "2026-04-26T22:45:45+00:00",
            })

        respx.post(f"{DEFAULT_BASE_URL}/verify/manifest").mock(side_effect=handler)

        results = api.verify_manifest(
            [sha256],
            path_hints={sha256: "~/test/model.safetensors"},
            size_bytes={sha256: 12345},
        )

        # Spec §6.2 request shape
        body = captured["body"]
        assert "hashes" in body
        assert "client" in body
        assert body["client"] == {"name": "trustfall-lite", "version": __version__}
        assert len(body["hashes"]) == 1
        assert body["hashes"][0] == {
            "sha256": sha256,
            "path_hint": "~/test/model.safetensors",
            "size_bytes": 12345,
        }
        assert results[0].status == "verified"

    @respx.mock
    def test_batch_omits_path_hint_by_default(self, api):
        """No path_hints arg → no path_hint field in request."""
        sha256 = "b477be7572f0ab3ae3cbba38d508cc33e70600b2045669c4ad848051c3432094"
        captured: dict = {}

        def handler(request: httpx.Request):
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={
                "results": [{"sha256": sha256, "status": "verified",
                             "record_jws": PROD_LLAMA_JWS}],
            })

        respx.post(f"{DEFAULT_BASE_URL}/verify/manifest").mock(side_effect=handler)

        api.verify_manifest([sha256], size_bytes={sha256: 100})
        assert "path_hint" not in captured["body"]["hashes"][0]
        assert captured["body"]["hashes"][0]["size_bytes"] == 100

    @respx.mock
    def test_batch_mixed_results(self, api):
        """Per-hash status mapping in input order."""
        h1 = "a" * 64
        h2 = "b" * 64
        h3 = "c" * 64

        respx.post(f"{DEFAULT_BASE_URL}/verify/manifest").mock(
            return_value=httpx.Response(200, json={
                "results": [
                    {"sha256": h1, "status": "verified", "record_jws": PROD_LLAMA_JWS},
                    {"sha256": h2, "status": "not_enrolled"},
                    {"sha256": h3, "status": "not_enrolled"},
                ],
            })
        )

        results = api.verify_manifest([h1, h2, h3])
        assert len(results) == 3
        assert results[0].sha256 == h1 and results[0].status == "verified"
        assert results[1].sha256 == h2 and results[1].status == "not_enrolled"
        assert results[2].sha256 == h3 and results[2].status == "not_enrolled"

    @respx.mock
    def test_503_returns_error_for_all(self, api):
        """503 after retries means CLI must fall back to local; client returns errors."""
        h = "a" * 64
        respx.post(f"{DEFAULT_BASE_URL}/verify/manifest").mock(
            return_value=httpx.Response(503)
        )

        results = api.verify_manifest([h])
        assert len(results) == 1
        assert results[0].status == "error"

    def test_chunking_at_max_batch_size(self, api):
        """Inputs larger than MAX_BATCH_SIZE split into multiple requests."""
        from fallrisk_trustfall.api import _chunked
        batch = [f"{i:064x}" for i in range(MAX_BATCH_SIZE + 5)]
        chunks = _chunked(batch, MAX_BATCH_SIZE)
        assert len(chunks) == 2
        assert len(chunks[0]) == MAX_BATCH_SIZE
        assert len(chunks[1]) == 5

    def test_empty_input_returns_empty(self, api):
        assert api.verify_manifest([]) == []
