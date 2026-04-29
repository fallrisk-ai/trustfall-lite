"""
API client for the Fall Risk verification API.

Wraps two endpoints:
  GET  /v1/verify/hash/{sha256}   — single hash lookup
  POST /v1/verify/manifest         — batch hash lookup (max 1000 hashes)

The deployed base URL is `https://api.attest.fallrisk.ai/v1/`. Note
that this differs from the original spec text (which said
`/api/v1/`) — the production deployment dropped the `/api` prefix.
The CLI follows the deployed URL.

Per the spec normative trust rule: this client treats `record_jws`
as authoritative. Every `verified` result is JWS-verified against
the local JWKS before being reported as verified. A signature
mismatch is treated as `not_enrolled` plus a warning, not as a soft
"trust me" pass.

The decoded `record` field returned by the API is convenience data
only and is not used to populate any user-facing field that affects
trust decisions. We re-decode the JWS payload locally and use that
as the source of truth for model_id, publisher, license, etc.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import httpx
from jose import jws as jose_jws
from jose.exceptions import JOSEError


DEFAULT_BASE_URL = "https://api.attest.fallrisk.ai/v1"
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_USER_AGENT = "trustfall-lite/0.2.0"

# Per spec §6.2: max 1000 hashes per batch
MAX_BATCH_SIZE = 1000

# Retry policy for 429 / 503
MAX_RETRIES = 3
INITIAL_BACKOFF_SECONDS = 1.0


# ════════════════════════════════════════════════════════════════════
# Result objects
# ════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class VerifiedRecord:
    """
    A successfully-verified registry record.

    The `claims` dict is populated from the locally-verified JWS
    payload — NOT from the convenience `record` field returned by
    the API. This is the spec's normative trust rule.
    """

    sha256: str
    record_jws: str
    claims: dict[str, Any]
    registry_kid: str | None = None
    registry_snapshot_at: str | None = None


@dataclass(frozen=True)
class APILookupResult:
    """
    Per-hash result from an API call. Three normative status values:

      - `verified`    : record_jws verified against JWKS, claims populated
      - `not_enrolled`: hash not in registry
      - `error`       : API or signature failure; not authoritative either way
    """

    sha256: str
    status: str  # "verified" | "not_enrolled" | "error"
    record: VerifiedRecord | None = None
    error_message: str | None = None


# ════════════════════════════════════════════════════════════════════
# Exceptions
# ════════════════════════════════════════════════════════════════════


class APIError(Exception):
    """Base class for unrecoverable API client errors."""


class APIUnreachableError(APIError):
    """Network failure or 5xx error after retries exhausted."""


class APIBadResponseError(APIError):
    """API returned a malformed response body."""


# ════════════════════════════════════════════════════════════════════
# Client
# ════════════════════════════════════════════════════════════════════


class TrustfallAPI:
    """
    Synchronous client for the Trustfall verification API.

    Constructed with a JWKS (the local pinned key set) used to verify
    every signed record. The client never trusts the API's decoded
    `record` field as authoritative — only locally-verified JWS
    payloads populate user-facing claims.
    """

    def __init__(
        self,
        jwks: dict[str, Any],
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        user_agent: str = DEFAULT_USER_AGENT,
        client: httpx.Client | None = None,
    ) -> None:
        self._jwks = jwks
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._user_agent = user_agent
        # Allow caller to inject an httpx.Client (used by tests with respx).
        self._client = client or httpx.Client(
            timeout=timeout,
            headers={"User-Agent": user_agent},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "TrustfallAPI":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ── Endpoint: GET /v1/verify/hash/{sha256} ───────────────────

    def verify_hash(self, sha256: str) -> APILookupResult:
        """Single-hash lookup. Returns APILookupResult."""
        if not _is_valid_hex_sha256(sha256):
            return APILookupResult(
                sha256=sha256,
                status="error",
                error_message="malformed hash (must be lowercase 64-char hex)",
            )

        url = f"{self._base_url}/verify/hash/{sha256}"
        response = self._request_with_retry("GET", url)

        if response is None:
            return APILookupResult(
                sha256=sha256,
                status="error",
                error_message="API unreachable after retries",
            )

        if response.status_code == 404:
            return APILookupResult(sha256=sha256, status="not_enrolled")

        if response.status_code != 200:
            return APILookupResult(
                sha256=sha256,
                status="error",
                error_message=f"unexpected HTTP {response.status_code}",
            )

        try:
            body = response.json()
        except (json.JSONDecodeError, ValueError):
            return APILookupResult(
                sha256=sha256,
                status="error",
                error_message="API returned malformed JSON",
            )

        return self._build_verified_result(sha256, body)

    # ── Endpoint: POST /v1/verify/manifest ───────────────────────

    def verify_manifest(
        self,
        sha256s: list[str],
        path_hints: dict[str, str] | None = None,
        size_bytes: dict[str, int] | None = None,
    ) -> list[APILookupResult]:
        """
        Batch lookup. Splits inputs into chunks of MAX_BATCH_SIZE if needed.

        Args:
            sha256s: list of lowercase hex digests to look up
            path_hints: optional, only sent when --include-paths was set
            size_bytes: optional diagnostic correlation

        Returns one APILookupResult per input hash, in input order.
        """
        if not sha256s:
            return []

        path_hints = path_hints or {}
        size_bytes = size_bytes or {}

        results: list[APILookupResult] = []
        for chunk in _chunked(sha256s, MAX_BATCH_SIZE):
            results.extend(
                self._verify_manifest_chunk(chunk, path_hints, size_bytes)
            )
        return results

    def _verify_manifest_chunk(
        self,
        sha256s: list[str],
        path_hints: dict[str, str],
        size_bytes: dict[str, int],
    ) -> list[APILookupResult]:
        """Send one batch request; map response back to per-hash results."""
        # Validate all hashes upfront
        invalid = [h for h in sha256s if not _is_valid_hex_sha256(h)]
        if invalid:
            return [
                APILookupResult(
                    sha256=h,
                    status="error",
                    error_message="malformed hash (must be lowercase 64-char hex)"
                    if h in invalid else "",
                )
                if h in invalid else APILookupResult(sha256=h, status="error",
                                                    error_message="batch contained malformed hash")
                for h in sha256s
            ]

        body: dict[str, Any] = {
            "hashes": [
                _build_hash_entry(h, path_hints.get(h), size_bytes.get(h))
                for h in sha256s
            ],
            "client": {"name": "trustfall-lite", "version": _client_version()},
        }

        url = f"{self._base_url}/verify/manifest"
        response = self._request_with_retry("POST", url, json=body)

        if response is None:
            return [
                APILookupResult(sha256=h, status="error",
                                error_message="API unreachable after retries")
                for h in sha256s
            ]

        if response.status_code == 503:
            return [
                APILookupResult(sha256=h, status="error",
                                error_message="registry temporarily unavailable")
                for h in sha256s
            ]

        if response.status_code != 200:
            return [
                APILookupResult(sha256=h, status="error",
                                error_message=f"unexpected HTTP {response.status_code}")
                for h in sha256s
            ]

        try:
            payload = response.json()
        except (json.JSONDecodeError, ValueError):
            return [
                APILookupResult(sha256=h, status="error",
                                error_message="API returned malformed JSON")
                for h in sha256s
            ]

        return self._build_batch_results(sha256s, payload)

    # ── Result builders ─────────────────────────────────────────

    def _build_verified_result(
        self, sha256: str, body: dict[str, Any]
    ) -> APILookupResult:
        """Build a VerifiedRecord from a 200 response on the single endpoint."""
        record_jws = body.get("record_jws")
        if not record_jws:
            return APILookupResult(
                sha256=sha256, status="error",
                error_message="API response missing record_jws",
            )

        claims = self._verify_jws(record_jws)
        if claims is None:
            return APILookupResult(
                sha256=sha256, status="error",
                error_message="JWS signature verification failed",
            )

        return APILookupResult(
            sha256=sha256,
            status="verified",
            record=VerifiedRecord(
                sha256=sha256,
                record_jws=record_jws,
                claims=claims,
                registry_kid=body.get("registry_kid"),
                registry_snapshot_at=body.get("registry_snapshot_at"),
            ),
        )

    def _build_batch_results(
        self, requested: list[str], payload: dict[str, Any]
    ) -> list[APILookupResult]:
        """Map batch response results back to a per-hash list in input order."""
        results_by_hash: dict[str, dict[str, Any]] = {}
        for entry in payload.get("results", []):
            h = entry.get("sha256")
            if h:
                results_by_hash[h] = entry

        kid = payload.get("registry_kid")
        snapshot_at = payload.get("registry_snapshot_at")

        out: list[APILookupResult] = []
        for h in requested:
            entry = results_by_hash.get(h)
            if entry is None:
                # API didn't return this hash at all
                out.append(APILookupResult(
                    sha256=h, status="error",
                    error_message="hash missing from API response",
                ))
                continue

            status = entry.get("status")
            if status == "not_enrolled":
                out.append(APILookupResult(sha256=h, status="not_enrolled"))
                continue

            if status == "verified":
                record_jws = entry.get("record_jws")
                if not record_jws:
                    out.append(APILookupResult(
                        sha256=h, status="error",
                        error_message="response missing record_jws",
                    ))
                    continue
                claims = self._verify_jws(record_jws)
                if claims is None:
                    out.append(APILookupResult(
                        sha256=h, status="error",
                        error_message="JWS signature verification failed",
                    ))
                    continue
                out.append(APILookupResult(
                    sha256=h,
                    status="verified",
                    record=VerifiedRecord(
                        sha256=h,
                        record_jws=record_jws,
                        claims=claims,
                        registry_kid=kid,
                        registry_snapshot_at=snapshot_at,
                    ),
                ))
                continue

            # Unknown status — treat as error
            out.append(APILookupResult(
                sha256=h, status="error",
                error_message=f"unknown status: {status!r}",
            ))

        return out

    # ── JWS verification ────────────────────────────────────────

    def _verify_jws(self, token: str) -> dict[str, Any] | None:
        """
        Verify a JWS against the local JWKS. Returns the decoded claims
        on success, None on any verification failure.

        This is the spec's normative trust rule — only successfully-
        verified payloads are treated as authoritative.
        """
        try:
            payload_bytes = jose_jws.verify(token, self._jwks, algorithms=["RS256"])
            return json.loads(payload_bytes)
        except (JOSEError, json.JSONDecodeError, ValueError):
            return None

    # ── HTTP transport ──────────────────────────────────────────

    def _request_with_retry(
        self,
        method: str,
        url: str,
        json: dict[str, Any] | None = None,
    ) -> httpx.Response | None:
        """
        Issue a request with exponential backoff on 429 and 503.

        Returns the response on success, or None if all retries exhausted.
        Honors Retry-After when present (per spec §6).
        """
        backoff = INITIAL_BACKOFF_SECONDS
        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self._client.request(method, url, json=json)
            except httpx.HTTPError:
                if attempt < MAX_RETRIES:
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                return None

            if response.status_code in (429, 503) and attempt < MAX_RETRIES:
                retry_after = response.headers.get("Retry-After")
                wait = backoff
                if retry_after:
                    try:
                        wait = max(wait, float(retry_after))
                    except ValueError:
                        pass
                time.sleep(wait)
                backoff *= 2
                continue

            return response

        return None


# ════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════


def _is_valid_hex_sha256(s: str) -> bool:
    if len(s) != 64:
        return False
    return all(c in "0123456789abcdef" for c in s)


def _chunked(items: list[str], size: int) -> list[list[str]]:
    return [items[i:i + size] for i in range(0, len(items), size)]


def _build_hash_entry(
    sha256: str,
    path_hint: str | None,
    size_bytes: int | None,
) -> dict[str, Any]:
    """Build one entry in the batch endpoint's `hashes` array."""
    entry: dict[str, Any] = {"sha256": sha256}
    if path_hint is not None:
        entry["path_hint"] = path_hint
    if size_bytes is not None:
        entry["size_bytes"] = size_bytes
    return entry


def _client_version() -> str:
    """Return the package version for the User-Agent and client.version fields."""
    from . import __version__
    return __version__
