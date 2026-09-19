"""Valt Python SDK - minimal client for the Valt secret vault API."""

import os
import json
import socket
import ipaddress
import urllib.request
import urllib.error
import urllib.parse
from typing import Optional, List, Dict, Any


class ValtError(Exception):
    """Raised when the Valt API returns an error."""

    def __init__(self, status: int, message: str) -> None:
        self.status = status
        super().__init__(f"Valt API error {status}: {message}")


# Requests to private/loopback/link-local addresses are refused by default so
# the SDK is safe to embed in server-side code. Local development against a
# localhost deployment opts in explicitly.
_ALLOW_PRIVATE = lambda: os.environ.get("VALT_ALLOW_PRIVATE_NETWORKS", "").lower() in ("1", "true", "yes")


def _validate_target(url: str) -> None:
    """Validate scheme and resolved address bounds before any request is made."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(f"invalid target URL: {url!r}")
    if _ALLOW_PRIVATE():
        return
    try:
        addrinfos = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise ValueError(f"cannot resolve target host: {parsed.hostname!r}") from exc
    for info in addrinfos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise ValueError(
                f"refusing to connect to private address {ip} — set "
                "VALT_ALLOW_PRIVATE_NETWORKS=1 to target local/internal deployments"
            )


class ValtClient:
    """Client for the Valt secret vault API."""

    def __init__(
        self,
        base_url: str = "http://localhost:8080/api/v1",
        token: Optional[str] = None,
    ) -> None:
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("base_url must be an absolute http(s) URL")
        self.base_url = base_url.rstrip("/")
        self.token = token or os.environ.get("VALT_TOKEN", "")

    @staticmethod
    def _encode_path_segment(value: str) -> str:
        """Encode a single path segment so it cannot traverse or change the
        request target."""
        return urllib.parse.quote(value, safe="")

    def _request(self, method: str, path: str, body: Optional[Dict] = None) -> Any:
        """Make an authenticated HTTP request. Path params must be pre-encoded
        via _encode_path_segment."""
        url = self.base_url + path
        _validate_target(url)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            raise ValtError(exc.code, raw) from exc

    def list_secrets(self) -> List[Dict[str, Any]]:
        """List all secrets."""
        return self._request("GET", "/secrets").get("secrets", [])

    def request_access(
        self, secret_id: str, reason: str, duration_minutes: int = 30
    ) -> str:
        """Request access to a secret. Returns the request ID."""
        result = self._request(
            "POST",
            f"/secrets/{self._encode_path_segment(secret_id)}/access-requests",
            {"reason": reason, "duration_minutes": duration_minutes},
        )
        return result.get("id", "")

    def get_credential(self, request_id: str) -> Dict[str, Any]:
        """Fetch the credential for an approved request."""
        return self._request("GET", f"/credentials/{self._encode_path_segment(request_id)}")
