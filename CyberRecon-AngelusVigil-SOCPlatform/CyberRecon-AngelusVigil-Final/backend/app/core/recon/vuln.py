"""Bounded web security misconfiguration checks for authorized assets."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin

import httpx

SENSITIVE_PATHS = ["/.env", "/.git/config", "/.git/HEAD", "/backup.zip", "/config.php.bak", "/database.sql"]
DIR_LISTING_PATHS = ["/uploads/", "/files/", "/backup/", "/static/"]


def _finding(name: str, description: str, asset: str, severity: str, evidence: str, recommendation: str, category: str = "MISCONFIGURATION") -> dict[str, Any]:
    return {"name": name, "description": description, "affected_asset": asset, "severity": severity, "evidence": evidence[:1200], "recommended_fix": recommendation, "status": "OPEN", "category": category}


def _tls_expiry(host: str, port: int = 443) -> tuple[datetime | None, str | None]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        expires = cert.get("notAfter")
        if not expires:
            return None, None
        return datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC), None
    except Exception as exc:
        return None, str(exc)[:220]


async def assess_target(domain: str, http_results: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    domain = domain.strip().lower().rstrip(".")
    urls = [r["url"] for r in (http_results or []) if r.get("status_code") is not None]
    if not urls:
        urls = [f"https://{domain}", f"http://{domain}"]

    findings: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=5, follow_redirects=False, verify=False, headers={"User-Agent": "CyberSentinel/1.0 security-assessment"}) as client:
        for url in urls[:4]:
            try:
                response = await client.get(url)
            except Exception:
                continue
            h = {k.lower(): v for k, v in response.headers.items()}
            asset = str(response.url)
            missing = [x for x in ["content-security-policy", "x-content-type-options", "referrer-policy", "permissions-policy"] if x not in h]
            if missing:
                findings.append(_finding("Missing security headers", "Recommended browser security controls are absent.", asset, "MEDIUM", ", ".join(missing), "Configure the missing response headers at the reverse proxy or application layer.", "SECURITY_HEADERS"))
            if url.startswith("http://") and response.status_code < 400 and not (300 <= response.status_code < 400 and response.headers.get("location", "").startswith("https://")):
                findings.append(_finding("HTTP not redirected to HTTPS", "The plaintext endpoint did not provide an HTTPS redirect.", asset, "MEDIUM", f"HTTP {response.status_code}; Location={response.headers.get('location', 'none')}", "Redirect all HTTP traffic to HTTPS and enable HSTS after validating the deployment.", "TRANSPORT"))
            if "set-cookie" in h:
                cookie_text = h["set-cookie"].lower()
                missing_attrs = [x for x in ["secure", "httponly", "samesite"] if x not in cookie_text]
                if missing_attrs:
                    findings.append(_finding("Insecure cookie attributes", "A response cookie is missing one or more recommended security attributes.", asset, "MEDIUM", f"Set-Cookie attributes missing: {', '.join(missing_attrs)}", "Add Secure, HttpOnly and an appropriate SameSite policy to session cookies.", "COOKIES"))

    # TLS expiry is evaluated independently so certificate errors are visible.
    expires, err = await asyncio.to_thread(_tls_expiry, domain, 443)
    if expires:
        days = (expires - datetime.now(UTC)).days
        if days < 0:
            findings.append(_finding("TLS certificate expired", "The certificate presented by the HTTPS service is expired.", f"https://{domain}:443", "CRITICAL", expires.isoformat(), "Renew and deploy a valid certificate before production traffic is accepted.", "TLS"))
        elif days <= 30:
            findings.append(_finding("TLS certificate expires soon", "The HTTPS certificate is within 30 days of expiry.", f"https://{domain}:443", "HIGH", f"Expires {expires.isoformat()} ({days} days)", "Renew the certificate and verify automated renewal/monitoring.", "TLS"))
    elif err:
        findings.append(_finding("TLS certificate inspection failed", "The HTTPS service could not be inspected for certificate expiry.", f"https://{domain}:443", "LOW", err, "Verify that the HTTPS endpoint is reachable and presents a valid certificate.", "TLS"))

    async with httpx.AsyncClient(timeout=4, follow_redirects=False, verify=False, headers={"User-Agent": "CyberSentinel/1.0 security-assessment"}) as client:
        for path in SENSITIVE_PATHS:
            try:
                r = await client.get(urljoin(f"https://{domain}", path))
                if r.status_code < 400 and len(r.content) > 0:
                    findings.append(_finding("Exposed sensitive file", "A commonly sensitive file path returned accessible content.", f"https://{domain}{path}", "HIGH", f"HTTP {r.status_code}; {len(r.content)} bytes", "Remove the file from the web root or deny access at the web server; rotate secrets if exposed.", "EXPOSURE"))
            except Exception:
                pass
        for path in DIR_LISTING_PATHS:
            try:
                r = await client.get(urljoin(f"https://{domain}", path))
                body = r.text.lower()[:12000]
                if r.status_code == 200 and ("index of /" in body or "directory listing" in body):
                    findings.append(_finding("Directory listing enabled", "The target appears to expose a directory index.", f"https://{domain}{path}", "MEDIUM", f"HTTP 200 with directory index indicators", "Disable autoindex/directory listing unless explicitly required.", "EXPOSURE"))
            except Exception:
                pass

    return findings
