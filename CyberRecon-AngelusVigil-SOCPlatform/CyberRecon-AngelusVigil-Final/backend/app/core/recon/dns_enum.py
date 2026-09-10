"""
CyberRecon engine for authorized asset discovery.

The engine intentionally limits activity to DNS lookups, bounded TCP
connect checks, and lightweight HTTP metadata collection. It does not
exploit services or attempt authentication bypasses.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import httpx


DEFAULT_SUBDOMAINS = (
    "www", "api", "app", "admin", "portal", "dev", "staging", "test",
    "mail", "smtp", "imap", "vpn", "cdn", "static", "assets", "docs",
    "blog", "shop", "support", "status", "auth", "login", "m", "mobile",
)

DEFAULT_PORTS = (
    21, 22, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587,
    631, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432,
    5601, 5672, 5900, 5985, 6379, 6443, 7001, 8000, 8008, 8080, 8081,
    8443, 8888, 9000, 9200, 9300, 11211, 27017,
)

DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA")


@dataclass(slots=True)
class DNSResult:
    domain: str
    addresses: list[str]
    aliases: list[str]
    records: dict[str, list[str]]
    reverse_dns: dict[str, str | None]


@dataclass(slots=True)
class SubdomainResult:
    subdomain: str
    addresses: list[str]
    status: str


@dataclass(slots=True)
class PortResult:
    ip: str
    port: int
    state: str
    service: str
    version: str | None


@dataclass(slots=True)
class HTTPResult:
    url: str
    final_url: str | None
    status_code: int | None
    server: str | None
    content_type: str | None
    title: str | None
    technologies: list[str]
    error: str | None


def normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or ""
    if not value or len(value) > 253:
        raise ValueError("Enter a valid domain, hostname or IP address.")
    if any(ch.isspace() for ch in value) or "/" in value:
        raise ValueError("Target contains invalid hostname characters.")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if ":" in value:
        raise ValueError("Enter a valid hostname or IP address.")
    return value

def _dns_resolve(domain: str, record_type: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=2.5)
        return [str(answer).rstrip(".") for answer in answers]
    except Exception:
        return []


def resolve_domain(domain: str) -> dict[str, Any]:
    domain = normalize_domain(domain)
    try:
        ipaddress.ip_address(domain)
        try:
            reverse = socket.gethostbyaddr(domain)[0]
        except (socket.herror, socket.gaierror):
            reverse = None
        return asdict(DNSResult(domain=domain, addresses=[domain], aliases=[], records={t: [] for t in DNS_RECORD_TYPES}, reverse_dns={domain: reverse}))
    except ValueError:
        pass
    addresses: set[str] = set()
    aliases: list[str] = []
    try:
        host, alias_list, ip_list = socket.gethostbyname_ex(domain)
        aliases = sorted(set(alias_list))
        addresses.update(ip_list)
        if host and host != domain:
            aliases.append(host)
    except socket.gaierror:
        pass

    records: dict[str, list[str]] = {}
    for record_type in DNS_RECORD_TYPES:
        values = _dns_resolve(domain, record_type)
        records[record_type] = values
        if record_type in {"A", "AAAA"}:
            addresses.update(values)

    reverse_dns: dict[str, str | None] = {}
    for ip in sorted(addresses):
        try:
            reverse_dns[ip] = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            reverse_dns[ip] = None

    return asdict(DNSResult(
        domain=domain,
        addresses=sorted(addresses),
        aliases=sorted(set(aliases)),
        records=records,
        reverse_dns=reverse_dns,
    ))


def enumerate_subdomains(
    domain: str,
    candidates: tuple[str, ...] = DEFAULT_SUBDOMAINS,
) -> list[dict[str, Any]]:
    domain = normalize_domain(domain)
    results: list[SubdomainResult] = []

    def check(label: str) -> SubdomainResult:
        fqdn = f"{label}.{domain}"
        addresses: set[str] = set()
        try:
            _, _, ips = socket.gethostbyname_ex(fqdn)
            addresses.update(ips)
        except socket.gaierror:
            pass
        for record_type in ("A", "AAAA"):
            addresses.update(_dns_resolve(fqdn, record_type))
        return SubdomainResult(fqdn, sorted(addresses), "live" if addresses else "dead")

    max_workers = min(12, max(1, len(candidates)))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        results.extend(pool.map(check, candidates))
    return [asdict(item) for item in sorted(results, key=lambda x: x.subdomain)]

def _service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return {
            80: "http", 443: "https", 8080: "http-proxy", 8443: "https-alt",
            3306: "mysql", 5432: "postgresql", 6379: "redis", 27017: "mongodb",
        }.get(port, "unknown")


def _scan_port(ip: str, port: int, timeout: float) -> PortResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        state = "open" if sock.connect_ex((ip, port)) == 0 else "closed"
        version = None
        if state == "open":
            try:
                if port in (80, 8080, 8000, 8008, 8888, 9000):
                    sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n")
                banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
                if banner:
                    version = banner.splitlines()[0][:160]
            except OSError:
                pass
    finally:
        sock.close()
    return PortResult(ip=ip, port=port, state=state, service=_service_name(port), version=version)

def scan_ports(
    addresses: list[str],
    ports: tuple[int, ...] = DEFAULT_PORTS,
    timeout: float = 0.5,
) -> list[dict[str, Any]]:
    clean_ports = tuple(sorted({p for p in ports if 1 <= p <= 65535}))
    if len(clean_ports) > 100:
        raise ValueError("Port scan is limited to 100 ports per assessment.")
    results: list[PortResult] = []
    jobs = [(ip, port) for ip in addresses if ":" not in ip for port in clean_ports]
    max_workers = min(32, max(1, len(jobs)))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_scan_port, ip, port, timeout) for ip, port in jobs]
        for future in futures:
            item = future.result()
            if item.state == "open":
                results.append(item)
    return [asdict(item) for item in results]


async def probe_http(target: str, addresses: list[str]) -> list[dict[str, Any]]:
    urls: list[str] = []
    host = normalize_domain(target)
    for scheme, port in (("https", 443), ("http", 80), ("http", 8080), ("https", 8443)):
        urls.append(f"{scheme}://{host}" if port in (80, 443) else f"{scheme}://{host}:{port}")

    headers = {
        "User-Agent": "CyberRecon/1.0 (authorized security assessment)",
        "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
    }

    async def one(url: str) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=5.0,
                verify=False,
                headers=headers,
            ) as client:
                response = await client.get(url)
            text = response.text[:200_000]
            title = None
            lower = text.lower()
            start = lower.find("<title")
            if start >= 0:
                start = lower.find(">", start)
                end = lower.find("</title>", start)
                if start >= 0 and end > start:
                    title = text[start + 1:end].strip()[:200]
            tech: list[str] = []
            server = response.headers.get("server")
            powered = response.headers.get("x-powered-by")
            if server:
                tech.append(server)
            if powered:
                tech.append(powered)
            for header, name in (
                ("x-generator", "generator"),
                ("x-aspnet-version", "ASP.NET"),
            ):
                if response.headers.get(header):
                    tech.append(f"{name}: {response.headers[header]}")
            return asdict(HTTPResult(
                url=url,
                final_url=str(response.url),
                status_code=response.status_code,
                server=server,
                content_type=response.headers.get("content-type"),
                title=title,
                technologies=sorted(set(tech)),
                error=None,
            ))
        except Exception as exc:
            return asdict(HTTPResult(
                url=url, final_url=None, status_code=None, server=None,
                content_type=None, title=None, technologies=[],
                error=str(exc)[:300],
            ))

    return await asyncio.gather(*(one(url) for url in urls))


async def run_full_scan(
    target: str,
    *,
    include_subdomains: bool = True,
    include_ports: bool = True,
    include_http: bool = True,
    ports: tuple[int, ...] = DEFAULT_PORTS,
) -> dict[str, Any]:
    started = time.perf_counter()
    domain = normalize_domain(target)
    dns = await asyncio.to_thread(resolve_domain, domain)
    is_ip = False
    try:
        ipaddress.ip_address(domain); is_ip = True
    except ValueError:
        pass

    subdomains: list[dict[str, Any]] = []
    if include_subdomains and not is_ip:
        subdomains = await asyncio.to_thread(enumerate_subdomains, domain)

    port_results: list[dict[str, Any]] = []
    if include_ports and dns["addresses"]:
        port_results = await asyncio.to_thread(scan_ports, dns["addresses"], ports)

    http_results: list[dict[str, Any]] = []
    if include_http:
        http_results = await probe_http(domain, dns["addresses"])

    open_ports = sorted({item["port"] for item in port_results})
    from app.core.recon.vuln import assess_target
    vulnerabilities = await assess_target(domain, http_results)
    dns_alerts: list[dict[str, str]] = []
    records = dns.get("records", {})
    txt = " ".join(records.get("TXT", [] )).lower()
    if records.get("MX") and "v=spf1" not in txt:
        dns_alerts.append({"severity": "MEDIUM", "name": "Missing/unclear SPF", "evidence": "MX exists but no SPF TXT record was observed."})
    if records.get("MX") and not any("_dmarc" in k.lower() for k in records):
        dns_alerts.append({"severity": "LOW", "name": "DMARC not confirmed", "evidence": "DMARC record was not part of the basic DNS check."})
    return {
        "target": domain,
        "dns": dns,
        "dns_alerts": dns_alerts,
        "subdomains": subdomains,
        "ports": port_results,
        "http": http_results,
        "vulnerabilities": vulnerabilities,
        "summary": {
            "ip_count": len(dns["addresses"]),
            "subdomain_count": sum(1 for x in subdomains if x.get("status") == "live"),
            "dead_subdomain_count": sum(1 for x in subdomains if x.get("status") == "dead"),
            "open_port_count": len(port_results),
            "open_ports": open_ports,
            "http_endpoint_count": sum(1 for item in http_results if item["status_code"] is not None),
            "duration_ms": round((time.perf_counter() - started) * 1000),
        },
    }
