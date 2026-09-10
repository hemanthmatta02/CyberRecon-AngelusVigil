"""Pydantic schemas for CyberRecon."""

from pydantic import BaseModel, Field, field_validator


class ReconRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)
    include_subdomains: bool = True
    include_ports: bool = True
    include_http: bool = True
    ports: list[int] = Field(default_factory=list, max_length=100)

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, value: list[int]) -> list[int]:
        if any(port < 1 or port > 65535 for port in value):
            raise ValueError("Ports must be between 1 and 65535.")
        return sorted(set(value))


class ReconScanSummary(BaseModel):
    ip_count: int
    subdomain_count: int
    open_port_count: int
    open_ports: list[int]
    http_endpoint_count: int
    duration_ms: int
    dead_subdomain_count: int = 0


class ReconResponse(BaseModel):
    target: str
    dns: dict
    subdomains: list[dict]
    ports: list[dict]
    http: list[dict]
    dns_alerts: list[dict] = []
    vulnerabilities: list[dict] = []
    summary: ReconScanSummary


class ReconHistoryItem(BaseModel):
    id: str
    target: str
    scan_type: str
    status: str
    duration_ms: int
    authorized_use: bool
    created_at: str
    completed_at: str | None = None


class ReconHistoryResponse(BaseModel):
    total: int
    items: list[ReconHistoryItem]
