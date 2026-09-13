"""Tests for the optional local Ollama analysis boundary."""

import pytest

from app.api.ai import (
    AnalyzeRequest,
    OllamaInvalidResponse,
    SecurityAnalysis,
    _ground_analysis,
)
from app.config import Settings


SAMPLE_SCAN = {
    "target": "example.test",
    "vulnerabilities": [
        {
            "name": "Missing security headers",
            "severity": "MEDIUM",
            "evidence": "content-security-policy",
        },
    ],
    "summary": {"open_port_count": 1},
}


def test_analyze_request_requires_explicit_real_scan_data() -> None:
    with pytest.raises(ValueError):
        AnalyzeRequest(question="What is risky?", scan_data={})
    with pytest.raises(ValueError):
        AnalyzeRequest(question="What is risky?", context=SAMPLE_SCAN)
    request = AnalyzeRequest(question="What is risky?", scan_data=SAMPLE_SCAN)
    assert request.scan_data == SAMPLE_SCAN


def test_grounded_evidence_accepts_exact_json_pointer_value() -> None:
    analysis = SecurityAnalysis.model_validate({
        "risk": "MEDIUM",
        "findings": [{
            "title": "Missing security headers",
            "severity": "MEDIUM",
            "evidence": [{
                "path": "/vulnerabilities/0/evidence",
                "value": "content-security-policy",
            }],
            "impact": "Browser protections may be weaker than intended.",
            "remediation": "Configure the missing response header.",
        }],
        "summary": "The scan contains one evidence-backed medium finding.",
    })
    assert _ground_analysis(analysis, SAMPLE_SCAN).findings[0].evidence[0].value == "content-security-policy"


def test_grounded_evidence_rejects_invented_value() -> None:
    analysis = SecurityAnalysis.model_validate({
        "risk": "HIGH",
        "findings": [{
            "title": "Invented issue",
            "severity": "HIGH",
            "evidence": [{
                "path": "/summary/open_port_count",
                "value": "999",
            }],
            "impact": "Unsupported impact.",
            "remediation": "Unsupported remediation.",
        }],
        "summary": "Unsupported.",
    })
    with pytest.raises(OllamaInvalidResponse):
        _ground_analysis(analysis, SAMPLE_SCAN)


def test_production_rejects_enabled_local_ollama() -> None:
    settings = Settings(
        env="production",
        auth_secret="x" * 32,
        allow_demo_auth=False,
        allow_public_registration=False,
        cors_origins="https://example.test",
        ollama_enabled=True,
        ollama_base_url="http://host.docker.internal:11434",
    )
    with pytest.raises(ValueError, match="OLLAMA_ENABLED"):
        settings.validate_runtime()


def test_development_rejects_public_ollama_url() -> None:
    settings = Settings(
        env="development",
        ollama_enabled=True,
        ollama_base_url="https://example.com/ollama",
    )
    with pytest.raises(ValueError, match="local"):
        settings.validate_runtime()
