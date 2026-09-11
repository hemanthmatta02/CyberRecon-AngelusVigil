"""CyberSentinel defensive AI with Ollama-first local inference and Gemini fallback."""
from __future__ import annotations

import json
import os
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.api.auth import current_user_from_request

router = APIRouter(prefix="/ai", tags=["ai"])


class AnalyzeRequest(BaseModel):
    question: str = Field(min_length=3, max_length=3000)
    context: dict[str, Any] = Field(default_factory=dict)


def _local_answer(question: str, context: dict[str, Any]) -> str:
    severity = context.get("severity", "unknown")
    score = context.get("score", "unknown")
    path = context.get("path", "the observed request")
    return (
        f"Defensive analysis: {path} was observed with severity {severity} and score {score}. "
        "Validate the matched rules, affected asset, and analyst feedback before escalating. "
        "Recommended workflow: preserve evidence → investigate → contain if confirmed → resolve/close after verification. "
        f"Question received: {question}"
    )


def _extract_gemini_text(data: dict[str, Any]) -> str:
    texts: list[str] = []
    for candidate in data.get("candidates", []):
        for part in candidate.get("content", {}).get("parts", []):
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                texts.append(part["text"])
    return "\n".join(texts).strip() or "No AI text returned."


def _extract_ollama_text(data: dict[str, Any]) -> str:
    message = data.get("message")
    if isinstance(message, dict) and isinstance(message.get("content"), str):
        return message["content"].strip()
    if isinstance(data.get("response"), str):
        return data["response"].strip()
    return "No AI text returned."


def _ollama_config() -> tuple[bool, str, str]:
    enabled = os.getenv("OLLAMA_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}
    base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").strip().rstrip("/")
    model = os.getenv("OLLAMA_MODEL", "qwen2.5:7b").strip()
    return enabled, base_url, model


async def _ollama_analyze(question: str, context: dict[str, Any]) -> tuple[str, str]:
    enabled, base_url, model = _ollama_config()
    if not enabled:
        raise RuntimeError("Ollama disabled")

    instructions = (
        "You are CyberSentinel, a defensive SOC security assistant. Analyze only authorized telemetry. "
        "Explain findings, prioritize risk, and recommend investigation and remediation. "
        "Never provide credential theft, malware, evasion, persistence, or unauthorized exploitation instructions. "
        "Keep recommendations practical and suitable for a defensive security operations platform."
    )
    prompt = (
        f"{instructions}\n\nQuestion:\n{question}\n\n"
        f"Telemetry context:\n{json.dumps(context, default=str)}"
    )

    async with httpx.AsyncClient(timeout=60) as client:
        health = await client.get(f"{base_url}/api/tags")
        health.raise_for_status()
        models = health.json().get("models", [])
        available = {item.get("name") for item in models if isinstance(item, dict)}
        if model not in available:
            raise RuntimeError(f"Ollama model '{model}' is not installed")

        response = await client.post(
            f"{base_url}/api/chat",
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "options": {"temperature": 0.2},
            },
        )
        response.raise_for_status()
        answer = _extract_ollama_text(response.json())
        if not answer:
            raise RuntimeError("Ollama returned an empty response")
        return model, answer


@router.get("/status")
async def ai_status(request: Request) -> dict[str, object]:
    current_user_from_request(request)
    enabled, base_url, model = _ollama_config()
    if not enabled:
        return {"provider": "OLLAMA", "enabled": False, "available": False, "model": model}

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(f"{base_url}/api/tags")
            response.raise_for_status()
            names = {
                item.get("name")
                for item in response.json().get("models", [])
                if isinstance(item, dict)
            }
            return {
                "provider": "OLLAMA",
                "enabled": True,
                "available": True,
                "model": model,
                "model_installed": model in names,
                "base_url": base_url,
            }
    except (httpx.HTTPError, ValueError):
        return {
            "provider": "OLLAMA",
            "enabled": True,
            "available": False,
            "model": model,
            "model_installed": False,
            "base_url": base_url,
        }


@router.post("/analyze")
async def analyze(payload: AnalyzeRequest, request: Request) -> dict[str, object]:
    current_user_from_request(request)

    try:
        model, answer = await _ollama_analyze(payload.question, payload.context)
        return {"mode": "OLLAMA", "model": model, "answer": answer}
    except (httpx.HTTPError, RuntimeError) as ollama_error:
        key = os.getenv("GEMINI_API_KEY", "").strip()
        if not key:
            return {
                "mode": "LOCAL_FALLBACK",
                "model": "local-defensive-analyzer",
                "answer": _local_answer(payload.question, payload.context),
                "provider_note": str(ollama_error),
            }

        model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        instructions = (
            "You are CyberSentinel, a defensive SOC copilot. Analyze only authorized security telemetry. "
            "Explain findings, prioritize risk, recommend investigation and remediation. "
            "Do not provide credential theft, malware, evasion, or unauthorized exploitation instructions."
        )
        body = {
            "system_instruction": {"parts": [{"text": instructions}]},
            "contents": [{
                "role": "user",
                "parts": [{"text": f"Question: {payload.question}\nTelemetry context:\n{json.dumps(payload.context, default=str)}"}],
            }],
            "generationConfig": {"temperature": 0.2},
        }
        try:
            async with httpx.AsyncClient(timeout=45) as client:
                response = await client.post(url, params={"key": key}, json=body)
                response.raise_for_status()
                return {"mode": "GEMINI", "model": model, "answer": _extract_gemini_text(response.json())}
        except httpx.HTTPError as exc:
            raise HTTPException(502, f"AI providers unavailable: {exc}") from exc
