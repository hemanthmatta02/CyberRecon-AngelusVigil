"""Gemini-powered defensive SOC copilot with a safe local fallback."""
from __future__ import annotations
import os, json
from typing import Any
import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from app.api.auth import current_user_from_request

router = APIRouter(prefix="/ai", tags=["ai-copilot"])

class AnalyzeRequest(BaseModel):
    question: str = Field(min_length=3, max_length=3000)
    context: dict[str, Any] = Field(default_factory=dict)

def _local_answer(question: str, context: dict[str, Any]) -> str:
    severity=context.get("severity","unknown"); score=context.get("score","unknown")
    path=context.get("path","the observed request")
    return (f"Defensive analysis: {path} was observed with severity {severity} and score {score}. "
            "Validate the matched rules, affected asset, and analyst feedback before escalating. "
            "Recommended workflow: preserve evidence → investigate → contain if confirmed → resolve/close after verification. "
            f"Question received: {question}")

def _extract_text(data: dict[str, Any]) -> str:
    texts=[]
    for candidate in data.get("candidates", []):
        for part in candidate.get("content", {}).get("parts", []):
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                texts.append(part["text"])
    return "\n".join(texts).strip() or "No AI text returned."

@router.post("/analyze")
async def analyze(payload: AnalyzeRequest, request: Request) -> dict[str, object]:
    current_user_from_request(request)
    key=os.getenv("GEMINI_API_KEY","").strip()
    if not key:
        return {"mode":"LOCAL_FALLBACK","model":"local-defensive-analyzer",
                "answer":_local_answer(payload.question,payload.context)}
    model=os.getenv("GEMINI_MODEL","gemini-2.5-flash")
    url=f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    instructions=("You are CyberSentinel, a defensive SOC copilot. Analyze only authorized security telemetry. "
                  "Explain findings, prioritize risk, recommend investigation and remediation. "
                  "Do not provide credential theft, malware, evasion, or unauthorized exploitation instructions.")
    body={"system_instruction":{"parts":[{"text":instructions}]},
          "contents":[{"role":"user","parts":[{"text":f"Question: {payload.question}\nTelemetry context:\n{json.dumps(payload.context, default=str)}"}]}],
          "generationConfig":{"temperature":0.2}}
    try:
        async with httpx.AsyncClient(timeout=45) as client:
            response=await client.post(url, params={"key":key}, json=body)
            if response.is_error:
                raise HTTPException(502, f"Gemini provider error: {response.text[:500]}")
            return {"mode":"GEMINI","model":model,"answer":_extract_text(response.json())}
    except HTTPException:
        raise
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Gemini provider unavailable: {exc}") from exc
