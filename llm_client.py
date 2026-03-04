"""OpenAI-compatible LLM client for summary and mitigation stages."""
import json
import re
from typing import Any

from openai import OpenAI

import config
from prompts import get_mitigation_prompt, get_summary_prompt

# JSON schema for the Stage 1 (summary) LLM response
SUMMARY_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "source": {"type": "string"},
        "affected_services": {"type": "array", "items": {"type": "string"}},
        "incident_type": {"type": "string"},
        "criticality": {"type": "string"},
        "extracted_keywords": {"type": "array", "items": {"type": "string"}},
        "summary": {"type": "string"},
    },
    "required": [
        "source",
        "affected_services",
        "incident_type",
        "criticality",
        "extracted_keywords",
        "summary",
    ],
    "additionalProperties": False,
}


def _get_client() -> OpenAI:
    return OpenAI(
        base_url=config.LLM_BASE_URL,
        api_key=config.LLM_API_KEY,
    )


def _extract_json_from_response(content: str) -> dict[str, Any]:
    """Strip markdown code blocks if present and parse JSON."""
    text = content.strip()
    # Remove ```json ... ``` or ``` ... ```
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if match:
        text = match.group(1).strip()
    return json.loads(text)


def summarize_incident(report_text: str) -> dict[str, Any]:
    """
    Stage 1: Call LLM to summarize the incident and extract structured fields.
    Returns a dict with source, affected_services, incident_type, criticality, extracted_keywords, summary.
    """
    client = _get_client()
    system, user = get_summary_prompt(report_text)
    response = client.chat.completions.create(
        model=config.LLM_MODEL,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.2,
    )
    content = response.choices[0].message.content
    if not content:
        raise ValueError("Empty LLM response for summary")
    data = _extract_json_from_response(content)
    # Normalize types
    for key in ("affected_services", "extracted_keywords"):
        if key in data and not isinstance(data[key], list):
            data[key] = [data[key]] if data[key] else []
    return data


def get_mitigation_plan(summary: str, runbook_text: str) -> str:
    """
    Stage 2: Call LLM to generate a mitigation plan using the incident summary and runbook.
    Returns plain text mitigation plan.
    """
    client = _get_client()
    system, user = get_mitigation_prompt(summary, runbook_text)
    response = client.chat.completions.create(
        model=config.LLM_MODEL,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.3,
    )
    content = response.choices[0].message.content
    return (content or "").strip()
