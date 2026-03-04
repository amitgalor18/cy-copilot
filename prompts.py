"""Prompt management for the copilot. Central place for all LLM prompts."""

SUMMARY_SYSTEM = """You are an automotive cybersecurity analyst assistant. Your task is to analyze security incident reports and extract structured information.

Always respond with valid JSON matching the required schema. Do not include markdown code fences or any text outside the JSON."""

SUMMARY_USER_TEMPLATE = """Analyze the following security incident report and extract the requested information.

INCIDENT REPORT:
---
{report_text}
---

Extract and return a JSON object with these exact keys:
- source: string (origin or reporter of the incident, e.g. SIEM, IDS, analyst name)
- affected_services: list of strings (e.g. "OTA", "CAN bus", "infotainment")
- incident_type: string (one of: malware_infection, unauthorized_access, dos_attack, data_breach, supply_chain_compromise, other)
- criticality: string (one of: low, medium, high, critical)
- extracted_keywords: list of strings (IPs, hostnames, user names, IDs, CVEs, or key terms useful for searching similar incidents)
- summary: string (a clear 2–4 sentence executive summary for the user)

Return only the JSON object, no other text."""

MITIGATION_SYSTEM = """You are an automotive cybersecurity response specialist. You produce mitigation and response plans that follow the company runbook and are tailored to the specific incident."""

MITIGATION_USER_TEMPLATE = """Based on the incident summary and the relevant runbook section below, produce a concise recommended mitigation and response plan.

EXECUTIVE SUMMARY OF THE INCIDENT:
---
{summary}
---

RELEVANT RUNBOOK GUIDELINES FOR THIS INCIDENT TYPE:
---
{runbook_text}
---

Provide a clear, step-by-step mitigation plan that:
1. Follows the runbook guidelines as much as possible
2. Is tailored to the specific incident details above
3. Uses short paragraphs or bullet points
4. Does not include generic filler; only actionable steps

Write the mitigation plan in plain text (no JSON)."""


def get_summary_prompt(report_text: str) -> tuple[str, str]:
    """Return (system, user) for the summary stage."""
    return SUMMARY_SYSTEM, SUMMARY_USER_TEMPLATE.format(report_text=report_text)


def get_mitigation_prompt(summary: str, runbook_text: str) -> tuple[str, str]:
    """Return (system, user) for the mitigation stage."""
    return MITIGATION_SYSTEM, MITIGATION_USER_TEMPLATE.format(
        summary=summary, runbook_text=runbook_text
    )
