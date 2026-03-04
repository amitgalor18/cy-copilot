"""
Evaluation module for the Automotive Cybersecurity Copilot.

Runs 10 example incidents through the full pipeline and measures 8 metrics:

  METRIC                      TYPE              GT NEEDED?
  ─────────────────────────── ───────────────── ──────────
  summarization-correctness   LLM-as-judge      Yes
  summarization-conciseness   Deterministic     Yes
  summarization-format        Deterministic     No
  mitigation-correctness      LLM-as-judge      Yes
  mitigation-groundedness     LLM-as-judge      No  (uses runbook only)
  retrieval-NDCG@k            Deterministic     Yes
  retrieval-recall@k          Deterministic     Yes
  retrieval-precision@k       Deterministic     Yes

  k = TOP_K (the same top_k used in the live pipeline, currently 2).

Production-readiness (metrics usable in live production WITHOUT ground truth):
  ✓ summarization-format      — purely structural; checks JSON schema compliance
  ✓ mitigation-groundedness   — only needs the runbook which is always available
  ✗ summarization-correctness — requires a reference summary
  ✗ summarization-conciseness — requires a reference summary length
  ✗ mitigation-correctness    — requires a reference mitigation plan
  ✗ retrieval-NDCG            — requires relevance labels
  ✗ retrieval-recall@k        — requires relevance labels
  ✗ retrieval-precision@k     — requires relevance labels

Usage:
  python evaluation.py
"""

import json
import math
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Optional

from openai import OpenAI

import config
from llm_client import summarize_incident, get_mitigation_plan
from runbook import get_runbook_for_incident_type
from weaviate_rag import (
    ensure_collection_seeded,
    get_weaviate_client,
    search_similar_incidents,
)

# ---------------------------------------------------------------------------
# Constants — must stay in sync with main.py / weaviate_rag.py
# ---------------------------------------------------------------------------
TOP_K = 2

VALID_INCIDENT_TYPES = {
    "malware_infection", "unauthorized_access", "dos_attack",
    "data_breach", "supply_chain_compromise", "other",
}
VALID_CRITICALITIES = {"low", "medium", "high", "critical"}
REQUIRED_SUMMARY_FIELDS: dict[str, type] = {
    "source": str,
    "affected_services": list,
    "incident_type": str,
    "criticality": str,
    "extracted_keywords": list,
    "summary": str,
}

# ---------------------------------------------------------------------------
# 10 evaluation examples
# ---------------------------------------------------------------------------
EVAL_EXAMPLES: list[dict[str, Any]] = [
    {
        "id": "EVAL-001",
        "raw_report": (
            "At 09:15 UTC the SIEM triggered alert S-4401 for multiple failed authentication "
            "attempts against the OTA management portal originating from 10.0.5.12. The service "
            "account svc_ota_prod was used. After 12 failed attempts a successful login occurred "
            "and the account attempted to access production deployment keys. Infotainment OTA "
            "pipeline and backend API are potentially compromised."
        ),
        "gt_structured": {
            "source": "SIEM",
            "affected_services": ["OTA", "infotainment"],
            "incident_type": "unauthorized_access",
            "criticality": "critical",
            "extracted_keywords": ["10.0.5.12", "svc_ota_prod", "S-4401", "OTA", "deployment keys"],
            "summary": (
                "Multiple failed logins from 10.0.5.12 using svc_ota_prod were followed by "
                "a successful authentication and attempted access to production deployment keys. "
                "The OTA management portal and infotainment pipeline may be compromised."
            ),
        },
        "gt_mitigation": (
            "1. Immediately revoke svc_ota_prod credentials and invalidate all active sessions.\n"
            "2. Rotate OTA deployment keys and API tokens for the infotainment pipeline.\n"
            "3. Block IP 10.0.5.12 at the network perimeter.\n"
            "4. Review audit logs for lateral movement or data exfiltration.\n"
            "5. Enforce MFA on all service accounts and apply least-privilege policies.\n"
            "6. Document findings and harden the OTA portal entry point."
        ),
        "relevant_ticket_ids": ["TKT-2024-001", "TKT-2024-016"],
    },
    {
        "id": "EVAL-002",
        "raw_report": (
            "Fleet monitoring detected an infotainment ECU in segment VLAN-42 exhibiting anomalous "
            "network behaviour. The onboard IDS flagged outbound connections to a known C2 domain. "
            "Malware hash SHA256:abcdef1234567890 matches ThreatIntel DB entry for automotive "
            "trojan family 'VehiRAT'. IP 10.0.5.12 seen in related traffic. No safety-critical "
            "systems affected so far."
        ),
        "gt_structured": {
            "source": "IDS",
            "affected_services": ["infotainment"],
            "incident_type": "malware_infection",
            "criticality": "high",
            "extracted_keywords": ["10.0.5.12", "VLAN-42", "VehiRAT", "SHA256:abcdef1234567890", "C2"],
            "summary": (
                "Malware (VehiRAT trojan) detected on an infotainment ECU in VLAN-42 with "
                "outbound C2 connections. IP 10.0.5.12 appears in related traffic. "
                "No safety-critical impact yet."
            ),
        },
        "gt_mitigation": (
            "1. Isolate the affected ECU and VLAN-42 segment from the vehicle network.\n"
            "2. Capture forensic images and logs before remediation.\n"
            "3. Block C2 domain and hash at IDS/gateway.\n"
            "4. Reimage affected ECUs from gold image.\n"
            "5. Verify OTA and supply chain integrity before reconnecting.\n"
            "6. Update detection rules and document in incident ticket."
        ),
        "relevant_ticket_ids": ["TKT-2024-002", "TKT-2024-014"],
    },
    {
        "id": "EVAL-003",
        "raw_report": (
            "Starting at 11:30 UTC the telematics API experienced a sustained traffic spike "
            "causing 503 errors for connected vehicles. Source IPs include 192.168.1.100 and "
            "several external addresses. Fleet reporting and remote diagnostics are offline. "
            "User jdoe opened an urgent support ticket. Cloud WAF logs show volumetric GET "
            "flood pattern."
        ),
        "gt_structured": {
            "source": "Cloud WAF",
            "affected_services": ["telematics"],
            "incident_type": "dos_attack",
            "criticality": "high",
            "extracted_keywords": ["192.168.1.100", "jdoe", "telematics API", "503", "GET flood"],
            "summary": (
                "A volumetric DoS attack hit the telematics API starting 11:30 UTC, causing "
                "503 errors. Source IPs include 192.168.1.100. Fleet reporting and remote "
                "diagnostics are down."
            ),
        },
        "gt_mitigation": (
            "1. Apply rate limiting and IP filtering at the edge/WAF for attacking IPs.\n"
            "2. Engage DDoS mitigation provider for volumetric scrubbing.\n"
            "3. Scale telematics tier or failover to backup.\n"
            "4. Preserve WAF and API logs for forensic analysis.\n"
            "5. Gradually restore service and monitor for recurrence.\n"
            "6. Update capacity runbooks and consider circuit breakers."
        ),
        "relevant_ticket_ids": ["TKT-2024-003", "TKT-2024-015"],
    },
    {
        "id": "EVAL-004",
        "raw_report": (
            "Security audit found that the development telematics API endpoint was publicly "
            "accessible without authentication. Customer PII including names, VINs, and trip "
            "history was exposed. Access logs show queries from user jdoe and service account "
            "svc_ota_prod over the past 72 hours. Approximately 15,000 records affected."
        ),
        "gt_structured": {
            "source": "Security audit",
            "affected_services": ["telematics"],
            "incident_type": "data_breach",
            "criticality": "critical",
            "extracted_keywords": ["jdoe", "svc_ota_prod", "PII", "VIN", "trip history", "15000 records"],
            "summary": (
                "A misconfigured dev telematics API exposed ~15,000 customer PII records "
                "(names, VINs, trip history). Access logs show jdoe and svc_ota_prod queries "
                "over 72 hours."
            ),
        },
        "gt_mitigation": (
            "1. Immediately disable the exposed API endpoint.\n"
            "2. Preserve access logs and database records for forensics.\n"
            "3. Identify affected data categories and individuals.\n"
            "4. Notify legal and compliance; begin regulatory notification.\n"
            "5. Rotate credentials for jdoe and svc_ota_prod; patch the misconfiguration.\n"
            "6. Conduct post-incident review and tighten access controls on dev environments."
        ),
        "relevant_ticket_ids": ["TKT-2024-004", "TKT-2024-013"],
    },
    {
        "id": "EVAL-005",
        "raw_report": (
            "Automated SBOM scan flagged a compromised third-party library in the OTA client "
            "package v3.8.1. CVE-2024-XXXX has been assigned. The library is used in both "
            "infotainment and telematics modules. No evidence of active exploitation yet, but "
            "the vulnerability allows arbitrary code execution on the ECU."
        ),
        "gt_structured": {
            "source": "SBOM scan",
            "affected_services": ["OTA", "infotainment", "telematics"],
            "incident_type": "supply_chain_compromise",
            "criticality": "high",
            "extracted_keywords": ["CVE-2024-XXXX", "OTA client", "v3.8.1", "SBOM", "arbitrary code execution"],
            "summary": (
                "A compromised dependency (CVE-2024-XXXX) was found in OTA client v3.8.1 "
                "affecting infotainment and telematics. The vulnerability enables arbitrary "
                "code execution. No active exploitation confirmed."
            ),
        },
        "gt_mitigation": (
            "1. Quarantine OTA client v3.8.1 and block deployment to vehicles.\n"
            "2. Coordinate with the library vendor for a patched version.\n"
            "3. Assess impact on already-deployed vehicles; plan OTA remediation.\n"
            "4. Harden build pipeline with signature verification.\n"
            "5. Update SBOM and add the CVE to the block list.\n"
            "6. Document in incident report and update supplier security requirements."
        ),
        "relevant_ticket_ids": ["TKT-2024-005", "TKT-2024-019"],
    },
    {
        "id": "EVAL-006",
        "raw_report": (
            "The in-vehicle IDS on a test fleet vehicle detected anomalous CAN frames being "
            "injected at high frequency. Source node maps to ECU address 10.0.5.12. Messages "
            "are spoofing brake and steering commands but the gateway is filtering them. "
            "Physical inspection pending. No crash or safety incident occurred."
        ),
        "gt_structured": {
            "source": "In-vehicle IDS",
            "affected_services": ["CAN bus"],
            "incident_type": "other",
            "criticality": "high",
            "extracted_keywords": ["10.0.5.12", "CAN", "injection", "brake", "steering", "IDS"],
            "summary": (
                "High-frequency CAN frame injection detected from ECU 10.0.5.12, spoofing "
                "brake and steering commands. The gateway filtered the frames. No safety "
                "event occurred; physical inspection is pending."
            ),
        },
        "gt_mitigation": (
            "1. Isolate the suspect ECU (10.0.5.12) from the CAN bus.\n"
            "2. Perform physical inspection for aftermarket or tampered hardware.\n"
            "3. Capture CAN traffic logs for forensic analysis.\n"
            "4. Reflash ECU firmware from a known-good image.\n"
            "5. Implement stricter CAN message authentication.\n"
            "6. Enhance IDS rules and document findings."
        ),
        "relevant_ticket_ids": ["TKT-2024-006", "TKT-2024-010", "TKT-2024-020"],
    },
    {
        "id": "EVAL-007",
        "raw_report": (
            "User jdoe reported receiving an MFA prompt they did not initiate at 03:22 UTC "
            "for the vehicle companion app. Login originated from IP 192.168.1.100. The "
            "session token was used to access vehicle telemetry data. Account was not locked "
            "but multiple geographically inconsistent logins detected."
        ),
        "gt_structured": {
            "source": "User report",
            "affected_services": ["vehicle app", "telematics"],
            "incident_type": "unauthorized_access",
            "criticality": "medium",
            "extracted_keywords": ["jdoe", "192.168.1.100", "MFA", "session token", "vehicle telemetry"],
            "summary": (
                "User jdoe received an unsolicited MFA prompt; a login from 192.168.1.100 "
                "used a session token to access vehicle telemetry. Multiple geographically "
                "inconsistent logins suggest credential compromise."
            ),
        },
        "gt_mitigation": (
            "1. Invalidate all active sessions for jdoe immediately.\n"
            "2. Force password reset and re-enroll MFA.\n"
            "3. Block IP 192.168.1.100 and review for other affected accounts.\n"
            "4. Audit access logs for vehicle telemetry data exfiltration.\n"
            "5. Apply conditional access policies (geo-fencing, device trust).\n"
            "6. Document the incident and harden the login flow."
        ),
        "relevant_ticket_ids": ["TKT-2024-007", "TKT-2024-011"],
    },
    {
        "id": "EVAL-008",
        "raw_report": (
            "OTA rollout R-2024-108 for the infotainment media stack stalled at 38% with "
            "error CERT_EXPIRED from the staging distribution server. svc_ota_prod tried "
            "a manual override but the signature verification also failed. A batch of ~500 "
            "vehicles received a partial update before the rollout was halted."
        ),
        "gt_structured": {
            "source": "OTA platform",
            "affected_services": ["OTA", "infotainment"],
            "incident_type": "other",
            "criticality": "high",
            "extracted_keywords": ["R-2024-108", "svc_ota_prod", "CERT_EXPIRED", "infotainment", "500 vehicles"],
            "summary": (
                "OTA rollout R-2024-108 stalled at 38% due to an expired certificate on the "
                "staging server. ~500 vehicles received partial updates. Signature verification "
                "also failed during manual override."
            ),
        },
        "gt_mitigation": (
            "1. Halt the OTA rollout immediately for all remaining vehicles.\n"
            "2. Renew the expired certificate on the staging distribution server.\n"
            "3. Roll back partial updates on the ~500 affected vehicles.\n"
            "4. Verify OTA signing keys and re-sign the update package.\n"
            "5. Add certificate expiry monitoring and alerting.\n"
            "6. Resume rollout in staged fashion with validation gates."
        ),
        "relevant_ticket_ids": ["TKT-2024-008", "TKT-2024-017"],
    },
    {
        "id": "EVAL-009",
        "raw_report": (
            "Network monitoring detected TLS certificate anomalies on telematics connections "
            "from a fleet of 30 vehicles in region EU-West. The certificates presented do not "
            "match the pinned CA chain. Traffic appears routed through an unauthorized proxy "
            "at 192.168.1.100. Potential man-in-the-middle attack on vehicle-to-cloud channel."
        ),
        "gt_structured": {
            "source": "Network monitoring",
            "affected_services": ["telematics"],
            "incident_type": "unauthorized_access",
            "criticality": "critical",
            "extracted_keywords": ["192.168.1.100", "TLS", "MITM", "certificate", "EU-West", "30 vehicles"],
            "summary": (
                "TLS certificate mismatch detected on 30 vehicles in EU-West; traffic is "
                "routed through an unauthorized proxy at 192.168.1.100. This indicates a "
                "man-in-the-middle attack on the telematics channel."
            ),
        },
        "gt_mitigation": (
            "1. Enforce certificate pinning on all affected vehicles immediately.\n"
            "2. Revoke the compromised intermediate certificates.\n"
            "3. Block proxy IP 192.168.1.100 at the network perimeter.\n"
            "4. Conduct fleet-wide certificate chain verification.\n"
            "5. Assess whether any data was intercepted during the MITM window.\n"
            "6. Harden TLS configuration and add certificate transparency monitoring."
        ),
        "relevant_ticket_ids": ["TKT-2024-018", "TKT-2024-009"],
    },
    {
        "id": "EVAL-010",
        "raw_report": (
            "The OTA integrity checker rejected an update package pushed to the staging "
            "repository. Checksum mismatch on 3 of 12 binaries. The upload originated from "
            "10.0.5.12 using CI pipeline credentials. Sigstore verification failed. Possible "
            "build pipeline compromise or insider threat. No vehicles received the payload."
        ),
        "gt_structured": {
            "source": "OTA integrity checker",
            "affected_services": ["OTA"],
            "incident_type": "supply_chain_compromise",
            "criticality": "high",
            "extracted_keywords": ["10.0.5.12", "checksum mismatch", "sigstore", "CI pipeline", "build pipeline"],
            "summary": (
                "OTA integrity checker rejected an update with checksum mismatches on 3 "
                "binaries uploaded from 10.0.5.12. Sigstore verification failed, indicating "
                "possible build pipeline compromise. No vehicles were affected."
            ),
        },
        "gt_mitigation": (
            "1. Block the compromised upload and quarantine affected binaries.\n"
            "2. Audit the CI pipeline and credentials used from 10.0.5.12.\n"
            "3. Rebuild from a verified clean pipeline.\n"
            "4. Add sigstore and SBOM verification to the release gate.\n"
            "5. Investigate insider threat or credential compromise.\n"
            "6. Document incident and update build security controls."
        ),
        "relevant_ticket_ids": ["TKT-2024-012", "TKT-2024-019"],
    },
]

# ---------------------------------------------------------------------------
# LLM-as-judge prompts
# ---------------------------------------------------------------------------
_JUDGE_SYSTEM = (
    "You are an impartial evaluator for an automotive cybersecurity incident-response "
    "copilot. You will be given a predicted output and context, and must rate quality "
    "on a 1-5 integer scale. Respond with ONLY a JSON object: "
    '{{"score": <1-5>, "reasoning": "<one sentence>"}}'
)

_JUDGE_SUMMARY_TMPL = """Rate the CORRECTNESS of the predicted incident summary compared to the reference.

## Original Incident Report
{raw_report}

## Reference Summary (Ground Truth)
{reference}

## Predicted Summary
{predicted}

Scale:
1 = Completely incorrect or misses the incident entirely
2 = Major facts wrong or missing
3 = Partially correct; captures some key facts
4 = Mostly correct; minor omissions or inaccuracies
5 = Fully correct; all key facts captured"""

_JUDGE_MITIGATION_TMPL = """Rate the CORRECTNESS of the predicted mitigation plan compared to the reference.

## Incident Summary
{summary}

## Reference Mitigation (Ground Truth)
{reference}

## Predicted Mitigation
{predicted}

Scale:
1 = Completely incorrect or irrelevant steps
2 = Major steps missing or wrong
3 = Partially correct; some actionable steps present
4 = Mostly correct; minor gaps
5 = Fully correct; all critical steps present and appropriate"""

_JUDGE_GROUNDEDNESS_TMPL = """Rate how well the predicted mitigation is GROUNDED in the provided runbook.
Only evaluate whether the steps can be traced back to the runbook — do NOT judge overall quality.

## Company Runbook for This Incident Type
{runbook_text}

## Predicted Mitigation
{predicted}

Scale:
1 = Not grounded; ignores the runbook entirely
2 = Weakly grounded; vaguely related but adds many unfounded steps
3 = Partially grounded; some steps map to the runbook
4 = Mostly grounded; nearly all steps traceable to runbook guidance
5 = Fully grounded; every step is clearly derived from the runbook"""


# ---------------------------------------------------------------------------
# LLM-as-judge helpers
# ---------------------------------------------------------------------------
def _parse_judge_score(text: str) -> Optional[int]:
    """
    Extract score 1-5 from judge LLM response. Tolerates single-quoted JSON,
    markdown-wrapped JSON, and truncated reasoning (first } in string).
    Returns None if no valid score found.
    """
    if not text:
        return None
    text = text.strip()

    # 1) Try parsing the whole response as JSON (some models return only JSON)
    try:
        data = json.loads(text)
        s = data.get("score")
        if s is not None:
            return max(1, min(5, int(s)))
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    # 2) Find a JSON object with balanced braces so reasoning can contain "}"
    start = text.find("{")
    if start >= 0:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        data = json.loads(text[start : i + 1])
                        s = data.get("score")
                        if s is not None:
                            return max(1, min(5, int(s)))
                    except (json.JSONDecodeError, TypeError, ValueError):
                        pass
                    break

    # 3) Try single-quoted JSON: normalize to double quotes (only for key names)
    #    Match 'score' or "score" then : then number
    for pattern in (
        r'"score"\s*:\s*(\d)',
        r"'score'\s*:\s*(\d)",
        r"\bscore\s*:\s*(\d)",
    ):
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            val = int(m.group(1))
            if 1 <= val <= 5:
                return val

    return None


def _judge_call(system: str, user: str) -> float:
    """Call the judge LLM and return a normalized 0-1 score (maps 1-5 → 0.0-1.0)."""
    client = OpenAI(
        base_url=config.JUDGE_LLM_BASE_URL,
        api_key=config.JUDGE_LLM_API_KEY,
    )
    try:
        resp = client.chat.completions.create(
            model=config.JUDGE_LLM_MODEL,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=0.0,
        )
        text = (resp.choices[0].message.content or "").strip()
        score = _parse_judge_score(text)
        if score is not None:
            return (score - 1) / 4.0
    except Exception as exc:
        print(f"  [judge error: {exc}]", file=sys.stderr)
    return 0.0


def judge_summary_correctness(raw_report: str, predicted: dict, reference: dict) -> float:
    user = _JUDGE_SUMMARY_TMPL.format(
        raw_report=raw_report,
        reference=json.dumps(reference, indent=2),
        predicted=json.dumps(predicted, indent=2),
    )
    return _judge_call(_JUDGE_SYSTEM, user)


def judge_mitigation_correctness(summary: str, predicted: str, reference: str) -> float:
    user = _JUDGE_MITIGATION_TMPL.format(
        summary=summary, reference=reference, predicted=predicted,
    )
    return _judge_call(_JUDGE_SYSTEM, user)


# PRODUCTION-READY: does not require ground truth — only the runbook (always available)
def judge_mitigation_groundedness(predicted: str, runbook_text: str) -> float:
    user = _JUDGE_GROUNDEDNESS_TMPL.format(
        runbook_text=runbook_text, predicted=predicted,
    )
    return _judge_call(_JUDGE_SYSTEM, user)


# ---------------------------------------------------------------------------
# Deterministic metrics — summarization
# ---------------------------------------------------------------------------
def score_summary_conciseness(predicted_summary: str, reference_summary: str) -> float:
    """Word-count ratio score: 1.0 when predicted length matches reference, degrades linearly."""
    pred_words = len(predicted_summary.split())
    ref_words = len(reference_summary.split())
    if ref_words == 0:
        return 0.0 if pred_words > 0 else 1.0
    ratio = pred_words / ref_words
    return max(0.0, 1.0 - abs(ratio - 1.0))


# PRODUCTION-READY: no ground truth needed — purely structural check
def score_summary_format(structured: dict) -> tuple[float, list[str]]:
    """Check JSON schema compliance. Returns (score 0-1, list of failure descriptions)."""
    checks_total = 0
    checks_passed = 0
    failures: list[str] = []

    for field, expected_type in REQUIRED_SUMMARY_FIELDS.items():
        checks_total += 1
        if field not in structured:
            failures.append(f"missing field '{field}'")
        elif not isinstance(structured[field], expected_type):
            failures.append(f"'{field}' should be {expected_type.__name__}, got {type(structured[field]).__name__}")
        else:
            checks_passed += 1

    checks_total += 1
    it = structured.get("incident_type", "")
    if it in VALID_INCIDENT_TYPES:
        checks_passed += 1
    else:
        failures.append(f"incident_type '{it}' not in {VALID_INCIDENT_TYPES}")

    checks_total += 1
    crit = structured.get("criticality", "")
    if crit in VALID_CRITICALITIES:
        checks_passed += 1
    else:
        failures.append(f"criticality '{crit}' not in {VALID_CRITICALITIES}")

    for list_field in ("affected_services", "extracted_keywords"):
        checks_total += 1
        val = structured.get(list_field, [])
        if isinstance(val, list) and len(val) > 0:
            checks_passed += 1
        else:
            failures.append(f"'{list_field}' should be non-empty list")

    return (checks_passed / checks_total if checks_total else 0.0), failures


# ---------------------------------------------------------------------------
# Retrieval metrics (binary relevance)
# ---------------------------------------------------------------------------
def ndcg_at_k(retrieved_ids: list[str], relevant_ids: list[str], k: int) -> float:
    retrieved = retrieved_ids[:k]
    relevance = [1.0 if rid in relevant_ids else 0.0 for rid in retrieved]
    dcg = sum(rel / math.log2(i + 2) for i, rel in enumerate(relevance))
    ideal_len = min(len(relevant_ids), k)
    ideal = [1.0] * ideal_len + [0.0] * max(0, k - ideal_len)
    idcg = sum(rel / math.log2(i + 2) for i, rel in enumerate(ideal))
    return dcg / idcg if idcg > 0 else 0.0


def recall_at_k(retrieved_ids: list[str], relevant_ids: list[str], k: int) -> float:
    if not relevant_ids:
        return 0.0
    retrieved_set = set(retrieved_ids[:k])
    return len(retrieved_set & set(relevant_ids)) / len(relevant_ids)


def precision_at_k(retrieved_ids: list[str], relevant_ids: list[str], k: int) -> float:
    retrieved = retrieved_ids[:k]
    if not retrieved:
        return 0.0
    return sum(1.0 for rid in retrieved if rid in relevant_ids) / len(retrieved)


# ---------------------------------------------------------------------------
# Single-example evaluation
# ---------------------------------------------------------------------------
def evaluate_single(example: dict, weaviate_client: Any = None) -> dict[str, Any]:
    """Run the full pipeline on one example and compute all metrics."""
    eid = example["id"]
    raw = example["raw_report"]
    gt_struct = example["gt_structured"]
    gt_mit = example["gt_mitigation"]
    relevant = example["relevant_ticket_ids"]

    result: dict[str, Any] = {"id": eid}

    # --- Stage 1: summarize ---
    try:
        predicted_struct = summarize_incident(raw)
    except Exception as exc:
        print(f"  [{eid}] summarization failed: {exc}", file=sys.stderr)
        predicted_struct = {}

    pred_summary = predicted_struct.get("summary", "")
    pred_type = predicted_struct.get("incident_type", "other")
    pred_keywords = predicted_struct.get("extracted_keywords", [])

    # --- Stage 2: mitigation ---
    runbook_text = get_runbook_for_incident_type(pred_type)
    try:
        predicted_mit = get_mitigation_plan(pred_summary, runbook_text)
    except Exception as exc:
        print(f"  [{eid}] mitigation failed: {exc}", file=sys.stderr)
        predicted_mit = ""

    # --- Stage 3: retrieval ---
    retrieved_ids: list[str] = []
    if weaviate_client is not None:
        bm25_query = " ".join(pred_keywords[:15]) if pred_keywords else pred_summary
        try:
            rag_results = search_similar_incidents(
                weaviate_client,
                bm25_query=bm25_query,
                vector_query=pred_summary,
                top_k=TOP_K,
                alpha=0.5,
            )
            retrieved_ids = [r["ticket_id"] for r in rag_results]
        except Exception as exc:
            print(f"  [{eid}] retrieval failed: {exc}", file=sys.stderr)

    # --- Metrics ---
    result["sum_correctness"] = judge_summary_correctness(raw, predicted_struct, gt_struct)
    result["sum_conciseness"] = score_summary_conciseness(pred_summary, gt_struct["summary"])
    fmt_score, fmt_failures = score_summary_format(predicted_struct)
    result["sum_format"] = fmt_score
    result["sum_format_failures"] = fmt_failures
    result["mit_correctness"] = judge_mitigation_correctness(pred_summary, predicted_mit, gt_mit)
    result["mit_groundedness"] = judge_mitigation_groundedness(predicted_mit, runbook_text)
    result["ret_ndcg"] = ndcg_at_k(retrieved_ids, relevant, TOP_K)
    result["ret_recall"] = recall_at_k(retrieved_ids, relevant, TOP_K)
    result["ret_precision"] = precision_at_k(retrieved_ids, relevant, TOP_K)

    return result


# ---------------------------------------------------------------------------
# Orchestrator & pretty-print
# ---------------------------------------------------------------------------
METRIC_KEYS = [
    ("sum_correctness",  "SumCorr"),
    ("sum_conciseness",  "SumConc"),
    ("sum_format",       "SumFmt"),
    ("mit_correctness",  "MitCorr"),
    ("mit_groundedness", "MitGrnd"),
    ("ret_ndcg",         "NDCG@k"),
    ("ret_recall",       "Rec@k"),
    ("ret_precision",    "Prec@k"),
]


def _fmt(val: float) -> str:
    return f"{val:.2f}"


EXPERIMENTS_DIR = "evaluation_runs"


def _save_experiment(experiment: dict[str, Any]) -> None:
    """Write experiment metadata and scores to a timestamped JSON file for later comparison."""
    os.makedirs(EXPERIMENTS_DIR, exist_ok=True)
    ts = experiment["timestamp_utc"].replace(":", "-").replace(".", "-")[:19]
    filename = os.path.join(EXPERIMENTS_DIR, f"experiment_{ts}Z.json")
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(experiment, f, indent=2)
    print(f"\nExperiment saved to {filename}")


def run_evaluation() -> None:
    print("=" * 90)
    print("EVALUATION — Automotive Cybersecurity Copilot")
    print(f"  examples: {len(EVAL_EXAMPLES)}   top_k: {TOP_K}")
    print(f"  copilot LLM: {config.LLM_BASE_URL} / {config.LLM_MODEL}")
    print(f"  judge LLM:   {config.JUDGE_LLM_BASE_URL} / {config.JUDGE_LLM_MODEL}")
    print(f"  embedding:   {config.EMBED_BASE_URL} / {config.EMBED_MODEL}")
    print("=" * 90)

    # Try to connect to Weaviate (retrieval metrics are skipped if unavailable)
    weaviate_client = None
    try:
        weaviate_client = get_weaviate_client()
        ensure_collection_seeded(weaviate_client)
        print("  Weaviate: connected ✓")
    except Exception as exc:
        print(f"  Weaviate: unavailable — retrieval metrics will be 0  ({exc})")

    results: list[dict[str, Any]] = []
    for i, ex in enumerate(EVAL_EXAMPLES, 1):
        print(f"\n[{i}/{len(EVAL_EXAMPLES)}] Running {ex['id']} …")
        res = evaluate_single(ex, weaviate_client)
        results.append(res)
        short = " | ".join(f"{label}={_fmt(res[key])}" for key, label in METRIC_KEYS)
        print(f"  {short}")
        if res.get("sum_format_failures"):
            print(f"  format issues: {res['sum_format_failures']}")

    if weaviate_client is not None:
        try:
            weaviate_client.close()
        except Exception:
            pass

    # --- Aggregate ---
    n = len(results)
    averages = {key: sum(r[key] for r in results) / n for key, _ in METRIC_KEYS}

    # --- Save experiment metadata for later comparison ---
    experiment = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "copilot_llm": {
            "base_url": config.LLM_BASE_URL,
            "model": config.LLM_MODEL,
        },
        "judge_llm": {
            "base_url": config.JUDGE_LLM_BASE_URL,
            "model": config.JUDGE_LLM_MODEL,
        },
        "embedding": {
            "base_url": config.EMBED_BASE_URL,
            "model": config.EMBED_MODEL,
        },
        "eval_params": {
            "top_k": TOP_K,
            "num_examples": len(EVAL_EXAMPLES),
        },
        "averages": {key: round(averages[key], 4) for key, _ in METRIC_KEYS},
        "per_example": [
            {k: (round(v, 4) if isinstance(v, float) else v) for k, v in r.items() if k != "sum_format_failures"}
            for r in results
        ],
    }
    _save_experiment(experiment)

    header_labels = [label for _, label in METRIC_KEYS]
    col_w = 8
    id_w = 10

    print("\n" + "=" * 90)
    print(f"{'Example':<{id_w}}" + "".join(f"{lbl:>{col_w}}" for lbl in header_labels))
    print("-" * (id_w + col_w * len(header_labels)))
    for r in results:
        row = f"{r['id']:<{id_w}}"
        row += "".join(f"{_fmt(r[key]):>{col_w}}" for key, _ in METRIC_KEYS)
        print(row)
    print("-" * (id_w + col_w * len(header_labels)))
    avg_row = f"{'AVERAGE':<{id_w}}"
    avg_row += "".join(f"{_fmt(averages[key]):>{col_w}}" for key, _ in METRIC_KEYS)
    print(avg_row)
    print("=" * 90)

    # Production-readiness reminder
    print(
        "\nMetrics usable in PRODUCTION (no ground truth):\n"
        "  * summarization-format      (structural JSON check)\n"
        "  * mitigation-groundedness   (runbook-based, always available)\n"
        "All other metrics require ground-truth labels and are OFFLINE-ONLY.\n"
    )


if __name__ == "__main__":
    run_evaluation()
