"""Mock company runbook: incident type -> mitigation guidelines."""

RUNBOOK: dict[str, str] = {
    "malware_infection": """
1. Isolate affected ECUs or segments from the vehicle network immediately.
2. Capture forensic images of affected systems (logs, memory if feasible) before reimaging.
3. Identify malware family and IOCs; block hashes and domains at gateway/IDS.
4. Reimage from known-good gold images; restore from clean backups if available.
5. Verify integrity of OTA and supply chain before reconnecting to backend.
6. Update detection rules and deploy patches; document in incident ticket.
""",
    "unauthorized_access": """
1. Revoke compromised credentials and session tokens; force MFA re-auth where applicable.
2. Determine scope: which systems (vehicle, backend, dev) were accessible.
3. Rotate API keys, service accounts, and certificates for affected services.
4. Review audit logs for persistence and lateral movement; contain any further access.
5. Align with IAM team on least-privilege and conditional access for automotive roles.
6. Document access path and harden entry points (VPN, SSO, vehicle-facing APIs).
""",
    "dos_attack": """
1. Identify target (e.g. telematics, OTA, or in-vehicle services) and traffic patterns.
2. Apply rate limiting and geo/IP filtering at edge; scale or failover if needed.
3. Engage DDoS mitigation (provider or cloud) if attack is volumetric.
4. Preserve logs and packet captures for analysis and potential legal action.
5. Restore normal capacity gradually; monitor for recurrence.
6. Update capacity and resilience runbooks; consider circuit breakers for critical APIs.
""",
    "data_breach": """
1. Contain the breach: disable exposed APIs, lock down databases, and isolate affected segments.
2. Preserve evidence (logs, DB dumps, access records) for forensics and legal.
3. Identify data categories (PII, vehicle data, source code) and affected individuals/systems.
4. Notify legal and compliance; follow regulatory and contractual notification timelines.
5. Rotate all potentially exposed credentials and keys; patch vulnerability that allowed access.
6. Conduct post-incident review and update data classification and access controls.
""",
    "supply_chain_compromise": """
1. Identify affected components (software, libraries, firmware, hardware) and versions.
2. Quarantine or block deployment of compromised artifacts; do not ship to vehicles or backend.
3. Coordinate with vendor and internal procurement; obtain patches or replacement components.
4. Assess impact on already-deployed vehicles and backend; plan recall or OTA remediation if needed.
5. Harden build and signing pipelines; verify integrity and provenance of future deliveries.
6. Document in SBOM and incident report; update supplier security requirements.
""",
    "other": """
1. Triage: assess scope, criticality, and affected assets (vehicle, cloud, internal).
2. Contain: isolate affected systems and prevent further spread or data exfiltration.
3. Preserve evidence (logs, snapshots) for forensics.
4. Eradicate: remove threat (malware, unauthorized access) and patch root cause.
5. Recover: restore from clean backups or gold images; verify integrity.
6. Post-incident: document timeline, IOCs, and lessons learned; update runbooks and detection.
""",
}


def get_runbook_for_incident_type(incident_type: str) -> str:
    """Return runbook text for the given incident type; fallback to 'other' if unknown."""
    normalized = (incident_type or "").strip().lower()
    return RUNBOOK.get(normalized, RUNBOOK["other"])
