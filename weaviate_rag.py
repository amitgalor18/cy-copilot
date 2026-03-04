"""
Weaviate RAG: collection schema, seed data with overlapping entities, and hybrid search.
Uses bring-your-own vectors: we embed via an OpenAI-compatible embedding API (e.g. VLLM).
"""
from typing import Any

from openai import OpenAI
import weaviate
from weaviate.classes.config import DataType, Property
from weaviate.classes.query import MetadataQuery

import config

COLLECTION_NAME = "ResolvedTicket"

# Seed data: resolved tickets with overlapping IPs, usernames, and terms for keyword search
SEED_TICKETS = [
    {
        "ticket_id": "TKT-2024-001",
        "description": "Unauthorized access from IP 10.0.5.12 to OTA backend. User svc_ota_prod attempted privilege escalation. Detected via SIEM alert.",
        "resolution_notes": "Revoked svc_ota_prod credentials, rotated API keys. Blocked 10.0.5.12 at firewall. Added MFA for OTA service accounts.",
    },
    {
        "ticket_id": "TKT-2024-002",
        "description": "Malware detected on infotainment ECU in fleet segment. Hash matched known trojan. Source IP 10.0.5.12 observed in logs.",
        "resolution_notes": "Isolated affected ECUs, reimaged from gold image. Updated IDS rules. No data exfiltration confirmed.",
    },
    {
        "ticket_id": "TKT-2024-003",
        "description": "DoS on telematics API; traffic spike from multiple IPs including 192.168.1.100. User jdoe reported outage.",
        "resolution_notes": "Rate limiting and geo-blocking applied. Scaled telematics tier. Preserved logs for forensics.",
    },
    {
        "ticket_id": "TKT-2024-004",
        "description": "Data breach: PII exposed via misconfigured dev API. Access from user jdoe and service account svc_ota_prod.",
        "resolution_notes": "API disabled. Credentials rotated. Legal and compliance notified. Access controls tightened.",
    },
    {
        "ticket_id": "TKT-2024-005",
        "description": "Supply chain compromise: malicious dependency in OTA client library. CVE-2024-XXXX. Affects infotainment and telematics.",
        "resolution_notes": "Quarantined library version. Patched and redeployed OTA client. SBOM updated.",
    },
    {
        "ticket_id": "TKT-2024-006",
        "description": "CAN bus anomaly from ECU 10.0.5.12; possible injection. Detected by in-vehicle IDS. No crash or safety event.",
        "resolution_notes": "ECU isolated and reflashed. CAN traffic monitoring enhanced. Root cause was corrupted firmware update.",
    },
    {
        "ticket_id": "TKT-2024-007",
        "description": "User jdoe reported suspicious login to vehicle app from 192.168.1.100. Session hijack suspected.",
        "resolution_notes": "Session invalidated. User password reset and MFA enforced. No vehicle control access confirmed.",
    },
    {
        "ticket_id": "TKT-2024-008",
        "description": "OTA update failure on infotainment units; rollout stuck at 40%. Error code 0xE12 from backend. User svc_ota_prod triggered manual retry.",
        "resolution_notes": "Identified certificate expiry on staging OTA server. Renewed certs, resumed rollout. Added monitoring for cert validity.",
    },
    {
        "ticket_id": "TKT-2024-009",
        "description": "Telematics gateway dropping packets; latency spike from 192.168.1.100 to cloud. Affects fleet reporting and remote diagnostics.",
        "resolution_notes": "Upgraded gateway firmware. Tuned TCP window and applied QoS. Latency returned to baseline.",
    },
    {
        "ticket_id": "TKT-2024-010",
        "description": "Rogue ECU broadcasting on CAN; spoofed messages from unknown node. In-vehicle IDS flagged 10.0.5.12 as source. No safety impact.",
        "resolution_notes": "Physical inspection found aftermarket dongle. Removed and re-secured CAN. Implemented stricter message authentication.",
    },
    {
        "ticket_id": "TKT-2024-011",
        "description": "jdoe account locked after multiple failed logins from 192.168.1.100. Possible brute force or credential stuffing.",
        "resolution_notes": "Account locked. User verified via alternate channel. Enabled CAPTCHA and rate limiting on login endpoint.",
    },
    {
        "ticket_id": "TKT-2024-012",
        "description": "Malicious OTA payload attempt; checksum mismatch and signature failure. Origin IP 10.0.5.12. Update rejected by client.",
        "resolution_notes": "Blocked origin. Audited OTA pipeline. Confirmed client correctly rejected tampered payload. No compromise.",
    },
    {
        "ticket_id": "TKT-2024-013",
        "description": "PII leak in telematics logs; customer IDs and trip data exposed in dev environment. Access from jdoe and svc_ota_prod.",
        "resolution_notes": "Sanitized dev data. Enforced data masking. Restricted access to PII. Retrained team on data handling.",
    },
    {
        "ticket_id": "TKT-2024-014",
        "description": "Infotainment system crash loop after OTA; kernel panic on specific ECU batch. No CAN or safety systems affected.",
        "resolution_notes": "Rolled back OTA for affected VIN range. Root cause: driver bug in media stack. Patch released in next OTA cycle.",
    },
    {
        "ticket_id": "TKT-2024-015",
        "description": "DDoS targeting telematics API; volumetric traffic from 192.168.1.100 and other IPs. Service degraded for 2 hours.",
        "resolution_notes": "Engaged DDoS mitigation. Scaled auto-scaling limits. Blacklisted attacking IP ranges. Post-incident review completed.",
    },
    {
        "ticket_id": "TKT-2024-016",
        "description": "Privilege escalation by svc_ota_prod; service account used to access production DB. Detected via audit log. SIEM alert.",
        "resolution_notes": "Immediate credential rotation. Reduced svc_ota_prod permissions to least privilege. Implemented just-in-time access.",
    },
    {
        "ticket_id": "TKT-2024-017",
        "description": "Firmware integrity check failure on ECU 10.0.5.12 during boot; secure boot chain reported tampering. Vehicle would not start.",
        "resolution_notes": "Recovered via dealer reflash. Root cause: partial OTA left inconsistent state. Improved OTA atomicity and rollback.",
    },
    {
        "ticket_id": "TKT-2024-018",
        "description": "Man-in-the-middle on telematics TLS; rogue certificate observed in fleet. Some vehicles connected to 192.168.1.100 proxy.",
        "resolution_notes": "Certificate pinning enforced. Revoked compromised intermediates. Fleet-wide cert check. No data loss confirmed.",
    },
    {
        "ticket_id": "TKT-2024-019",
        "description": "Supply chain: compromised build pipeline; unsigned binary in OTA client library. CVE-2024-YYYY. Affects infotainment only.",
        "resolution_notes": "Halted OTA distribution. Rebuilt from clean pipeline. SBOM and sigstore verification added. No active exploitation.",
    },
    {
        "ticket_id": "TKT-2024-020",
        "description": "CAN bus flood from diagnostic tool left connected; 10.0.5.12 sourced high-rate traffic. In-vehicle IDS triggered. No crash.",
        "resolution_notes": "Tool disconnected. Updated diagnostic procedures. Rate limiting on diagnostic interface. Training for field techs.",
    },
]


def _embed_client() -> OpenAI:
    return OpenAI(
        base_url=config.EMBED_BASE_URL,
        api_key=config.EMBED_API_KEY,
    )


def get_embedding(text: str) -> list[float]:
    """Get embedding vector from OpenAI-compatible embedding API (e.g. VLLM)."""
    client = _embed_client()
    # OpenAI embedding API shape
    resp = client.embeddings.create(model=config.EMBED_MODEL, input=text)
    return resp.data[0].embedding


def get_weaviate_client() -> weaviate.WeaviateClient:
    """
    Return Weaviate client. WEAVIATE_URL must be set: use a local Weaviate (e.g. Docker)
    or Weaviate Cloud (with WEAVIATE_API_KEY).
    """
    if not config.WEAVIATE_URL:
        raise RuntimeError(
            "WEAVIATE_URL is required. Run Weaviate via Docker (e.g. "
            "docker run -d -p 8081:8080 -p 50051:50051 cr.weaviate.io/semitechnologies/weaviate:latest) "
            "and set WEAVIATE_URL=http://localhost:8081, or use Weaviate Cloud with WEAVIATE_URL and WEAVIATE_API_KEY."
        )
    if config.WEAVIATE_API_KEY:
        from weaviate.classes.init import Auth
        return weaviate.connect_to_weaviate_cloud(
            cluster_url=config.WEAVIATE_URL,
            auth_credentials=Auth.api_key(config.WEAVIATE_API_KEY),
        )
    # Local: parse host/port from WEAVIATE_URL (e.g. http://localhost:8081)
    url = config.WEAVIATE_URL.rstrip("/").replace("https://", "").replace("http://", "")
    parts = url.split(":")
    host = parts[0] or "localhost"
    port = int(parts[1]) if len(parts) > 1 else 8080
    return weaviate.connect_to_local(host=host, port=port)


def create_schema(client: weaviate.WeaviateClient) -> None:
    """Create ResolvedTicket collection with self-provided vectors (no vectorizer)."""
    if client.collections.exists(COLLECTION_NAME):
        return
    from weaviate.classes.config import Configure
    # Bring your own vectors: no vectorizer; we supply vectors at insert and query time
    client.collections.create(
        name=COLLECTION_NAME,
        properties=[
            Property(name="ticket_id", data_type=DataType.TEXT),
            Property(name="description", data_type=DataType.TEXT),
            Property(name="resolution_notes", data_type=DataType.TEXT),
        ],
        vectorizer_config=Configure.Vectorizer.none(),
    )


def seed_collection(client: weaviate.WeaviateClient) -> None:
    """Insert seed tickets with precomputed embeddings (description vectorized)."""
    coll = client.collections.get(COLLECTION_NAME)
    with coll.batch.dynamic() as batch:
        for item in SEED_TICKETS:
            vector = get_embedding(item["description"])
            batch.add_object(
                properties={
                    "ticket_id": item["ticket_id"],
                    "description": item["description"],
                    "resolution_notes": item["resolution_notes"],
                },
                vector=vector,
            )


def ensure_collection_seeded(client: weaviate.WeaviateClient) -> None:
    """Create collection if missing and seed if empty."""
    create_schema(client)
    coll = client.collections.get(COLLECTION_NAME)
    if coll.aggregate.over_all(total_count=True).total_count == 0:
        seed_collection(client)


def search_similar_incidents(
    client: weaviate.WeaviateClient,
    bm25_query: str,
    vector_query: str,
    top_k: int = 2,
    alpha: float = 0.5,
) -> list[dict[str, Any]]:
    """
    Hybrid search: BM25 over bm25_query (typically extracted_keywords for lexical match),
    vector search from embedding of vector_query (typically summary for semantic match).
    Returns list of dicts with ticket_id, description, resolution_notes, score.
    """
    query_vector = get_embedding(vector_query)
    coll = client.collections.get(COLLECTION_NAME)
    response = coll.query.hybrid(
        query=bm25_query,
        vector=query_vector,
        alpha=alpha,
        limit=top_k,
        return_metadata=MetadataQuery(score=True),
    )
    results = []
    for obj in response.objects:
        results.append({
            "ticket_id": obj.properties.get("ticket_id", ""),
            "description": obj.properties.get("description", ""),
            "resolution_notes": obj.properties.get("resolution_notes", ""),
            "score": float(obj.metadata.score) if obj.metadata and obj.metadata.score is not None else 0.0,
        })
    return results


def format_similar_incidents(results: list[dict[str, Any]]) -> str:
    """Format top results as readable lines: Ticket ID | Similarity | Description | Resolution."""
    lines = []
    for r in results:
        desc = r.get("description", "")
        resolution = r.get("resolution_notes", "")
        lines.append(
            f"Ticket ID: {r['ticket_id']} | Similarity: {r['score']:.4f}\n  Description: {desc}\n  Resolution: {resolution}"
        )
    return "\n".join(lines) if lines else "No similar incidents found."
