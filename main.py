"""
Automotive Cybersecurity Analyst Copilot — main entrypoint.

Takes a raw security incident report (free text), then:
  1. Summarizes and extracts structured fields (LLM, JSON schema)
  2. Suggests mitigation from runbook + second LLM call
  3. Retrieves similar past incidents from Weaviate (hybrid search)

Usage:
  python main.py "Your incident report text here..."
  python main.py --file path/to/report.txt
"""
import argparse
import sys

import config
from llm_client import get_mitigation_plan, summarize_incident
from runbook import get_runbook_for_incident_type
from weaviate_rag import (
    ensure_collection_seeded,
    format_similar_incidents,
    get_weaviate_client,
    search_similar_incidents,
)


def run_copilot(raw_report: str) -> dict:
    """
    Run the full copilot pipeline on a raw incident report.
    Returns dict with keys: summary_text, mitigation_text, similar_incidents_text, structured (stage 1 JSON).
    """
    # Stage 1: Summarize and extract
    structured = summarize_incident(raw_report)
    summary_text = structured.get("summary", "")
    incident_type = structured.get("incident_type", "other")
    extracted_keywords = structured.get("extracted_keywords", [])

    # Stage 2: Runbook + mitigation LLM
    runbook_text = get_runbook_for_incident_type(incident_type)
    mitigation_text = get_mitigation_plan(summary_text, runbook_text)

    # Stage 3: Similar incidents from Weaviate (hybrid: BM25 on keywords, vector on summary)
    bm25_query = " ".join(extracted_keywords[:15]) if extracted_keywords else summary_text
    similar_incidents_text = "No similar incidents found."
    try:
        client = get_weaviate_client()
        ensure_collection_seeded(client)
        results = search_similar_incidents(
            client,
            bm25_query=bm25_query,
            vector_query=summary_text,
            top_k=2,
            alpha=0.5,
        )
        similar_incidents_text = format_similar_incidents(results)
        client.close()
    except Exception as e:
        similar_incidents_text = f"Could not query knowledge base: {e}"

    return {
        "summary_text": summary_text,
        "mitigation_text": mitigation_text,
        "similar_incidents_text": similar_incidents_text,
        "structured": structured,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Automotive Cybersecurity Analyst Copilot — summarize, mitigate, and find similar incidents."
    )
    parser.add_argument(
        "report",
        nargs="?",
        default=None,
        help="Raw incident report text (or use --file).",
    )
    parser.add_argument(
        "--file", "-f",
        dest="file",
        default=None,
        help="Read report from file instead of argument.",
    )
    args = parser.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            raw_report = f.read()
    elif args.report:
        raw_report = args.report
    else:
        print("Provide report text as argument or use --file path/to/report.txt", file=sys.stderr)
        sys.exit(1)

    result = run_copilot(raw_report)

    print("\n--- EXECUTIVE SUMMARY ---\n")
    print(result["summary_text"])
    print("\n--- RECOMMENDED MITIGATION ---\n")
    print(result["mitigation_text"])
    print("\n--- RELEVANT PAST INCIDENTS ---\n")
    print(result["similar_incidents_text"])
    print()


if __name__ == "__main__":
    main()
