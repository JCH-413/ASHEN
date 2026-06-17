"""
Recommendation under controlled conditions (RAG off / plain RAG / action-aware
RAG).

This mirrors `app.services.attack_recommender` but exposes the knobs the
evaluation needs that the production path hard-codes:

  * `grounding` — "off" (no retrieval), "plain" (dump retrieved CVEs into the
    prompt, the current app behaviour), or "action_aware" (map retrieved CVEs
    onto ASHEN's exploit types via eval.grounding before prompting).
  * `options` — Ollama generation options (temperature, seed) for reproducible
    or variance runs.

The "plain" path is kept byte-identical to the app so the comparison is against
the real system, not a re-implementation.
"""
from __future__ import annotations

from app.services.ollama_client import OllamaClient
from app.services.prompt_templates import build_attack_prompt
from app.services.rag_store import (
    retrieve_relevant_cves,
    retrieve_relevant_cves_structured,
)

from eval.grounding import build_grounding_block

client = OllamaClient()

_ACTION_AWARE_PROMPT = """You are an exploit recommender for an authorized penetration test. \
You may ONLY recommend from ASHEN's available exploit types listed below. \
Prioritize exploits whose target service AND weakness are confirmed in the scan findings; \
use the CVE evidence to support an exploit, not to introduce one. \
Do NOT recommend an exploit type that has neither a confirmed scan finding nor matching CVE evidence. \
Do NOT cite CVEs marked as having no matching ASHEN exploit.

Scan findings:
{scan_context}

{grounding_block}

For each recommended exploit write one line: priority number, port, exploit type, and why.

Exploitation Order:

1."""


def recommend(scan_context: str, *, grounding: str = "off",
              options: dict | None = None) -> dict:
    """Generate one attack recommendation under a fixed grounding condition.

    `grounding` is one of "off", "plain", "action_aware". Returns a dict with
    the condition, the exact prompt sent, the grounding used, and the raw model
    output (primed with "1." exactly as the app does).
    """
    if grounding == "action_aware":
        cve_rows = retrieve_relevant_cves_structured(scan_context)
        grounding_block = build_grounding_block(cve_rows)
        prompt = _ACTION_AWARE_PROMPT.format(
            scan_context=scan_context, grounding_block=grounding_block
        )
        cve_context = grounding_block
    else:
        cve_context = retrieve_relevant_cves(scan_context) if grounding == "plain" else ""
        enriched = (
            f"{scan_context}\n\nRelevant CVE context:\n{cve_context}"
            if cve_context
            else scan_context
        )
        prompt = build_attack_prompt(enriched)

    raw = client.generate(prompt, options=options) or ""
    full = "Exploitation Order:\n\n1." + raw

    return {
        "grounding": grounding,
        "cve_context": cve_context,
        "prompt": prompt,
        "raw_output": raw,
        "recommendation": full,
    }
