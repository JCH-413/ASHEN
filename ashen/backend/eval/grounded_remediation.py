"""
Grounded remediation: the RAG counterpart of `app.services.remediation_service`.

The production remediation path is ungrounded free-form generation, which
hallucinates incorrect specifics (e.g. a `DisableSMBv1` registry value, an
`allow_root` directive). This variant retrieves curated, verified fix references
for the finding and constrains the LLM to base every concrete command/value on
them — the same grounding principle applied to recommendation in eval.grounding.

Returns (remediation_text, references_used) so the evaluation can record what the
fix was grounded on.
"""
from __future__ import annotations

from app.services.ollama_client import OllamaClient
from app.services.rag_store import retrieve_remediation

client = OllamaClient()

_PROMPT = """You are a cybersecurity remediation expert. Use ONLY the vetted \
remediation references below as the basis for your fix. Do NOT invent commands, \
registry values, config directives, or options that are not supported by the \
references — if a reference gives an exact value (e.g. a registry name or config \
key), use it verbatim.

Vetted remediation references:
{refs}

Vulnerability to remediate:
{context}

Respond using EXACTLY this structure, basing every concrete command/value on the
references above:

## Root Cause
## Immediate Containment
## Permanent Fix
## Validation
## Hardening"""


def get_grounded_remediation(context: str, query: str | None = None,
                             options: dict | None = None) -> tuple[str, list[dict]]:
    """Generate a remediation grounded in retrieved fix references.

    `query` drives retrieval (defaults to the finding context). Falls back to the
    context-only prompt if no references are found, so behaviour degrades safely.
    """
    refs_rows = retrieve_remediation(query or context)
    refs = "\n".join(
        f"- {r['text']} (source: {r['source']})" for r in refs_rows
    ) or "(no references found)"
    prompt = _PROMPT.format(refs=refs, context=context)
    text = client.generate(prompt, options=options) or ""
    return text, refs_rows
