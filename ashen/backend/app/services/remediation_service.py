from typing import Generator

from .ollama_client import AIServiceUnavailableError, OllamaClient
from .prompt_templates import build_remediation_prompt
from .safety_filter import filter_remediation_response

client = OllamaClient()


def _is_echo(context: str, response: str) -> bool:
    """Detect if the LLM echoed the input context instead of generating guidance."""
    if not response or not context:
        return False
    resp_lower = response.lower().strip()
    # If >40% of the context lines appear verbatim in the response, it's an echo
    context_lines = [l.strip().lower() for l in context.split("\n") if len(l.strip()) > 15]
    if not context_lines:
        return False
    matches = sum(1 for line in context_lines if line in resp_lower)
    return matches / len(context_lines) > 0.4


def get_remediation(data):
    try:
        prompt = build_remediation_prompt(data)
        response = client.generate(prompt)

        # If the model echoed the context back, retry with a focused nudge
        if _is_echo(data, response):
            retry_prompt = (
                "Write remediation steps for this cybersecurity issue. "
                "Do NOT repeat the issue description.\n\n"
                f"Issue: {data[:300]}\n\n"
                "Respond with:\n"
                "## Root Cause\n## Immediate Containment\n## Permanent Fix\n## Validation\n## Hardening"
            )
            response = client.generate(retry_prompt)

        return filter_remediation_response(response)

    except AIServiceUnavailableError:
        raise
    except Exception:
        return "Error generating remediation guidance. Please try again or contact your administrator."


def stream_remediation(data) -> Generator[str, None, None]:
    """Yield remediation tokens as they arrive from the LLM."""
    prompt = build_remediation_prompt(data)
    yield from client.generate_stream(prompt)
