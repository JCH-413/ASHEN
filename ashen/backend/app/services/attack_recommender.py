from typing import Generator

from .ollama_client import AIServiceUnavailableError, OllamaClient
from .prompt_templates import build_attack_prompt
from .safety_filter import filter_attack_response

client = OllamaClient()


def recommend_attacks(data):
    """Synchronous attack recommendation (kept for backward compatibility)."""
    if not data:
        return "No input provided"

    try:
        prompt = build_attack_prompt(data)
        response = client.generate(prompt)

        if not response:
            return "No response from AI"

        return filter_attack_response("Exploitation Order:\n\n1." + response)

    except AIServiceUnavailableError:
        raise
    except Exception:
        return "Error generating attack recommendations. Please try again or contact your administrator."


def stream_attack_recommendation(data) -> Generator[str, None, None]:
    """Yield attack recommendation tokens as they arrive from the LLM."""
    prompt = build_attack_prompt(data)
    # The prompt ends with "1." to prime the model — prepend it so the
    # streamed output starts with the full first step
    yield "Exploitation Order:\n\n1."
    yield from client.generate_stream(prompt)
