from .ollama_client import AIServiceUnavailableError, OllamaClient
from .prompt_templates import build_attack_prompt
from .safety_filter import filter_response
from .governance_logger import log_event   # ✅ NEW

client = OllamaClient()

def recommend_attacks(data):
    if not data:
        return "No input provided"

    try:
        prompt = build_attack_prompt(data)
        response = client.generate(prompt)

        if not response:
            return "No response from AI"

        # 🔥 DIRECT FILTER APPLY (IMPORTANT)
        return filter_response(response)

    except AIServiceUnavailableError:
        raise
    except Exception:
        return "Error generating attack recommendations"