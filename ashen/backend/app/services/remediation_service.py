from .ollama_client import AIServiceUnavailableError, OllamaClient
from .prompt_templates import build_remediation_prompt
from .safety_filter import filter_response

client = OllamaClient()

def get_remediation(data):
    try:
        prompt = build_remediation_prompt(data)
        response = client.generate(prompt)

        lines = response.split("\n")

        clean = []
        for line in lines:
            line = line.strip()

            if not line:
                continue

            # detect steps or useful lines
            if any(word in line.lower() for word in ["disable", "use", "close", "restrict", "update", "install"]):
                clean.append(f"- {line}")

        final_output = "\n".join(clean) if clean else response

        return filter_response(final_output)

    except AIServiceUnavailableError:
        raise
    except Exception:
        return "Error generating remediation guidance"