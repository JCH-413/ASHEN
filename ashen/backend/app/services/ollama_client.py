import json
import os
from typing import Generator

import httpx


class AIServiceUnavailableError(Exception):
    """Raised when the local AI provider cannot be reached."""

class OllamaClient:
    def __init__(self):
        self.url = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
        self.model = os.getenv("OLLAMA_MODEL", "llama3.2")

    def generate(self, prompt):
        try:
            with httpx.stream(
                "POST",
                self.url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": True,
                },
                timeout=120,
            ) as response:
                response.raise_for_status()
                result = ""

                for line in response.iter_lines():
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        result += data.get("response", "")
                    except json.JSONDecodeError:
                        continue

                return result.strip()

        except httpx.ConnectError as e:
            raise AIServiceUnavailableError(
                "AI service is unavailable. Start Ollama and try again. "
                f"(expected at {self.url})"
            ) from e
        except httpx.HTTPStatusError as e:
            raise RuntimeError(f"AI provider returned HTTP {e.response.status_code}") from e
        except httpx.TimeoutException as e:
            raise RuntimeError("AI provider request timed out") from e

    def generate_stream(self, prompt) -> Generator[str, None, None]:
        """Yield tokens as they arrive from Ollama."""
        try:
            with httpx.stream(
                "POST",
                self.url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": True,
                },
                timeout=120,
            ) as response:
                response.raise_for_status()

                for line in response.iter_lines():
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        token = data.get("response", "")
                        if token:
                            yield token
                    except json.JSONDecodeError:
                        continue

        except httpx.ConnectError as e:
            raise AIServiceUnavailableError(
                "AI service is unavailable. Start Ollama and try again. "
                f"(expected at {self.url})"
            ) from e
        except httpx.HTTPStatusError as e:
            raise RuntimeError(f"AI provider returned HTTP {e.response.status_code}") from e
        except httpx.TimeoutException as e:
            raise RuntimeError("AI provider request timed out") from e
