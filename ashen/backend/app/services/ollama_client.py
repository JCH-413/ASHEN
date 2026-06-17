import json
import os
import time
from typing import Generator

import httpx


class AIServiceUnavailableError(Exception):
    """Raised when the local AI provider cannot be reached."""

class OllamaClient:
    def __init__(self):
        self.url = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
        self.model = os.getenv("OLLAMA_MODEL", "llama3.2")
        # Request timeout (seconds). Configurable for slow CPU-only inference,
        # e.g. the evaluation harness on hardware without a GPU.
        self.timeout = float(os.getenv("OLLAMA_TIMEOUT", "120"))
        # Retry transient server errors (HTTP 5xx / timeouts), which occur under
        # memory pressure on small hosts. Default 3 attempts; app behaviour is
        # unchanged on success.
        self.retries = int(os.getenv("OLLAMA_RETRIES", "3"))

    def generate(self, prompt, options: dict | None = None):
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": True,
        }
        # Optional Ollama generation options (e.g. temperature, seed).
        # Defaults to None so app behaviour is unchanged; the evaluation
        # harness passes these to make runs reproducible.
        if options:
            payload["options"] = options
        for attempt in range(self.retries):
            try:
                with httpx.stream(
                    "POST",
                    self.url,
                    json=payload,
                    timeout=self.timeout,
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
            except (httpx.HTTPStatusError, httpx.TimeoutException) as e:
                # Transient server-side errors (5xx) and timeouts happen under
                # memory pressure; back off and retry before giving up.
                if attempt < self.retries - 1:
                    time.sleep(2 * (attempt + 1))
                    continue
                if isinstance(e, httpx.HTTPStatusError):
                    raise RuntimeError(
                        f"AI provider returned HTTP {e.response.status_code}"
                    ) from e
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
                timeout=self.timeout,
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
