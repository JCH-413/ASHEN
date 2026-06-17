import re


BANNED_KEYWORDS = [
    "rm -rf", "delete system", "shutdown",
    "format disk", "malware", "ddos"
]


def _strip_rag_context(response: str) -> str:
    """Remove common RAG/CVE context lines if the model echoes them."""
    cleaned = response
    patterns = [
        r"^\s*Relevant CVE context:\s*$",
        r"^\s*-\s*(CRITICAL|HIGH|MEDIUM|LOW)\s*:\s*.*$",
        r"^\s*Related CVEs\s*:.*$",
        r"^\s*Known vulnerabilities.*$",
        r"^\s*Vulnerabilities found\s*:.*$",
        r"^\s*Reference vulnerabilities\s*:.*$",
        r"^\s*.*\bCVE-\d{4}-\d+\b.*$",
    ]
    for pattern in patterns:
        cleaned = re.sub(pattern, "", cleaned, flags=re.IGNORECASE | re.MULTILINE)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned.strip()


def _check_safety(response):
    """Return blocked message if unsafe content detected, else None."""
    if not response:
        return "No response"
    if any(word in response.lower() for word in BANNED_KEYWORDS):
        return "⚠️ Unsafe content detected. Response blocked."
    return None


def filter_response(response):
    """Filter for attack recommendation responses (strict keyword filtering)."""
    blocked = _check_safety(response)
    if blocked:
        return blocked

    lines = response.split("\n")

    explanation = ""
    bullets = []

    for line in lines:
        line = line.strip()

        if not line:
            continue

        # Remove links
        if "http" in line or "www" in line:
            continue

        # Remove "attack technique 1" etc
        if "attack technique" in line.lower():
            continue

        # Remove numbering prefix
        if line.startswith("-"):
            line = line[1:].strip()

        if line and line[0].isdigit():
            line = line.split(".", 1)[-1].strip()

        # Short explanation (only first small line)
        if not explanation and len(line.split()) <= 12:
            explanation = line
            continue

        # Strict attack filter
        if any(word in line.lower() for word in [
            "ftp", "brute", "login", "mitm", "dos"
        ]):
            bullets.append(f"- {line}")

    output = ""

    if explanation:
        output += explanation + "\n\n"

    if bullets:
        output += "\n".join(bullets)

    return output.strip() if output else "No valid attacks found"


def filter_attack_response(response):
    """Filter for attack recommendation responses — preserves structured plan,
    only blocks unsafe material and removes links."""
    response = _strip_rag_context(response) if response else response

    blocked = _check_safety(response)
    if blocked:
        return blocked

    cleaned_lines = []
    for line in response.split("\n"):
        stripped = line.strip()

        # Remove lines that are only links
        if stripped and all(
            part.startswith("http") or part.startswith("www")
            for part in stripped.split()
            if part
        ):
            continue

        # Inline: strip URLs but keep the rest of the line
        words = line.split()
        filtered_words = [w for w in words if not w.startswith("http") and not w.startswith("www.")]
        if words and not filtered_words:
            continue
        cleaned_lines.append(" ".join(filtered_words) if filtered_words != words else line)

    result = "\n".join(cleaned_lines).strip()
    return result if result else "No attack recommendations could be generated."


def filter_remediation_response(response):
    """Filter for remediation responses — preserves structured content,
    only blocks unsafe material and removes links."""
    blocked = _check_safety(response)
    if blocked:
        return blocked

    cleaned_lines = []
    for line in response.split("\n"):
        stripped = line.strip()

        # Remove lines that are only links
        if stripped and all(
            part.startswith("http") or part.startswith("www")
            for part in stripped.split()
            if part
        ):
            continue

        # Inline: strip URLs but keep the rest of the line
        words = line.split()
        filtered_words = [w for w in words if not w.startswith("http") and not w.startswith("www.")]
        if words and not filtered_words:
            continue  # line was only URLs
        cleaned_lines.append(" ".join(filtered_words) if filtered_words != words else line)

    result = "\n".join(cleaned_lines).strip()
    return result if result else "No remediation guidance could be generated."