def filter_response(response):
    if not response:
        return "No response"

    # 🔴 BLOCK unsafe content
    banned_keywords = [
        "rm -rf", "delete system", "shutdown",
        "format disk", "malware", "ddos"
    ]

    if any(word in response.lower() for word in banned_keywords):
        return "⚠️ Unsafe content detected. Response blocked."

    lines = response.split("\n")

    explanation = ""
    bullets = []

    for line in lines:
        line = line.strip()

        if not line:
            continue

        # ❌ REMOVE LINKS
        if "http" in line or "www" in line:
            continue

        # ❌ REMOVE "attack technique 1" etc
        if "attack technique" in line.lower():
            continue

        # ❌ REMOVE numbering
        if line.startswith("-"):
            line = line[1:].strip()

        if line and line[0].isdigit():
            line = line.split(".", 1)[-1].strip()

        # 🟢 SHORT EXPLANATION (only first small line)
        if not explanation and len(line.split()) <= 12:
            explanation = line
            continue

        # 🟢 STRICT ATTACK FILTER
        if any(word in line.lower() for word in [
            "ftp", "brute", "login", "mitm", "dos"
        ]):
            bullets.append(f"- {line}")

    # 🟢 FINAL OUTPUT
    output = ""

    if explanation:
        output += explanation + "\n\n"

    if bullets:
        output += "\n".join(bullets)

    return output.strip() if output else "No valid attacks found"