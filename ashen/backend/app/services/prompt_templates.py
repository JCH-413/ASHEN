def build_attack_prompt(data, cve_context=""):
    cve_block = ""
    if cve_context:
        cve_block = f"""\nRelevant CVE context:\n{cve_context}\n"""

    return f"""You are an exploit recommender. Given scan results and available exploits, list ONLY the exploits that match open ports. Order by priority: critical/high severity first, then medium, then low.

For each match write one line: priority number, port, exploit name, and why.

{cve_block}

{data}

Exploitation Order:

1."""

def build_remediation_prompt(data):
    return f"""You are a cybersecurity remediation expert. Your task is to write actionable fix instructions.

IMPORTANT: Do NOT repeat the vulnerability data below. Only output remediation steps.

Respond using EXACTLY this format:

## Root Cause
Why this vulnerability exists (2-3 sentences).

## Immediate Containment
- Steps to limit exposure right now

## Permanent Fix
- Concrete steps to fully resolve the vulnerability

## Validation
- How to confirm the fix worked

## Hardening
- Prevent recurrence

Here is the vulnerability data to remediate:
---
{data}
---

Now write the remediation guidance following the format above. Do NOT echo the data back."""