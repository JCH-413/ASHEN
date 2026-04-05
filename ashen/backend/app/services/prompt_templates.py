def build_attack_prompt(data):
    return f"""
List only attack techniques for this vulnerability:

{data}

Only output like:
- attack 1
- attack 2

No explanation.
"""

def build_remediation_prompt(data):
    return f"""
Provide only short remediation steps for this issue:

{data}

Format:
- step 1
- step 2

No explanation.
"""