from app.services.remediation_service import get_remediation

result = get_remediation("Open port 22 detected")

print(result)