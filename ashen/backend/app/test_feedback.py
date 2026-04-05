from app.services.feedback_service import handle_feedback

prompt = "Open port 21 FTP detected"
response = "- FTP brute force attack"

print(handle_feedback(prompt, response, "accept"))
print(handle_feedback(prompt, response, "reject"))
print(handle_feedback(prompt, response, "regenerate"))