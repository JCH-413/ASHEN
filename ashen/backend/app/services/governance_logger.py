import json
from datetime import datetime

LOG_FILE = "ai_logs.json"

def log_event(prompt, response, action="generated"):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "prompt": prompt,
        "response": response,
        "action": action
    }

    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"Logging failed: {str(e)}")