from .governance_logger import log_event

def handle_feedback(prompt, response, action):
    """
    action = accept / reject / regenerate
    """

    if action == "accept":
        log_event(prompt, response, action="accepted")
        return " Response accepted"

    elif action == "reject":
        log_event(prompt, response, action="rejected")
        return "Response rejected"

    elif action == "regenerate":
        log_event(prompt, response, action="regenerated")
        return " Regenerating response..."

    else:
        return "Invalid action"