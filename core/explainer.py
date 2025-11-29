# core/explainer.py

def explain_functions(function_names):
    """
    Dummy explanation generator for now.
    """
    known = {
        "main": "Main function where execution starts.",
        "keylogger": "Records keystrokes from the user.",
        "send_data": "Sends stolen data to a remote server.",
        "backdoor": "Creates a hidden access point for attackers."
    }

    explanation = ""
    for func in function_names:
        explanation += f"{func}: {known.get(func, 'No description available.')}\n"

    return explanation
