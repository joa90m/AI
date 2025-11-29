# core/deobfuscator.py

def explain_code(code):
    """
    Provide a basic explanation of code logic.
    Only works for Python source files.

    Args:
        code (str): Raw source code string.

    Returns:
        str: Human-readable explanation of logic.
    """
    if "os.system" in code or "subprocess" in code:
        return "This code executes system commands."
    elif "socket" in code:
        return "This code uses networking (e.g., sending/receiving data)."
    elif "open(" in code and "write" in code:
        return "This code writes data to a file."
    elif "eval(" in code or "exec(" in code:
        return "This code dynamically executes code – possible obfuscation or injection."
    else:
        return "No obvious malicious behavior found. Static analysis only."
