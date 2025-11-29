import ast

def extract_functions(code):
    """
    Extract function names from Python source code using AST.
    """
    try:
        tree = ast.parse(code)
        return [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    except SyntaxError as e:
        return [f"SyntaxError: {e}"]

def extract_python_features(code):
    """
    Extract basic static features from Python source code.
    Returns a dictionary of binary feature flags.
    """
    features = {
        "os.system": int("os.system" in code),
        "eval": int("eval" in code),
        "exec": int("exec" in code),
        "subprocess": int("subprocess" in code),
        "socket": int("socket" in code),
        "open": int("open" in code),
        "getenv": int("getenv" in code),
        "ctypes": int("ctypes" in code),
        "shutil": int("shutil" in code),
        "HTTP": int("http" in code.lower()),
        "FTP": int("ftp" in code.lower()),
        "SMTP": int("smtp" in code.lower()),
        "DNS": int("dns" in code.lower()),
    }
    return features
