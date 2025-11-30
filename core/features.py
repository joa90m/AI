# features.py
import os
import re
import pefile
import lief
import zipfile
lief.logging.disable()

from .parser import extract_python_features, extract_functions
from .archive_tools import extract_from_archive
PRIMARY_FEATURES = [
    'HTTP', 'FTP', 'SMTP', 'DNS',
    'os.system', 'subprocess', 'eval', 'exec', 'open',
    'socket', 'shutil', 'ctypes', 'getenv'
]
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

def extract_assembly(binary):
    assembly = []

    try:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for insn in md.disasm(binary, 0x1000):
            assembly.append(f"{insn.mnemonic} {insn.op_str}")

        if not assembly:  # Try 32-bit
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            for insn in md.disasm(binary, 0x1000):
                assembly.append(f"{insn.mnemonic} {insn.op_str}")

    except Exception:
        pass

    return assembly

def extract_features_from_file(file_path):
    """
    Extract features from any file type.
    Python: functions, imports, calls
    Archives: recursively extract contained files
    Binaries: imports, strings, protocols, low-level instructions
    """
    ext = os.path.splitext(file_path)[-1].lower()

    if ext == ".py":
        return _extract_python(file_path)
    elif ext in [".zip", ".tar", ".tar.gz", ".tgz"]:
        return extract_from_archive(file_path)
    elif ext in [".exe", ".dll", ".elf", ".so", ".msi"]:
        return extract_features_from_binary(file_path)
    else:
        # Attempt generic binary analysis
        return extract_features_from_binary(file_path)


def _extract_python(file_path):
    """Extract Python-specific features"""
    try:
        with open(file_path, "r", errors="ignore") as f:
            code = f.read()
            features = extract_python_features(code)
            features['functions'] = extract_functions(code)
            features['imports'] = _extract_python_imports(code)
            features['params'] = _extract_function_params(code)
            return features
    except Exception:
        return {}


def _extract_python_imports(code):
    """Return a list of imported modules"""
    imports = re.findall(r'^\s*import (\S+)|^\s*from (\S+) import', code, re.MULTILINE)
    return list({m for tup in imports for m in tup if m})


def _extract_function_params(code):
    """Return a dict of function names and their parameters"""
    funcs = re.findall(r'def (\w+)\((.*?)\):', code)
    return {name: params.split(',') if params else [] for name, params in funcs}


def extract_features_from_binary(path):
    """
    Safe, consistent binary feature extractor.
    NEVER returns ellipsis (...) and ALWAYS returns all fields.
    """
    features = {
        "protocols": [],
        "permissions": [],
        "files": [],
        "strings": [],
        "imports": [],
        "assembly": []
    }

    try:
        with open(path, "rb") as f:
            content = f.read()
            text = content.decode(errors="ignore")

        # --- Strings ---
        features["strings"] = _extract_strings(content)

        # --- Imports ---
        features["imports"] = _extract_imports(path)

        # --- Assembly ---
        asm = extract_assembly(content)
        if asm:
            features["assembly"] = asm[:200]  # limit for safety

        # --- Protocol detection in strings ---
        protocols = []
        if "http" in text.lower(): protocols.append("HTTP")
        if "ftp" in text.lower(): protocols.append("FTP")
        if "smtp" in text.lower(): protocols.append("SMTP")
        if "dns" in text.lower(): protocols.append("DNS")

        features["protocols"] = protocols

        return features

    except Exception as e:
        print(f"[!] Binary extraction error: {e}")
        return features  # return safe empty structure


PE_HEADER_STRINGS = {
    "!This program cannot be run in DOS mode.",
    ".text", ".data", ".rdata", ".pdata", ".xdata", ".rsrc",
    ".reloc", ".bss", ".idata"
}

def is_ignored_string(s):
    if s in PE_HEADER_STRINGS:
        return True
    if len(s) < 4:
        return True
    # skip pure hex / offsets
    if all(c in "0123456789ABCDEFabcdef" for c in s.strip()):
        return True
    return False

def _extract_strings(binary_data, min_len=4):
    result = []
    current = ""

    for b in binary_data:
        if 32 <= b <= 126:
            current += chr(b)
        else:
            if len(current) >= min_len and not is_ignored_string(current):
                result.append(current)
            current = ""

    if len(current) >= min_len and not is_ignored_string(current):
        result.append(current)

    return result



def _extract_imports(file_path):
    """Extract imported functions and libraries from EXE/ELF"""
    imports = []
    try:
        ext = os.path.splitext(file_path)[-1].lower()
        if ext in [".exe", ".dll", ".msi"]:
            pe = pefile.PE(file_path)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    imports.append(entry.dll.decode())
        elif ext in [".elf", ".so"]:
            elf = lief.parse(file_path)
            if elf:
                imports = [lib for lib in elf.libraries]
    except Exception:
        pass
    return imports
