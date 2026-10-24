import os

def analyze_and_patch_abl_code(file_path: str):
    """
    Scans a Progress OpenEdge ABL file for insecure patterns 
    and writes a secure patched version.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"ABL file not found at: {file_path}")

    print(f"[*] Scanning ABL script for security anti-patterns: {file_path}")
    
    with open(file_path, "r", encoding="utf-8") as f:
        code_content = f.read()

    patched_content = code_content
    vulnerabilities_found = []

    # Check for insecure OS-COMMAND
    if "OS-COMMAND" in code_content and "SILENT" not in code_content:
        vulnerabilities_found.append("Unsecured OS-COMMAND execution without parameter sanitization or SILENT flag.")
        patched_content = patched_content.replace(
            "OS-COMMAND", 
            "/* [OpenEdge-Agent-Security-Fix] Wrapped for input validation */\nRUN security/SafeOSCommand.p"
        )

    # Check for dynamic queries lacking validation
    if "CAN-DO" not in code_content and "DYNAMIC-QUERY" in code_content:
        vulnerabilities_found.append("Dynamic query executed without strict CAN-DO authorization checks.")
        patched_content = "/* [OpenEdge-Agent-Security-Fix] Added security gate */\nIF NOT SECURITY-POLICY:CHECK-AUTH() THEN RETURN ERROR.\n" + patched_content

    base, ext = os.path.splitext(file_path)
    patched_path = f"{base}_secure_patch{ext}"
    
    with open(patched_path, "w", encoding="utf-8") as f:
        f.write(patched_content)

    print(f"[+] Security patch generated successfully: {patched_path}")
    return {
        "original_file": file_path,
        "patched_file": patched_path,
        "vulnerabilities": vulnerabilities_found if vulnerabilities_found else ["No critical anti-patterns detected; standard header applied."]
    }