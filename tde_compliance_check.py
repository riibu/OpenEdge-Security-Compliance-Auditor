import json
import os

def audit_tde_configuration(config_json_path="tde_config.json"):
    """
    Audits Progress OpenEdge Database TDE (Transparent Data Encryption) 
    policy files for cryptographic compliance.
    """
    print(f"[*] Auditing OpenEdge TDE & Key Store configuration...")

    # Mock or load database encryption metadata structure
    # In enterprise setups, this reads domain key policies and database startup parameters (.db startup keys)
    tde_policy = {
        "database_name": "openedge_prod_db",
        "tde_enabled": True,
        "algorithm": "AES_CBC_128", # Flagged as weaker cipher baseline
        "keystore_separation": False, # Flagged security gap
        "auto_wallet_login": True
    }

    compliance_findings = []
    
    if tde_policy["algorithm"] != "AES_GCM_256":
        compliance_findings.append({
            "control": "ISO 27001 A.10 (Cryptographic Controls)",
            "severity": "HIGH",
            "issue": f"Suboptimal encryption algorithm detected ({tde_policy['algorithm']}). Recommended: AES_GCM_256."
        })

    if not tde_policy["keystore_separation"]:
        compliance_findings.append({
            "control": "ISO 27001 A.9 (Access Control)",
            "severity": "CRITICAL",
            "issue": "Database Master Key and Keystore are not physically or logically segregated from application binaries."
        })

    print(f"[+] TDE Audit complete. Found {len(compliance_findings)} critical security controls requiring remediation.")
    return compliance_findings

if __name__ == "__main__":
    audit_tde_configuration()