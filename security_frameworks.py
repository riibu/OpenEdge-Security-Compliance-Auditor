# security_frameworks.py

SECURITY_DOMAINS_KNOWLEDGE = [
    {
        "id": "framework_pentest",
        "category": "Penetration Testing",
        "content": """
        PENETRATION TESTING FRAMEWORK (OWASP / MITRE ATT&CK):
        - Methodology: Reconnaissance, Enumeration, Vulnerability Analysis, Exploitation, Post-Exploitation, Reporting.
        - OpenEdge Specific Vectors: Unauthenticated AdminServer ports (9090, 18000), exposed database broker ports (_mprosrv), weak SQL-92 credentials in _sql_user, PASOE REST API injection points.
        - Output Structure Requirement: 
          1. Vulnerability Title & ID
          2. CVSS v3.1 Score & Vector
          3. Affected Component / Endpoint
          4. Technical Proof of Concept (PoC) / Simulation Log
          5. Actionable Remediation & Patch Code
        """
    },
    {
        "id": "framework_vuln_assessment",
        "category": "Vulnerability Assessment",
        "content": """
        VULNERABILITY ASSESSMENT FRAMEWORK:
        - Asset Discovery & Classification: Identify open ports, outdated software versions, missing security patches.
        - OpenEdge Vulnerability Baselines: Check against known CVEs for OpenSSL, Progress Application Server (PASOE), and underlying Java/Tomcat components.
        - Severity Classification: Critical (9.0-10.0), High (7.0-8.9), Medium (4.0-6.9), Low (0.1-3.9).
        """
    },
    {
        "id": "framework_risk_analysis",
        "category": "Risk Analysis",
        "content": """
        QUANTITATIVE & QUALITATIVE RISK ANALYSIS (NIST SP 800-30):
        - Likelihood Evaluation: Low, Medium, High based on threat actor capability and exploit availability.
        - Impact Evaluation: Financial, Operational, and Reputational impact on core enterprise database assets.
        - Risk Level Matrix: Likelihood x Impact -> Final Risk Score (Critical, High, Medium, Low) for executive board reporting.
        """
    },
    {
        "id": "framework_dfir",
        "category": "Digital Forensics & Incident Response",
        "content": """
        DFIR LIFECYCLE (SANS / NIST SP 800-61):
        1. Preparation: Logging, telemetry collection (PASOE broker logs, Windows Event Logs).
        2. Identification: Anomaly detection, unauthorized authentication spikes, abnormal API requests.
        3. Containment: Network isolation, service termination, credential revocation.
        4. Eradication: Malware removal, patch deployment, configuration hardening.
        5. Recovery: System restoration, integrity verification.
        6. Lessons Learned: Post-incident review and policy updates.
        - Incident Report Structure: Executive Summary, Chronological Attack Timeline, Indicators of Compromise (IOCs), Containment Actions, and Preventive Recommendations.
        """
    }
]

def ingest_frameworks_into_vault():
    """Ingests professional pentesting, vulnerability, risk, and DFIR frameworks into ChromaDB."""
    import chromadb
    from chromadb.utils import embedding_functions

    chroma_client = chromadb.PersistentClient(path="./chroma_db")
    embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
    collection = chroma_client.get_or_create_collection(name="openedge_compliance_vault", embedding_function=embedding_fn)

    documents = [d["content"] for d in SECURITY_DOMAINS_KNOWLEDGE]
    metadatas = [{"source": f"framework:{d['category']}"} for d in SECURITY_DOMAINS_KNOWLEDGE]
    ids = [d["id"] for d in SECURITY_DOMAINS_KNOWLEDGE]

    collection.add(documents=documents, metadatas=metadatas, ids=ids)
    print("[+] Professional Security Frameworks ingested successfully into ChromaDB!")
    return len(SECURITY_DOMAINS_KNOWLEDGE)