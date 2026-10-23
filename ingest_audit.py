import os
import json

# Configuration constants
JSON_AUDIT_FILE = "security_audit_export.json"
KNOWLEDGE_BASE_DIR = "./knowledge_base"
OUTPUT_INDEX_FILE = "./vector_store_mock.json"

def main():
    print("--- OpenEdge Security & Compliance Auditor: Lightweight Ingestion Pipeline ---")
    
    documents = []

    # 1. Load OpenEdge ABL JSON audit logs
    if os.path.exists(JSON_AUDIT_FILE):
        with open(JSON_AUDIT_FILE, "r", encoding="utf-8") as f:
            events = json.load(f)
        print(f"[*] Loaded {len(events)} security audit events from {JSON_AUDIT_FILE}...")
        
        for event in events:
            content = (
                f"Security Audit Event ID: {event.get('event_id')}\n"
                f"User: {event.get('user_name')}\n"
                f"Action Type: {event.get('action_type')}\n"
                f"Timestamp: {event.get('timestamp')}\n"
                f"Details: {event.get('details')}"
            )
            documents.append({
                "source": "openedge_audit_log",
                "id": event.get('event_id'),
                "content": content
            })
    else:
        print(f"[!] Warning: {JSON_AUDIT_FILE} not found.")

    # 2. Load Compliance Knowledge Base (.md files)
    if os.path.exists(KNOWLEDGE_BASE_DIR):
        print(f"[*] Loading compliance baselines from {KNOWLEDGE_BASE_DIR}...")
        for filename in os.listdir(KNOWLEDGE_BASE_DIR):
            if filename.endswith(".md"):
                path = os.path.join(KNOWLEDGE_BASE_DIR, filename)
                with open(path, "r", encoding="utf-8") as f:
                    text = f.read()
                documents.append({
                    "source": "compliance_baseline",
                    "id": filename,
                    "content": text
                })
    else:
        print(f"[!] Warning: Knowledge base directory not found.")

    if not documents:
        print("[!] Error: No documents found to ingest.")
        return

    # 3. Save to local searchable index file
    os.makedirs(os.path.dirname(OUTPUT_INDEX_FILE), exist_ok=True)
    with open(OUTPUT_INDEX_FILE, "w", encoding="utf-8") as f:
        json.dump(documents, f, indent=4)

    print(f"[+] Success! Indexed {len(documents)} documents into {OUTPUT_INDEX_FILE}.")
    print("--- Ingestion Complete ---")

if __name__ == "__main__":
    main()