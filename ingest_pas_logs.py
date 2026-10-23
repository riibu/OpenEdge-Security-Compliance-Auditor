import os
import json
import chromadb
from chromadb.utils import embedding_functions

def ingest_live_pas_logs(vector_db_path="./chroma_db"):
    """
    Simulates or polls live PAS for OpenEdge management/security logs 
    and indexes them into the ChromaDB compliance vault.
    """
    print("[*] Connecting to PAS for OpenEdge management/monitoring endpoints...")

    # Simulated real-time security events captured from a live PASOE instance
    # In a production setup, you would replace this with a requests.get() call to your PASOE REST API.
    live_pas_events = [
        {
            "id": "pas_live_001",
            "content": "PASOE Agent Security Warning: Unauthorized HTTP TRACE method attempt detected on transport adapter /apsv from IP 192.168.10.55. Action: Blocked by security interceptor.",
            "source": "pas_oe_live_telemetry"
        },
        {
            "id": "pas_live_002",
            "content": "PASOE Session Alert: Maximum multi-session agent pool utilization reached (95%). Potential resource exhaustion vector identified on OE broker port 8810.",
            "source": "pas_oe_live_telemetry"
        },
        {
            "id": "pas_live_003",
            "content": "PASOE Client TLS Handshake Error: Weak cipher suite TLS_RSA_WITH_AES_128_CBC_SHA requested by connecting legacy client. Connection rejected per ISO 27001 transport encryption baseline.",
            "source": "pas_oe_live_telemetry"
        }
    ]

    # Connect to persistent ChromaDB
    if not os.path.exists(vector_db_path):
        raise FileNotFoundError(f"Vector DB path '{vector_db_path}' not found. Initialize environment first.")

    chroma_client = chromadb.PersistentClient(path=vector_db_path)
    embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )
    collection = chroma_client.get_or_create_collection(
        name="openedge_compliance_vault",
        embedding_function=embedding_fn
    )

    # Prepare batch data for ChromaDB insertion
    ids = [event["id"] for event in live_pas_events]
    documents = [event["content"] for event in live_pas_events]
    metadatas = [{"source": event["source"]} for event in live_pas_events]

    # Upsert or add into collection so we don't duplicate IDs if run multiple times
    collection.upsert(
        documents=documents,
        metadatas=metadatas,
        ids=ids
    )

    print(f"[+] Successfully ingested {len(ids)} live PAS for OpenEdge security events into ChromaDB!")
    return len(ids)

if __name__ == "__main__":
    ingest_live_pas_logs()