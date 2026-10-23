import os
import json
import chromadb
from chromadb.utils import embedding_functions

def run_ingestion():
    print("[*] Starting advanced semantic ingestion pipeline...")
    
    # Define paths
    vector_db_path = "./chroma_db"
    mock_source_path = "./vector_store_mock.json" # Fallback or original source data
    
    # Initialize ChromaDB client (Persists locally to disk)
    chroma_client = chromadb.PersistentClient(path=vector_db_path)
    
    # Use a lightweight local embedding function (downloads automatically on first run)
    embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )
    
    # Create or get collection
    collection = chroma_client.get_or_create_collection(
        name="openedge_compliance_vault",
        embedding_function=embedding_fn
    )
    
    # Load source documents (checking your mock json or knowledge base)
    documents_to_ingest = []
    
    if os.path.exists(mock_source_path):
        with open(mock_source_path, "r", encoding="utf-8") as f:
            raw_docs = json.load(f)
            for idx, doc in enumerate(raw_docs):
                documents_to_ingest.append({
                    "id": f"doc_{idx}",
                    "content": doc.get("content", ""),
                    "source": doc.get("source", "unknown")
                })
    else:
        # Fallback sample data if mock file isn't present
        documents_to_ingest = [
            {"id": "doc_0", "content": "SEC-1001: Failed SSH login attempts detected from external IP 192.168.1.105 exceeding threshold.", "source": "openedge_audit_log"},
            {"id": "doc_1", "content": "SEC-1003: Unauthorized read access attempt on sensitive /etc/shadow backup file.", "source": "openedge_audit_log"},
            {"id": "doc_2", "content": "ISO 27001 A.9.4.2: Secure log-on procedures must be enforced with Multi-Factor Authentication (MFA) and strict subnet restrictions.", "source": "compliance_baseline"}
        ]

    # Clear existing collection items to prevent duplication on re-run
    existing = collection.get()
    if existing["ids"]:
        collection.delete(ids=existing["ids"])

    # Add documents to ChromaDB
    ids = [d["id"] for d in documents_to_ingest]
    texts = [d["content"] for d in documents_to_ingest]
    metadatas = [{"source": d["source"]} for d in documents_to_ingest]

    collection.add(
        documents=texts,
        metadatas=metadatas,
        ids=ids
    )

    print(f"[+] Successfully embedded and stored {len(ids)} chunks into ChromaDB vector store at '{vector_db_path}'!")

if __name__ == "__main__":
    run_ingestion()