# knowledge_vault.py
import uuid
import chromadb
from chromadb.utils import embedding_functions

def record_knowledge(content: str, category: str, title: str = "Learned Insight"):
    """
    Saves new audit findings, analyst notes, or generated responses back into 
    ChromaDB so the platform can recall them in future queries and compliance checks.
    """
    try:
        chroma_client = chromadb.PersistentClient(path="./chroma_db")
        embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
        collection = chroma_client.get_or_create_collection(
            name="openedge_compliance_vault", 
            embedding_function=embedding_fn
        )
        
        # Create a unique ID and metadata tag for the learned knowledge
        doc_id = f"dynamic_insight_{category}_{uuid.uuid4().hex[:8]}"
        metadata = {
            "source": f"learned_knowledge:{category}",
            "title": title
        }
        
        collection.add(
            documents=[content],
            metadatas=[metadata],
            ids=[doc_id]
        ]
        print(f"[+] Successfully saved new knowledge to ChromaDB vault: [{title}]")
        return True
    except Exception as e:
        print(f"[!] Failed to record knowledge: {str(e)}")
        return False