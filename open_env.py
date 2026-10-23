import os
import json
import urllib.request
import urllib.error
import chromadb
from chromadb.utils import embedding_functions

class OpenEdgeAuditEnv:
    """
    Advanced Agentic RAG OpenEnv interface wrapper backed by ChromaDB vector search.
    """
    def __init__(self, vector_db_path="./chroma_db", ollama_url="http://localhost:11434/api/generate", model_name="llama3.1"):
        self.vector_db_path = vector_db_path
        self.ollama_url = ollama_url
        self.model_name = model_name
        self.chroma_client = None
        self.collection = None
        self.current_state = None
        self.on_chunk_received = None  # Live GUI streaming callback

    def reset(self):
        """Initializes connection to the ChromaDB vector store and returns expected counts."""
        if not os.path.exists(self.vector_db_path):
            raise FileNotFoundError(f"Vector DB path '{self.vector_db_path}' not found. Run ingest_audit.py first.")
        
        # Connect to persistent ChromaDB
        self.chroma_client = chromadb.PersistentClient(path=self.vector_db_path)
        embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
        self.collection = self.chroma_client.get_or_create_collection(
            name="openedge_compliance_vault",
            embedding_function=embedding_fn
        )
        
        count = self.collection.count()
        self.current_state = {
            "status": "READY",
            "audit_log_count": count,
            "baseline_count": count  # Added baseline_count to satisfy GUI expectations
        }
        return self.current_state

    def step(self, action_query: str) -> dict:
        """
        Performs semantic similarity search against ChromaDB, builds a targeted context,
        and streams the evaluation report from Llama 3.1.
        """
        if not self.collection:
            self.reset()

        # 1. SEMANTIC SEARCH: Query ChromaDB for the most relevant context chunks (top_k=3)
        search_results = self.collection.query(
            query_texts=[action_query],
            n_results=3
        )
        
        retrieved_chunks = search_results.get("documents", [[]])[0]
        context_text = "\n\n".join(retrieved_chunks) if retrieved_chunks else "No relevant context found."

        # 2. CONSTRUCT PROMPT with targeted context
        prompt = f"""You are an expert OpenEdge Security and Compliance Auditor. 
Your task is to evaluate system audit findings against the retrieved compliance standards.

### Retrieved Context / Knowledge Base Snippets:
{context_text}

### Target Audit Finding / Question:
{action_query}

Provide your evaluation structured precisely into:
1. Risk Assessment
2. Compliance Impact (ISO 27001 References)
3. Actionable Remediation Steps
"""

        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": True,
            "options": {"temperature": 0.1}
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.ollama_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=300.0) as response:
                full_report = ""
                for line in response:
                    if line:
                        chunk = json.loads(line.decode("utf-8"))
                        text_chunk = chunk.get("response", "")
                        full_report += text_chunk
                        
                        if self.on_chunk_received:
                            self.on_chunk_received(text_chunk)
                            
                return {"success": True, "report": full_report, "error": None}
                
        except urllib.error.URLError as e:
            return {"success": False, "report": None, "error": f"URLError: {e.reason}"}
        except Exception as e:
            return {"success": False, "report": None, "error": str(e)}