import os
import json
import urllib.request
import urllib.error
import chromadb
from chromadb.utils import embedding_functions

class OpenEdgeAuditEnv:
    """
    Advanced Agentic RAG OpenEnv interface wrapper featuring a Multi-Step ReAct 
    (Reason + Act) loop backed by ChromaDB vector search and Llama 3.1.
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
            "baseline_count": count
        }
        return self.current_state

    def _query_ollama(self, prompt: str) -> str:
        """Helper to send prompt to local Ollama instance and stream chunks."""
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

        full_response = ""
        with urllib.request.urlopen(req, timeout=300.0) as response:
            for line in response:
                if line:
                    chunk = json.loads(line.decode("utf-8"))
                    text_chunk = chunk.get("response", "")
                    full_response += text_chunk
                    if self.on_chunk_received:
                        self.on_chunk_received(text_chunk)
        return full_response

    def step(self, action_query: str) -> dict:
        """
        Executes a Multi-Step ReAct (Reason + Act) loop:
        Step 1: Initial Investigation & Vector Search
        Step 2: Deep-Dive Cross-Reference Search based on initial findings
        Step 3: Comprehensive Synthesis & Final Compliance Report
        """
        if not self.collection:
            self.reset()

        try:
            # --- REACT STEP 1: INITIAL INVESTIGATION ---
            if self.on_chunk_received:
                self.on_chunk_received(f"\n--- [ReAct Step 1/3] Initial Vector Search for: '{action_query}' ---\n")
            
            search_results_1 = self.collection.query(query_texts=[action_query], n_results=2)
            context_1 = "\n\n".join(search_results_1.get("documents", [[]])[0]) or "No initial context found."

            prompt_1 = f"""You are an expert OpenEdge Security and Compliance Auditor operating in a ReAct loop.
Target Audit Query: {action_query}

Retrieved Evidence (Step 1):
{context_1}

Analyze this evidence. Formulate a brief Thought and identify if a secondary investigation (e.g., checking compliance baselines or specific privilege rules) is required.
"""
            thought_1 = self._query_ollama(prompt_1)

            # --- REACT STEP 2: DEEP-DIVE CROSS-REFERENCE ---
            if self.on_chunk_received:
                self.on_chunk_received(f"\n\n--- [ReAct Step 2/3] Deep-Dive Compliance Cross-Reference ---\n")

            # Use the initial findings or original query to pull compliance baseline context
            secondary_query = f"ISO 27001 security controls and remediation for {action_query}"
            search_results_2 = self.collection.query(query_texts=[secondary_query], n_results=2)
            context_2 = "\n\n".join(search_results_2.get("documents", [[]])[0]) or "No compliance rules found."

            prompt_2 = f"""Previous Analysis Thought: {thought_1}

Retrieved Compliance Standards (Step 2):
{context_2}

Synthesize these findings. Cross-reference the audit events against the ISO 27001 baseline standards retrieved above.
"""
            thought_2 = self._query_ollama(prompt_2)

            # --- REACT STEP 3: FINAL REPORT GENERATION ---
            if self.on_chunk_received:
                self.on_chunk_received(f"\n\n--- [ReAct Step 3/3] Generating Final Validated Audit Report ---\n")

            final_prompt = f"""You are an elite Chief Information Security Officer (CISO). Based on the multi-step investigation below, generate the final executive compliance report.

### Investigation History:
- Initial Query: {action_query}
- Step 1 Evidence: {context_1}
- Step 2 Evidence: {context_2}

Provide your final report structured precisely into:
1. Executive Summary & Risk Rating
2. Detailed Findings & Log Evidence
3. ISO 27001 Compliance Gaps
4. Actionable Remediation Roadmap
"""
            final_report = self._query_ollama(final_prompt)

            return {"success": True, "report": final_report, "error": None}

        except urllib.error.URLError as e:
            return {"success": False, "report": None, "error": f"URLError: {e.reason}"}
        except Exception as e:
            return {"success": False, "report": None, "error": str(e)}