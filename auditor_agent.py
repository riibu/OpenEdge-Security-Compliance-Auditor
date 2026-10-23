import os
import json
import urllib.request
import urllib.error

# Configuration constants
VECTOR_STORE_FILE = "./vector_store_mock.json"
OLLAMA_API_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.1"

class AuditorAgent:
    def __init__(self, index_path=VECTOR_STORE_FILE):
        self.index_path = index_path
        self.context = self.load_vector_store()

    def load_vector_store(self) -> list:
        """Loads the indexed documents from our local vector store mock."""
        if not os.path.exists(self.index_path):
            return []
        with open(self.index_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def run_audit(self, target_question: str) -> str:
        """Executes the agent evaluation against local Llama 3.1."""
        documents = self.load_vector_store()
        if not documents:
            return "[!] Error: No documents found in vector store. Please run ingestion first."

        context_text = "\n\n".join([doc.get("content", "") for doc in documents])

        prompt = f"""You are an expert OpenEdge Security and Compliance Auditor. 
Your task is to evaluate system audit findings against the provided compliance standards.

### Context / Knowledge Base:
{context_text}

### Target Audit Finding:
{target_question}

Provide your evaluation structured precisely into:
1. Risk Assessment
2. Compliance Impact (ISO 27001 References)
3. Actionable Remediation Steps
"""

        payload = {
            "model": MODEL_NAME,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1  # Low temperature for analytical consistency
            }
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            OLLAMA_API_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=600.0) as response:
                if response.status == 200:
                    response_body = json.loads(response.read().decode("utf-8"))
                    return response_body.get("response", "No response field returned.")
                else:
                    return f"[!] Error from Ollama API: HTTP {response.status}"
        except urllib.error.HTTPError as error:
            return f"[!] Error from Ollama API: HTTP {error.code}"
        except urllib.error.URLError as error:
            return f"[!] Could not connect to Ollama API: {error.reason}"

if __name__ == "__main__":
    # Standalone CLI test mode
    agent = AuditorAgent()
    print("--- OpenEdge Security & Compliance Auditor: Agentic RAG Engine ---")
    query = "Analyze the high-severity security events (such as SEC-1001 failed SSH login and SEC-1003 unauthorized file access) against our ISO 27001 compliance baselines."
    print(agent.run_audit(query))