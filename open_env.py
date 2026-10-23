import os
import json
import urllib.request
import urllib.error

class OpenEdgeAuditEnv:
    """
    OpenEnv interface wrapper for OpenEdge Security & Compliance Audit environment.
    Follows agentic environment conventions (reset, step, render).
    """
    def __init__(self, vector_store_path="./vector_store_mock.json", ollama_url="http://localhost:11434/api/generate", model_name="llama3.1"):
        self.vector_store_path = vector_store_path
        self.ollama_url = ollama_url
        self.model_name = model_name
        self.documents = []
        self.current_state = None
        self.on_chunk_received = None  # Callback function for live UI streaming

    def reset(self):
        """Resets and loads environment observations from vector store index."""
        if not os.path.exists(self.vector_store_path):
            raise FileNotFoundError(f"Index file '{self.vector_store_path}' not found. Run ingest_audit.py first.")
        
        with open(self.vector_store_path, "r", encoding="utf-8") as f:
            self.documents = json.load(f)
            
        audit_logs = [d for d in self.documents if d["source"] == "openedge_audit_log"]
        baselines = [d for d in self.documents if d["source"] == "compliance_baseline"]

        self.current_state = {
            "status": "READY",
            "audit_log_count": len(audit_logs),
            "baseline_count": len(baselines),
            "context_text": "\n\n".join([d["content"] for d in self.documents])
        }
        return self.current_state

    def step(self, action_query: str) -> dict:
        """
        Executes an agent action (query) against the environment state and LLM model with live streaming.
        """
        if not self.current_state:
            self.reset()

        prompt = f"""You are an expert OpenEdge Security and Compliance Auditor. 
Your task is to evaluate system audit findings against the provided compliance standards.

### Context / Knowledge Base:
{self.current_state['context_text']}

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
            "stream": True,  # <--- Enabled streaming for real-time output & zero timeouts
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
            # Generous timeout for initial model prompt processing across the VM bridge
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
        except TimeoutError:
            return {"success": False, "report": None, "error": "Connection timed out waiting for Llama 3.1 model response."}
        except Exception as e:
            return {"success": False, "report": None, "error": str(e)}
                
        except urllib.error.URLError as e:
            return {"success": False, "report": None, "error": f"Ollama Connection Error: {e.reason}"}
        except Exception as e:
            return {"success": False, "report": None, "error": str(e)}