import os
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import threading
from pypdf import PdfReader
from docx import Document
import chromadb
from chromadb.utils import embedding_functions

# Import your OpenEnv wrapper
from open_env import OpenEdgeAuditEnv

class OpenEdgeGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("OpenEdge Security & Compliance Auditor (Agentic RAG)")
        self.root.geometry("900x740")
        
        # Initialize OpenEnv
        self.env = OpenEdgeAuditEnv()
        self.last_generated_report = ""

        # --- GUI LAYOUT ---
        
        # Title Label
        title_label = tk.Label(root, text="🛡️ OpenEdge Autonomous Compliance Auditor", font=("Arial", 16, "bold"))
        title_label.pack(pady=8)

        # Control Panel Frame (Primary Buttons: 1, 2, 3)
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=3)

        self.btn_ingest = tk.Button(btn_frame, text="1. Run Data Ingestion", command=self.run_ingestion_thread, bg="#2b5b84", fg="white", font=("Arial", 9, "bold"), width=22)
        self.btn_ingest.grid(row=0, column=0, padx=4, pady=3)

        self.btn_reset = tk.Button(btn_frame, text="2. Reset OpenEnv", command=self.reset_env, bg="#2b845b", fg="white", font=("Arial", 9, "bold"), width=22)
        self.btn_reset.grid(row=0, column=1, padx=4, pady=3)

        self.btn_agent = tk.Button(btn_frame, text="3. Execute Compliance Audit", command=self.run_agent_thread, bg="#845b2b", fg="white", font=("Arial", 9, "bold"), width=24)
        self.btn_agent.grid(row=0, column=2, padx=4, pady=3)

        # Secondary Row (Buttons: 4, 5, 6)
        btn_frame_2 = tk.Frame(root)
        btn_frame_2.pack(pady=3)

        self.btn_pdf = tk.Button(btn_frame_2, text="4. Upload & Ingest PDF", command=self.upload_and_ingest_pdf, bg="#5b2b84", fg="white", font=("Arial", 9, "bold"), width=22)
        self.btn_pdf.grid(row=0, column=0, padx=4, pady=3)

        self.btn_pas = tk.Button(btn_frame_2, text="5. Ingest Live PAS Logs", command=self.run_pas_ingestion, bg="#2b8484", fg="white", font=("Arial", 9, "bold"), width=22)
        self.btn_pas.grid(row=0, column=1, padx=4, pady=3)

        self.btn_export = tk.Button(btn_frame_2, text="6. Export Report (.docx)", command=self.export_report, bg="#842b5b", fg="white", font=("Arial", 9, "bold"), width=24)
        self.btn_export.grid(row=0, column=2, padx=4, pady=3)

        # Third Row (Advanced Enterprise Features: Buttons 7, 8, 9)
        btn_frame_3 = tk.Frame(root)
        btn_frame_3.pack(pady=3)

        self.btn_patch = tk.Button(btn_frame_3, text="7. Patch ABL Code", command=self.run_abl_patch, bg="#845b00", fg="white", font=("Arial", 9, "bold"), width=22)
        self.btn_patch.grid(row=0, column=0, padx=4, pady=3)

        self.btn_tde = tk.Button(btn_frame_3, text="8. Audit TDE Encryption", command=self.run_tde_audit, bg="#005b84", fg="white", font=("Arial", 9, "bold"), width=22)
        self.btn_tde.grid(row=0, column=1, padx=4, pady=3)

        self.btn_api = tk.Button(btn_frame_3, text="9. Launch FastAPI Gateway", command=self.start_fastapi_server, bg="#00845b", fg="white", font=("Arial", 9, "bold"), width=24)
        self.btn_api.grid(row=0, column=2, padx=4, pady=3)

        # --- CUSTOM QUERY INPUT FRAME ---
        query_frame = tk.Frame(root)
        query_frame.pack(fill=tk.X, padx=15, pady=6)

        query_label = tk.Label(query_frame, text="Custom Audit Prompt / Query (Targeting Ingested Docs & Telemetry):", font=("Arial", 9, "bold"), anchor="w")
        query_label.pack(fill=tk.X, pady=2)

        self.query_entry = tk.Entry(query_frame, font=("Consolas", 10), bg="#2d2d2d", fg="#ffffff", insertbackground="white")
        self.query_entry.pack(fill=tk.X, expand=True, ipady=4)
        self.query_entry.insert(0, "Analyze live PASOE security events and vulnerability assessment requirements against ISO 27001 baselines.")

        # Output Terminal Frame (ScrolledText)
        terminal_frame = tk.Frame(root)
        terminal_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=5)

        terminal_label = tk.Label(terminal_frame, text="Execution Terminal & ReAct Audit Log:", font=("Arial", 10, "bold"), anchor="w")
        terminal_label.pack(fill=tk.X, pady=2)

        self.terminal = scrolledtext.ScrolledText(terminal_frame, wrap=tk.WORD, bg="#1e1e1e", fg="#00ffcc", font=("Consolas", 10))
        self.terminal.pack(fill=tk.BOTH, expand=True)

        # Set up streaming callback for OpenEnv
        self.env.on_chunk_received = self.stream_to_terminal

        self.log_to_terminal("[+] System ready. All 9 operational buttons loaded successfully!\n")

    def log_to_terminal(self, message):
        """Helper to write messages to the GUI terminal safely."""
        self.terminal.insert(tk.END, message + "\n")
        self.terminal.see(tk.END)

    def stream_to_terminal(self, text_chunk):
        """Callback function for live streaming text from Llama 3.1 / ReAct steps."""
        self.terminal.insert(tk.END, text_chunk)
        self.terminal.see(tk.END)
        self.root.update_idletasks()

    def run_ingestion_thread(self):
        """Runs base JSON data ingestion in a separate thread."""
        self.terminal.delete("1.0", tk.END)
        self.log_to_terminal("[*] Triggering mock data ingestion pipeline...")
        import ingest_audit
        try:
            ingest_audit.run_ingestion()
            self.log_to_terminal("[+] Ingestion successful! ChromaDB vector store updated.")
            messagebox.showinfo("Success", "Data ingestion completed successfully!")
        except Exception as e:
            self.log_to_terminal(f"[!] Ingestion Error: {str(e)}")
            messagebox.showerror("Error", str(e))

    def reset_env(self):
        """Resets and connects the OpenEnv wrapper to ChromaDB."""
        try:
            state = self.env.reset()
            self.log_to_terminal("[+] OpenEnv Reset Successful!")
            self.log_to_terminal(f"    - Loaded Audit Chunks: {state.get('audit_log_count', 0)}")
            self.log_to_terminal(f"    - OpenEnv Status: {state.get('status', 'UNKNOWN')}\n")
            messagebox.showinfo("Success", "OpenEnv reset and connected to ChromaDB successfully!")
        except Exception as e:
            self.log_to_terminal(f"[!] OpenEnv Reset Error: {str(e)}")
            messagebox.showerror("Error", str(e))

    def run_agent_thread(self):
        """Runs the ReAct audit agent in a background thread."""
        threading.Thread(target=self.execute_audit_agent, daemon=True).start()

    def execute_audit_agent(self):
        """Executes the multi-step ReAct compliance audit using the user's custom query input."""
        self.terminal.delete("1.0", tk.END)
        
        query = self.query_entry.get().strip()
        if not query:
            query = "Analyze high-severity security events against ISO 27001 baselines."
        
        self.log_to_terminal(f"==================================================")
        self.log_to_terminal(f"[*] Executing ReAct Agent Audit Loop...")
        self.log_to_terminal(f"[*] Target Query: {query}")
        self.log_to_terminal(f"==================================================\n")
        
        result = self.env.step(query)
        
        if result["success"]:
            self.last_generated_report = result["report"]
            self.log_to_terminal(f"\n\n==================================================")
            self.log_to_terminal(f"[+] Audit Execution Complete! Ready to export (.docx).")
            self.log_to_terminal(f"==================================================")
        else:
            self.log_to_terminal(f"\n[!] Audit Execution Error: {result['error']}")

    def upload_and_ingest_pdf(self):
        """Opens file dialog to select a PDF, extracts text, and ingests into ChromaDB."""
        pdf_path = filedialog.askopenfilename(
            title="Select Policy PDF Document",
            filetypes=[("PDF Documents", "*.pdf"), ("All Files", "*.*")]
        )
        if not pdf_path:
            return

        self.log_to_terminal(f"\n[*] Extracting text from PDF: {os.path.basename(pdf_path)}...")
        
        try:
            reader = PdfReader(pdf_path)
            pdf_chunks = []
            
            for page_num, page in enumerate(reader.pages):
                text = page.extract_text()
                if text and text.strip():
                    pdf_chunks.append({
                        "id": f"pdf_{os.path.basename(pdf_path)}_p{page_num+1}",
                        "content": text.strip(),
                        "source": f"pdf_upload:{os.path.basename(pdf_path)}"
                    })
            
            if not pdf_chunks:
                raise ValueError("No extractable text found in this PDF.")

            chroma_client = chromadb.PersistentClient(path="./chroma_db")
            embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name="all-MiniLM-L6-v2"
            )
            collection = chroma_client.get_or_create_collection(
                name="openedge_compliance_vault",
                embedding_function=embedding_fn
            )

            collection.add(
                documents=[d["content"] for d in pdf_chunks],
                metadatas=[{"source": d["source"]} for d in pdf_chunks],
                ids=[d["id"] for d in pdf_chunks]
            )
            
            self.log_to_terminal(f"[+] Successfully indexed {len(pdf_chunks)} chunks from PDF into ChromaDB!")
            messagebox.showinfo("PDF Ingested", f"Successfully ingested {len(pdf_chunks)} pages from {os.path.basename(pdf_path)}!")

        except Exception as e:
            self.log_to_terminal(f"[!] PDF Ingestion Error: {str(e)}")
            messagebox.showerror("Error", str(e))

    def run_pas_ingestion(self):
        """Triggers live PAS for OpenEdge log telemetry ingestion."""
        self.log_to_terminal(f"\n[*] Triggering live PAS for OpenEdge log telemetry ingestion...")
        import ingest_pas_logs
        try:
            count = ingest_pas_logs.ingest_live_pas_logs()
            self.log_to_terminal(f"[+] PASOE Telemetry Ingested Successfully! ({count} events added)")
            messagebox.showinfo("PASOE Ingestion", f"Successfully synced {count} live PAS events into ChromaDB!")
        except Exception as e:
            self.log_to_terminal(f"[!] PAS Ingestion Error: {str(e)}")
            messagebox.showerror("Error", str(e))

    def run_abl_patch(self):
        """Triggers autonomous ABL security patching on selected files."""
        file_path = filedialog.askopenfilename(
            title="Select OpenEdge ABL Script (.p or .cls)",
            filetypes=[("ABL Code", "*.p *.cls *.txt"), ("All Files", "*.*")]
        )
        if not file_path:
            return

        self.log_to_terminal(f"\n[*] Running autonomous security patch generator on: {os.path.basename(file_path)}...")
        try:
            import abl_patch_generator
            result = abl_patch_generator.analyze_and_patch_abl_code(file_path)
            self.log_to_terminal(f"[+] Patch Generated Successfully! Saved as: {result['patched_file']}")
            for v in result['vulnerabilities']:
                self.log_to_terminal(f"    - {v}")
            messagebox.showinfo("Patch Complete", f"Secure patch generated at:\n{result['patched_file']}")
        except Exception as e:
            self.log_to_terminal(f"[!] ABL Patch Error: {str(e)}")
            messagebox.showerror("Error", str(e))

    def run_tde_audit(self):
        """Triggers database Transparent Data Encryption compliance check."""
        self.log_to_terminal(f"\n[*] Auditing OpenEdge Transparent Data Encryption (TDE)...")
        try:
            import tde_compliance_check
            findings = tde_compliance_check.audit_tde_configuration()
            self.log_to_terminal(f"[+] TDE Audit Finished: {len(findings)} cryptographic gaps detected.")
            for f in findings:
                self.log_to_terminal(f"    - [{f['severity']}] {f['control']}: {f['issue']}")
            messagebox.showinfo("TDE Audit Complete", f"Audit finished! Found {len(findings)} security gaps. Check terminal.")
        except Exception as e:
            self.log_to_terminal(f"[!] TDE Audit Error: {str(e)}")
            messagebox.showerror("Error", str(e))

    def start_fastapi_server(self):
        """Launches the FastAPI real-time webhook gateway in a background thread."""
        def run_server():
            try:
                import uvicorn
                self.log_to_terminal("\n[+] Launching FastAPI Security Gateway on http://127.0.0.1:8001...")
                uvicorn.run("gateway_api:app", host="127.0.0.1", port=8001, log_level="error")
            except Exception as e:
                self.log_to_terminal(f"[!] FastAPI Gateway Error: {str(e)}")

        threading.Thread(target=run_server, daemon=True).start()
        messagebox.showinfo("Gateway Launched", "FastAPI background server started on http://127.0.0.1:8001!\nWebhooks can now hit /api/v1/audit.")

    def export_report(self):
        """Exports the generated report into a professional .docx Word document."""
        if not self.last_generated_report:
            messagebox.showwarning("No Report", "Please execute a compliance audit first to generate a report.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".docx",
            filetypes=[("Word Document", "*.docx"), ("All Files", "*.*")],
            initialfile="OpenEdge_Compliance_Audit_Report.docx"
        )
        if not file_path:
            return

        try:
            doc = Document()
            doc.add_heading("OpenEdge Security & Compliance Audit Report", level=1)
            doc.add_paragraph("Generated autonomously via Agentic RAG (Llama 3.1 + ChromaDB ReAct Loop).")
            
            for line in self.last_generated_report.split("\n"):
                if line.startswith("# ") or line.startswith("1. ") or line.startswith("2. ") or line.startswith("3. ") or line.startswith("4. "):
                    doc.add_heading(line, level=2)
                else:
                    doc.add_paragraph(line)
                    
            doc.save(file_path)
            self.log_to_terminal(f"[+] Report successfully exported to: {file_path}")
            messagebox.showinfo("Export Successful", f"Report saved successfully as:\n{file_path}")

        except Exception as e:
            self.log_to_terminal(f"[!] Export Error: {str(e)}")
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = OpenEdgeGUI(root)
    root.mainloop()