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
        self.root.geometry("900x700")
        
        # Initialize OpenEnv
        self.env = OpenEdgeAuditEnv()
        self.last_generated_report = ""

        # --- GUI LAYOUT ---
        
        # Title Label
        title_label = tk.Label(root, text="🛡️ OpenEdge Autonomous Compliance Auditor", font=("Arial", 16, "bold"))
        title_label.pack(pady=10)

        # Control Panel Frame (Primary Buttons)
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=5)

        self.btn_ingest = tk.Button(btn_frame, text="1. Run Data Ingestion", command=self.run_ingestion_thread, bg="#2b5b84", fg="white", font=("Arial", 10, "bold"), width=22)
        self.btn_ingest.grid(row=0, column=0, padx=5, pady=5)

        self.btn_reset = tk.Button(btn_frame, text="2. Reset OpenEnv", command=self.reset_env, bg="#2b845b", fg="white", font=("Arial", 10, "bold"), width=22)
        self.btn_reset.grid(row=0, column=1, padx=5, pady=5)

        self.btn_agent = tk.Button(btn_frame, text="3. Execute Compliance Audit", command=self.run_agent_thread, bg="#845b2b", fg="white", font=("Arial", 10, "bold"), width=25)
        self.btn_agent.grid(row=0, column=2, padx=5, pady=5)

        # Secondary Row (PDF Upload, Live PAS Logs, & Word Export)
        btn_frame_2 = tk.Frame(root)
        btn_frame_2.pack(pady=5)

        self.btn_pdf = tk.Button(btn_frame_2, text="4. Upload & Ingest PDF", command=self.upload_and_ingest_pdf, bg="#5b2b84", fg="white", font=("Arial", 10, "bold"), width=24)
        self.btn_pdf.grid(row=0, column=0, padx=4, pady=5)

        self.btn_pas = tk.Button(btn_frame_2, text="5. Ingest Live PAS Logs", command=self.run_pas_ingestion, bg="#2b8484", fg="white", font=("Arial", 10, "bold"), width=24)
        self.btn_pas.grid(row=0, column=1, padx=4, pady=5)

        self.btn_export = tk.Button(btn_frame_2, text="6. Export Report (.docx)", command=self.export_report, bg="#842b5b", fg="white", font=("Arial", 10, "bold"), width=24)
        self.btn_export.grid(row=0, column=2, padx=4, pady=5)

        # --- CUSTOM QUERY INPUT FRAME ---
        query_frame = tk.Frame(root)
        query_frame.pack(fill=tk.X, padx=15, pady=8)

        query_label = tk.Label(query_frame, text="Custom Audit Prompt / Query (Targeting Ingested Docs & Telemetry):", font=("Arial", 9, "bold"), anchor="w")
        query_label.pack(fill=tk.X, pady=2)

        self.query_entry = tk.Entry(query_frame, font=("Consolas", 10), bg="#2d2d2d", fg="#ffffff", insertbackground="white")
        self.query_entry.pack(fill=tk.X, expand=True, ipady=4)
        # Default query referencing security telemetry and PDF compliance
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

        self.log_to_terminal("[+] System ready. Ingest PDFs or live PAS logs, type your query above, and hit button 3!\n")

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
        
        # Grab custom query from the text input field
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

            ids = [d["id"] for d in pdf_chunks]
            texts = [d["content"] for d in pdf_chunks]
            metadatas = [{"source": d["source"]} for d in pdf_chunks]

            collection.add(documents=texts, metadatas=metadatas, ids=ids)
            
            self.log_to_terminal(f"[+] Successfully embedded and indexed {len(ids)} chunks from PDF into ChromaDB!")
            messagebox.showinfo("PDF Ingested", f"Successfully ingested {len(ids)} pages from {os.path.basename(pdf_path)} into the vector store!")

        except Exception as e:
            self.log_to_terminal(f"[!] PDF Ingestion Error: {str(e)}")
            messagebox.showerror("Error", str(e))

    def run_pas_ingestion(self):
        """Triggers live PAS for OpenEdge log telemetry ingestion."""
        self.log_to_terminal(f"\n[*] Triggering live PAS for OpenEdge log telemetry ingestion...")
        import ingest_pas_logs
        try:
            count = ingest_pas_logs.ingest_live_pas_logs()
            self.log_to_terminal(f"[+] PASOE Telemetry Ingested Successfully! ({count} live security events added to ChromaDB)")
            messagebox.showinfo("PASOE Ingestion", f"Successfully synced {count} live PAS for OpenEdge events into the vector store!")
        except Exception as e:
            self.log_to_terminal(f"[!] PAS Ingestion Error: {str(e)}")
            messagebox.showerror("Error", str(e))

    def export_report(self):
        """Exports the generated report into a professional .docx Word document."""
        if not self.last_generated_report:
            messagebox.showwarning("No Report", "Please execute a compliance audit first to generate a report before exporting.")
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