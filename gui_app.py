import os
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from open_env import OpenEdgeAuditEnv

class AuditorGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("OpenEdge Security & Compliance Auditor (OpenEnv Agentic RAG)")
        self.geometry("1000x720")
        self.configure(bg="#0F172A") # Dark terminal aesthetic

        self.env = None
        self._init_styles()
        self._build_widgets()

    def _init_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#0F172A")
        style.configure("Header.TLabel", background="#0F172A", foreground="#38BDF8", font=("Consolas", 16, "bold"))
        style.configure("Sub.TLabel", background="#0F172A", foreground="#94A3B8", font=("Consolas", 10))
        style.configure("Dark.TButton", background="#1E293B", foreground="#F8FAFC", font=("Consolas", 10, "bold"), borderwidth=1)
        style.map("Dark.TButton", background=[("active", "#334155")])

    def _build_widgets(self):
        # Header Section
        header_frame = ttk.Frame(self, padding=15)
        header_frame.pack(fill="x")

        title = ttk.Label(header_frame, text="🛡️ OpenEdge Security & Compliance Auditor", style="Header.TLabel")
        title.pack(anchor="w")

        subtitle = ttk.Label(header_frame, text="Agentic RAG Engine | OpenEnv Protocol | Windows Host ↔ Kali Ollama Bridge", style="Sub.TLabel")
        subtitle.pack(anchor="w", pady=(2, 0))

        # Control Panel Controls
        btn_frame = ttk.Frame(self, padding=10)
        btn_frame.pack(fill="x")

        self.btn_ingest = ttk.Button(btn_frame, text="⚡ 1. Run Data Ingestion", style="Dark.TButton", command=self.run_ingestion)
        self.btn_ingest.pack(side="left", padx=5)

        self.btn_reset_env = ttk.Button(btn_frame, text="🔄 2. Reset OpenEnv", style="Dark.TButton", command=self.reset_environment)
        self.btn_reset_env.pack(side="left", padx=5)

        self.btn_run_agent = ttk.Button(btn_frame, text="🤖 3. Execute Compliance Audit Agent", style="Dark.TButton", command=self.run_agent_audit)
        self.btn_run_agent.pack(side="left", padx=5)

        # Query Entry Field
        query_frame = ttk.Frame(self, padding=10)
        query_frame.pack(fill="x")

        lbl_query = ttk.Label(query_frame, text="Audit Target / Prompt:", style="Sub.TLabel")
        lbl_query.pack(anchor="w", pady=(0, 2))

        self.entry_query = tk.Entry(query_frame, bg="#1E293B", fg="#F8FAFC", insertbackground="#38BDF8", font=("Consolas", 10), relief="flat")
        self.entry_query.pack(fill="x", ipady=6)
        self.entry_query.insert(0, "Analyze high-severity security events (SEC-1001 failed SSH login and SEC-1003 unauthorized file access) against ISO 27001 baselines.")

        # Terminal Display Console
        console_frame = ttk.Frame(self, padding=10)
        console_frame.pack(fill="both", expand=True)

        lbl_console = ttk.Label(console_frame, text="Agent Observation & Audit Output Console:", style="Sub.TLabel")
        lbl_console.pack(anchor="w", pady=(0, 2))

        self.console = scrolledtext.ScrolledText(
            console_frame,
            bg="#020617",
            fg="#38BDF8",
            insertbackground="#38BDF8",
            font=("Consolas", 10),
            wrap="word",
            relief="flat"
        )
        self.console.pack(fill="both", expand=True)
        self.log_console("[+] System ready. Click '1. Run Data Ingestion' or '2. Reset OpenEnv' to initialize.")

    def log_console(self, message: str):
        self.console.insert(tk.END, message + "\n")
        self.console.see(tk.END)

    def run_ingestion(self):
        self.log_console("[*] Triggering data ingestion pipeline...")
        def worker():
            res = os.system("python ingest_audit.py")
            if res == 0:
                self.log_console("[+] Ingestion successful! vector_store_mock.json updated.")
            else:
                self.log_console("[!] Ingestion failed. Check terminal logs.")
        threading.Thread(target=worker, daemon=True).start()

    def reset_environment(self):
        try:
            self.env = OpenEdgeAuditEnv()
            state = self.env.reset()
            self.log_console(f"[+] OpenEnv Reset Successful!")
            self.log_console(f"    - Loaded Audit Events: {state['audit_log_count']}")
            self.log_console(f"    - Loaded Compliance Rules: {state['baseline_count']}")
            self.log_console(f"    - OpenEnv Status: {state['status']}")
        except Exception as e:
            self.log_console(f"[!] OpenEnv Reset Error: {e}")

    def run_agent_audit(self):
        if not self.env:
            self.reset_environment()
            if not self.env:
                return

        query = self.entry_query.get().strip()
        if not query:
            messagebox.showwarning("Input Error", "Please provide an audit prompt query.")
            return

        self.log_console("\n==================================================")
        self.log_console(f"[*] Executing Live Streaming Agent Step: '{query}'")
        self.log_console("==================================================\n")
        
        self.btn_run_agent.config(state="disabled")

        # Define live chunk callback safely dispatched to Tkinter's main thread via self.after
        def stream_callback(text_chunk):
            self.after(0, lambda: self.console.insert(tk.END, text_chunk))
            self.after(0, lambda: self.console.see(tk.END))

        def worker():
            self.env.on_chunk_received = stream_callback
            result = self.env.step(query)
            self.after(0, lambda: self._handle_agent_result(result))

        threading.Thread(target=worker, daemon=True).start()

    def _handle_agent_result(self, result: dict):
        self.btn_run_agent.config(state="normal")
        self.console.insert(tk.END, "\n")
        if not result["success"]:
            self.log_console(f"\n[!] Agent Step Error: {result['error']}")
        self.log_console("==================================================\n")

if __name__ == "__main__":
    app = AuditorGUI()
    app.mainloop()