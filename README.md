# 🛡️ OpenEdge Security & Compliance Auditor

An enterprise-grade **Agentic RAG Security & Compliance Auditor** designed for real-time risk assessment, compliance gap analysis, and automated remediation generation. Built with an **OpenEnv** protocol wrapper and a distributed bridge architecture.

---

## 🏗️ Architecture Overview

The system features a hybrid distributed design:
* **Host Layer (Windows):** Hosts the interactive operator GUI (`gui_app.py`) built with Tkinter and the OpenEnv environment interface (`open_env.py`), ensuring a responsive desktop control panel.
* **Inference Layer (Kali Linux VM):** Runs **Llama 3.1** locally via **Ollama**, serving high-performance LLM generations across a secure network bridge.
* **Agentic RAG Workflow:** Ingests raw security audit logs, cross-references them against ISO 27001 compliance baselines, and streams structured mitigation reports live into the console.

---

## 🚀 Key Features

* **Real-Time Streaming Console:** Leverages chunked HTTP streaming to render live token-by-token audit reports with zero connection timeouts.
* **OpenEnv Protocol Compliance:** Implements standardized environment lifecycle methods (`reset()`, `step()`) tailored for security agent evaluations.
* **Dark Terminal Aesthetics:** Custom-styled retro-hacker operator console designed for clarity and speed.

---

## 🛠️ Installation & Setup

### 1. Clone the Repository
```bash
git clone [https://github.com/riibu/OpenEdge-Security-Compliance-Auditor.git](https://github.com/riibu/OpenEdge-Security-Compliance-Auditor.git)
cd OpenEdge-Security-Compliance-Auditor