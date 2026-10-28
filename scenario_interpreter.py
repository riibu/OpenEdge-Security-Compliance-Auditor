import os
import re
from pypdf import PdfReader
import chromadb
from chromadb.utils import embedding_functions

def extract_questions_from_pdf(pdf_path: str) -> list[dict]:
    """Extracts questions and task prompts from an assessment PDF."""
    print(f"[*] Reading assessment brief: {pdf_path}...")
    reader = PdfReader(pdf_path)
    full_text = ""
    for page in reader.pages:
        text = page.extract_text()
        if text:
            full_text += "\n" + text

    # Simple regex pattern to catch question numbering like "1.1", "2.3", etc.
    # Adjust regex based on your specific assessment template formatting
    question_pattern = re.compile(r'(\d+\.\d+)\s+([^\n]+)', re.MULTILINE)
    matches = question_pattern.findall(full_text)
    
    questions = []
    for q_num, q_text in matches:
        questions.append({"number": q_num, "prompt": q_text.strip()})
        
    print(f"[+] Extracted {len(questions)} target questions from the assessment.")
    return questions

def query_knowledge_vault(query_text: str, n_results: int = 3) -> list[str]:
    """Queries your local ChromaDB expert vault for relevant NIST/OWASP guidance."""
    chroma_client = chromadb.PersistentClient(path="./chroma_db")
    embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
    
    try:
        collection = chroma_client.get_collection(name="openedge_compliance_vault", embedding_function=embedding_fn)
        results = collection.query(query_texts=[query_text], n_results=n_results)
        return results.get("documents", [[]])[0]
    except Exception as e:
        print(f"[!] Vault query error: {str(e)}")
        return []

def generate_scenario_answer(question_prompt: str, scenario_context: str) -> str:
    """
    Combines the scenario context, the specific assessment question, 
    and your local vector vault knowledge to generate a precision answer.
    """
    # 1. Fetch relevant expert rules from local ChromaDB
    retrieved_chunks = query_knowledge_vault(question_prompt, n_results=2)
    expert_guidance = "\n".join(retrieved_chunks)

    # 2. Construct the prompt payload for your local LLM / Guru
    synthesized_prompt = f"""
    You are an expert Cybersecurity Guru and DFIR Analyst.
    
    === SCENARIO CONTEXT ===
    {scenario_context}
    
    === AUTHORITATIVE FRAMEWORK KNOWLEDGE (NIST / OWASP) ===
    {expert_guidance}
    
    === ASSESSMENT TASK / QUESTION ===
    {question_prompt}
    
    Instructions:
    - Provide a complete, professional, framework-aligned answer.
    - Strictly adhere to the scenario parameters (hostnames, IP addresses, user profiles, artefacts).
    - Format tables and lists cleanly using Markdown.
    """
    
    # In your local implementation, pass 'synthesized_prompt' to your local Llama 3 model API (Ollama / HuggingFace)
    return synthesized_prompt

if __name__ == "__main__":
    # Example test runner
    pdf_file = "knowledge_sources/DigitalForensicsandIncidentResponse-Formative_Assessment1_kt1.pdf"
    if os.path.exists(pdf_file):
        qs = extract_questions_from_pdf(pdf_file)
        for q in qs[:3]: # Test first 3 extracted questions
            print(f"\n--- Question {q['number']} ---")
            print(f"Prompt: {q['prompt']}")
    else:
        print("[!] Place your assessment PDF inside knowledge_sources/ to test extraction.")