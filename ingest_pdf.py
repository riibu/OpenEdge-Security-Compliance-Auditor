import os
import chromadb
from chromadb.utils import embedding_functions
from pypdf import PdfReader

def ingest_pdf_document(pdf_path: str, vector_db_path="./chroma_db"):
    """
    Extracts text from a user-provided PDF, chunks it, and indexes it into ChromaDB.
    """
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"PDF file not found at: {pdf_path}")
    
    print(f"[*] Extracting text from PDF: {os.path.basename(pdf_path)}...")
    
    reader = PdfReader(pdf_path)
    pdf_chunks = []
    
    for page_num, page in enumerate(reader.pages):
        text = page.extract_text()
        if text.strip():
            # Simple paragraph/page-level chunking
            pdf_chunks.append({
                "id": f"pdf_{os.path.basename(pdf_path)}_page_{page_num+1}",
                "content": text.strip(),
                "source": f"pdf_upload:{os.path.basename(pdf_path)}"
            })
            
    if not pdf_chunks:
        raise ValueError("No extractable text found in the provided PDF.")

    # Connect to ChromaDB
    chroma_client = chromadb.PersistentClient(path=vector_db_path)
    embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name="all-MiniLM-L6-v2"
    )
    collection = chroma_client.get_or_create_collection(
        name="openedge_compliance_vault",
        embedding_function=embedding_fn
    )

    # Add PDF chunks to collection
    ids = [d["id"] for d in pdf_chunks]
    texts = [d["content"] for d in pdf_chunks]
    metadatas = [{"source": d["source"]} for d in pdf_chunks]

    collection.add(
        documents=texts,
        metadatas=metadatas,
        ids=ids
    )

    print(f"[+] Successfully ingested {len(ids)} chunks from PDF into ChromaDB!")
    return len(ids)