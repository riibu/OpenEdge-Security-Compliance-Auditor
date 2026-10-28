import os
from pypdf import PdfReader
import chromadb
from chromadb.utils import embedding_functions

def chunk_text(text: str, chunk_size: int = 1200, overlap: int = 250) -> list[str]:
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end])
        start += chunk_size - overlap
    return chunks

def ingest_knowledge_directory(source_dir: str = "./knowledge_sources"):
    if not os.path.exists(source_dir):
        os.makedirs(source_dir)
        print(f"[!] Created directory '{source_dir}'.")
        return

    pdf_files = [f for f in os.listdir(source_dir) if f.lower().endswith('.pdf')]
    
    if not pdf_files:
        print(f"[!] No PDF files found in '{source_dir}'.")
        return

    print(f"[*] Connecting to local ChromaDB vault at ./chroma_db...")
    chroma_client = chromadb.PersistentClient(path="./chroma_db")
    embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")
    collection = chroma_client.get_or_create_collection(name="openedge_compliance_vault", embedding_function=embedding_fn)

    total_chunks_added = 0

    for pdf_file in pdf_files:
        pdf_path = os.path.join(source_dir, pdf_file)
        print(f"[*] Processing and chunking: {pdf_file}...")
        
        try:
            reader = PdfReader(pdf_path)
            full_text = ""
            for page_num, page in enumerate(reader.pages):
                page_text = page.extract_text()
                if page_text:
                    full_text += "\n\n" + page_text

            chunks = chunk_text(full_text)
            
            documents = []
            metadatas = []
            ids = []

            for idx, chunk in enumerate(chunks):
                doc_id = f"{pdf_file}_chunk_{idx}"
                documents.append(chunk)
                metadatas.append({"source": pdf_file, "chunk_index": idx})
                ids.append(doc_id)

            if documents:
                collection.upsert(
                    documents=documents,
                    metadatas=metadatas,
                    ids=ids
                )
                print(f"[+] Successfully ingested {len(chunks)} chunks from {pdf_file}.")
                total_chunks_added += len(chunks)

        except Exception as e:
            print(f"[!] Error processing {pdf_file}: {str(e)}")

    print(f"\n[+] Ingestion Complete! Total new expert knowledge chunks added to vault: {total_chunks_added}")

if __name__ == "__main__":
    ingest_knowledge_directory()
