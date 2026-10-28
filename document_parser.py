import os
from pypdf import PdfReader
import re

class QuestionBlock:
    def __init__(self, raw_text=""):
        self.raw_text = raw_text

def extract_structured_questions(file_path):
    """
    Extracts text from either a PDF or a plain text (.txt) file 
    and returns structured question blocks.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    text = ""
    
    # Check if the file is a PDF or a text file
    if file_path.lower().endswith('.pdf'):
        reader = PdfReader(file_path)
        for page in reader.pages:
            extracted = page.extract_text()
            if extracted:
                text += extracted + "\n"
    else:
        # Read as a standard text file
        with open(file_path, 'r', encoding='utf-8') as f:
            text = f.read()

    # Wrap the extracted text into a QuestionBlock or structured format
    block = QuestionBlock(raw_text=text)
    return [block]