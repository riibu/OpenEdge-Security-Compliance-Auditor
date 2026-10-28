import re
from pypdf import PdfReader

class QuestionBlock:
    def __init__(self, section, q_id, text, marks, answer_slot_index):
        self.section = section        # e.g., "SECTION D: Memory, Storage and Log Analysis"
        self.q_id = q_id              # e.g., "4.1"
        self.text = text              # e.g., "Analyse the memory-string artefact summary..."
        self.marks = marks            # e.g., 10
        self.answer = ""

def extract_structured_questions(pdf_path):
    reader = PdfReader(pdf_path)
    full_text = "\n".join([page.extract_text() for page in reader.pages])
    
    # Regex pattern to identify question patterns like "4.1 Analyse the..." or "Question 4.1"
    question_pattern = re.compile(
        r'(SECTION\s+[A-Z]:[^\n]+)?\n*(\d+\.\d+)\s+([^\n\[]+)\[(\d+)\]', 
        re.MULTILINE
    )
    
    questions = []
    current_section = "General"
    
    for match in question_pattern.finditer(full_text):
        sec, q_id, q_text, marks = match.groups()
        if sec:
            current_section = sec.strip()
        questions.append(QuestionBlock(
            section=current_section,
            q_id=q_id.strip(),
            text=q_text.strip(),
            marks=int(marks),
            answer_slot_index=match.end()
        ))
    return questions