import os
from fpdf import FPDF
from pygments import highlight
from pygments.lexers import guess_lexer_for_filename, TextLexer
from pygments.formatters import HtmlFormatter

root_folder = "."

class PDF(FPDF):
    pass

def safe_text(text):
    """Replace unsupported Unicode characters with a placeholder."""
    return text.encode("latin-1", errors="replace").decode("latin-1")

def add_code_to_pdf(pdf, file_path, formatter):
    relative_path = os.path.relpath(file_path, root_folder)
    print(f"Adding: {relative_path}")

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read()

    try:
        lexer = guess_lexer_for_filename(file_path, code)
    except Exception:
        lexer = TextLexer()

    html_code = highlight(code, lexer, formatter)
    html_code = safe_text(html_code)  # Replace unsupported characters

    pdf.add_page()
    pdf.set_font("Courier", "", 10)  # Use default built-in font
    pdf.cell(0, 10, safe_text(relative_path), new_y="NEXT")
    pdf.ln(2)
    pdf.write_html(html_code)

def convert_project_to_pdf(root_folder, output_pdf="Project_Code.pdf"):
    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    formatter = HtmlFormatter(style="monokai", noclasses=True, linenos=False)

    for root, dirs, files in os.walk(root_folder):
        for file in files:
            if file.endswith((".py", ".js", ".html", ".css", ".cpp", ".java", ".ts", ".json", ".txt", ".md")):
                add_code_to_pdf(pdf, os.path.join(root, file), formatter)

    pdf.output(output_pdf)
    print(f"\n✅ Project converted into '{output_pdf}' successfully!")

if __name__ == "__main__":
    convert_project_to_pdf(root_folder)
