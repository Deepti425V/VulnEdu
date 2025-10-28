import os
from fpdf import FPDF, HTMLMixin
from pygments import highlight
from pygments.lexers import guess_lexer_for_filename, TextLexer
from pygments.formatters import HtmlFormatter

class MyFPDF(FPDF, HTMLMixin):
    pass

def safe_text(text):
    """Replace unsupported Unicode characters with a placeholder."""
    return text.encode("latin-1", errors="replace").decode("latin-1")

def convert_project_to_individual_pdfs(root_folder, output_folder="project_pdfs", combine_all=True):
    """
    Convert project files to individual PDFs and optionally one combined PDF.
    
    Args:
        root_folder (str): Root directory of the project
        output_folder (str): Folder to save individual PDF files
        combine_all (bool): Whether to also generate one combined PDF
    """
    os.makedirs(output_folder, exist_ok=True)

    supported_extensions = [".py", ".js", ".html", ".css", ".cpp", ".java", ".ts", ".json", ".txt", ".md"]

    total_files = 0
    converted_files = 0

    formatter = HtmlFormatter(style="monokai", noclasses=True, linenos=False)

    # For combined PDF
    combined_pdf = MyFPDF()
    combined_pdf.set_auto_page_break(auto=True, margin=15)
    combined_pdf.set_font("Courier", "", 10)

    for root, dirs, files in os.walk(root_folder):
        dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules', 'venv'}]
        
        for file in files:
            if any(file.endswith(ext) for ext in supported_extensions):
                total_files += 1
                file_path = os.path.join(root, file)

                # Skip large files
                if os.path.getsize(file_path) > 1 * 1024 * 1024:
                    print(f"⚠️ Skipping large file: {file_path}")
                    continue

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        code = f.read()

                    try:
                        lexer = guess_lexer_for_filename(file_path, code)
                    except Exception:
                        lexer = TextLexer()

                    html_code = highlight(code, lexer, formatter)
                    html_code = safe_text(html_code)
                    relative_path = os.path.relpath(file_path, root_folder)

                    # ========== INDIVIDUAL PDF ==========
                    pdf = MyFPDF()
                    pdf.set_auto_page_break(auto=True, margin=15)
                    pdf.add_page()
                    pdf.set_font("Courier", "B", 12)
                    pdf.cell(0, 10, safe_text(relative_path), new_y="NEXT")
                    pdf.ln(2)
                    pdf.write_html(html_code)

                    pdf_filename = relative_path.replace(os.path.sep, '_') + ".pdf"
                    pdf_path = os.path.join(output_folder, pdf_filename)
                    pdf.output(pdf_path)
                    converted_files += 1

                    print(f"✅ Converted: {file_path} → {pdf_path}")

                    # ========== COMBINED PDF ==========
                    if combine_all:
                        combined_pdf.add_page()
                        combined_pdf.set_font("Courier", "B", 12)
                        combined_pdf.cell(0, 10, safe_text(relative_path), new_y="NEXT")
                        combined_pdf.ln(2)
                        combined_pdf.write_html(html_code)

                except Exception as e:
                    print(f"❌ Error converting {file_path}: {e}")

    # Save combined PDF
    if combine_all and converted_files > 0:
        combined_path = os.path.join(output_folder, "project_combined.pdf")
        combined_pdf.output(combined_path)
        print(f"\n📘 Combined PDF created: {combined_path}")

    print(f"\n📄 Total files found: {total_files}")
    print(f"📕 Files converted to individual PDFs: {converted_files}")

# Usage
if __name__ == "__main__":
    project_root = "."  # Current directory
    output_directory = "./project_pdfs"
    convert_project_to_individual_pdfs(project_root, output_directory, combine_all=True)
