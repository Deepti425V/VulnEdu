import os
from fpdf import FPDF
from pygments import highlight
from pygments.lexers import guess_lexer_for_filename, TextLexer
from pygments.formatters import HtmlFormatter

def safe_text(text):
    """Replace unsupported Unicode characters with a placeholder."""
    return text.encode("latin-1", errors="replace").decode("latin-1")

def convert_project_to_individual_pdfs(root_folder, output_folder="project_pdfs"):
    """
    Convert project files to individual PDFs in a single folder
    
    Args:
        root_folder (str): Root directory of the project
        output_folder (str): Folder to save individual PDF files
    """
    # Create output folder if it doesn't exist
    os.makedirs(output_folder, exist_ok=True)

    # Supported file extensions
    supported_extensions = [".py", ".js", ".html", ".css", ".cpp", ".java", ".ts", ".json", ".txt", ".md"]

    # Counters
    total_files = 0
    converted_files = 0

    # PDF formatter
    formatter = HtmlFormatter(style="monokai", noclasses=True, linenos=False)

    # Walk through project files
    for root, dirs, files in os.walk(root_folder):
        # Skip unnecessary directories
        dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules', 'venv'}]
        
        for file in files:
            # Check if file has supported extension
            if any(file.endswith(ext) for ext in supported_extensions):
                total_files += 1
                file_path = os.path.join(root, file)
                
                # Skip large files (over 1MB)
                if os.path.getsize(file_path) < 1 * 1024 * 1024:
                    try:
                        # Create PDF for individual file
                        pdf = FPDF()
                        pdf.set_auto_page_break(auto=True, margin=15)
                        
                        # Read file content
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            code = f.read()
                        
                        # Determine lexer
                        try:
                            lexer = guess_lexer_for_filename(file_path, code)
                        except Exception:
                            lexer = TextLexer()
                        
                        # Highlight code
                        html_code = highlight(code, lexer, formatter)
                        html_code = safe_text(html_code)
                        
                        # Generate unique PDF filename
                        relative_path = os.path.relpath(file_path, root_folder)
                        pdf_filename = relative_path.replace(os.path.sep, '_') + ".pdf"
                        pdf_path = os.path.join(output_folder, pdf_filename)
                        
                        # Create PDF
                        pdf.add_page()
                        pdf.set_font("Courier", "", 10)
                        pdf.cell(0, 10, safe_text(relative_path), new_y="NEXT")
                        pdf.ln(2)
                        pdf.write_html(html_code)
                        
                        # Save PDF
                        pdf.output(pdf_path)
                        converted_files += 1
                        print(f"✅ Converted: {file_path} → {pdf_path}")
                    
                    except Exception as e:
                        print(f"❌ Error converting {file_path}: {e}")

    # Print summary
    print(f"\n📄 Total files found: {total_files}")
    print(f"📕 Files converted to PDF: {converted_files}")

# Usage
if __name__ == "__main__":
    project_root = "."  # Current directory
    output_directory = "./project_pdfs"
    convert_project_to_individual_pdfs(project_root, output_directory)