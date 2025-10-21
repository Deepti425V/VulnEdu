# Flask blueprint system for modular route organization
from flask import Blueprint, render_template

# Create utility blueprint for reference and documentation routes
utility_bp = Blueprint('utility', __name__)

@utility_bp.route("/references")
def references():
    """References and resources page"""
    # Render main references template - serves as navigation hub for documentation
    return render_template("references.html")

@utility_bp.route("/references/<section>")
def references_section(section):
    """References section pages"""
    # Whitelist of valid reference sections for security and content control
    valid_sections = ['data-sources', 'apis-feeds', 'tech-docs', 'dev-tools']

    # Validate section parameter to prevent unauthorized template access
    if section not in valid_sections:
        # Fallback to main references page for invalid sections
        return render_template("references.html")

    # Render section-specific template using validated parameter
    return render_template(f"references/{section}.html")
