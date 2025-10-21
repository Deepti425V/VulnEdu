# Type hints for better code documentation and IDE support
from typing import Dict, List, Any, Optional

class CWEModel:
    """Data model for CWE weakness records"""

    def __init__(self, data: Dict[str, Any]):
        # Extract CWE code (e.g., "CWE-79") with empty string fallback
        self.code = data.get('code', '')
        # Get weakness name/title with empty string fallback
        self.name = data.get('name', '')
        # Extract description text with empty string fallback
        self.description = data.get('description', '')
        # Get list of mitigation strategies with empty list fallback
        self.mitigations = data.get('mitigations', [])
        # Extract examples list with empty list fallback
        self.examples = data.get('examples', [])
        # Get relationships to other CWEs with empty list fallback
        self.relationships = data.get('relationships', [])
        # Track data source with 'unknown' fallback for provenance
        self.source = data.get('source', 'unknown')

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format"""
        # Return all instance attributes as dictionary for serialization
        return {
            'code': self.code,
            'name': self.name,
            'description': self.description,
            'mitigations': self.mitigations,
            'examples': self.examples,
            'relationships': self.relationships,
            'source': self.source
        }

    def get_id(self) -> str:
        """Get CWE ID number from code"""
        # Check if code follows standard "CWE-123" format
        if self.code.startswith('CWE-'):
            # Return numeric part after "CWE-" prefix (index 4 onwards)
            return self.code[4:]
        # Return original code if format doesn't match
        return self.code

    def get_mitre_url(self) -> str:
        """Get MITRE URL for this CWE"""
        # Extract numeric CWE ID
        cwe_id = self.get_id()
        # Build complete URL to MITRE CWE definition page
        return f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"

    def has_mitigations(self) -> bool:
        """Check if CWE has mitigation strategies"""
        # Verify mitigations exist AND first item isn't placeholder text
        return len(self.mitigations) > 0 and self.mitigations[0] != 'Loading detailed information...'
