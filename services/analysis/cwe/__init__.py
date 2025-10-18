"""
CWE Analysis Module
Modular CWE processing and analysis functionality
"""

# Import core CWE processing class for severity analysis and data aggregation
from .processor import CWESeverityProcessor
# Import advanced analysis functions for risk assessment and trend analysis
from .analyzer import get_vendor_risk_analysis, get_weighted_cwe_analysis, get_cwe_30_day_counts
# Import CWE catalog management class for loading weakness definitions
from .catalog import CWECatalogLoader
# Import utility functions for CWE title resolution and helper operations
from .utils import get_cwe_title

# Create global processor instance for backward compatibility and immediate use
cwe_processor = CWESeverityProcessor()

# Export main functions and classes for controlled public API
# Includes both legacy global instance and modern class-based interface
__all__ = [
    'cwe_processor',              # Global instance for backward compatibility
    'CWESeverityProcessor',       # Class for custom processor instances
    'CWECatalogLoader',          # Class for CWE catalog management
    'get_vendor_risk_analysis',   # Function for vendor risk assessment
    'get_weighted_cwe_analysis',  # Function for weighted CWE analysis
    'get_cwe_30_day_counts',     # Function for temporal trend analysis
    'get_cwe_title'              # Utility function for CWE title resolution
]
