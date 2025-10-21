"""
CWE Processor - Main Interface
This file maintains backward compatibility while using the new modular CWE structure
"""

# Import all functionality from the modular CWE package
# This provides a transparent interface to the new architecture
from .cwe import (
    cwe_processor,              # Global processor instance for backward compatibility
    CWESeverityProcessor,       # Main processor class for CWE severity analysis
    get_vendor_risk_analysis,   # Advanced vendor risk assessment function
    get_weighted_cwe_analysis,  # Severity-weighted CWE scoring function
    get_cwe_30_day_counts,     # Recent CWE frequency analysis function
    get_cwe_title              # CWE code to title resolution utility
)

# Re-export everything for backward compatibility
# This ensures existing code can continue using the same import paths
__all__ = [
    'cwe_processor',           # Legacy global instance access
    'CWESeverityProcessor',    # Class for creating custom processor instances
    'get_vendor_risk_analysis',   # Comprehensive risk analysis functionality
    'get_weighted_cwe_analysis',  # Weighted analysis for priority assessment
    'get_cwe_30_day_counts',      # Temporal trend analysis capabilities
    'get_cwe_title'               # Utility function for CWE title resolution
]
