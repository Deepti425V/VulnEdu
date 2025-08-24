# Static mapping of Common Weakness Enumeration (CWE) IDs to human-readable titles
# This provides instant lookup for the most critical/common vulnerabilities
CWE_TITLES = {
    # Web Application Security (OWASP Top 10)
    "CWE-79": "Cross-Site Scripting",
    "CWE-89": "SQL Injection", 
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    
    # Memory Safety Issues (C/C++ common vulnerabilities)
    "CWE-119": "Buffer Overflow",
    "CWE-120": "Buffer Copy without Checking Size",
    "CWE-193": "Off-by-one Error",
    
    # Information Security
    "CWE-200": "Information Exposure",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    
    # Authentication & Access Control
    "CWE-287": "Improper Authentication", 
    "CWE-264": "Permissions, Privileges, and Access Controls",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-255": "Credentials Management",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
    "CWE-384": "Session Fixation",
    
    # Code Injection Attacks
    "CWE-88": "Argument Injection or Modification",
    "CWE-78": "OS Command Injection", 
    "CWE-94": "Code Injection",
    
    # File System & Data Processing
    "CWE-59": "Improper Link Resolution Before File Access",
    "CWE-19": "Data Processing Errors",
    "CWE-178": "Improper Handling of Case Sensitivity",
    
    # Generic/Broad Categories
    "CWE-17": "Code",
    
    # Special Cases - National Vulnerability Database (NVD) classifications
    "NVD-CWE-Other": "Other/Unclassified",
    "NVD-CWE-noinfo": "Unclassified", 
    "Unclassified": "Unknown"
}

def cwe_title(cwe):
    """
    Safe lookup function to get human-readable title for a CWE ID.
    Handles missing entries and null inputs gracefully.
    
    Args:
        cwe (str or None): CWE identifier (e.g., "CWE-79")
    
    Returns:
        str: Human-readable title, original CWE ID, or "Not specified"
    """
    # Triple-fallback logic: 
    # 1. Try dictionary lookup
    # 2. If not found, return original CWE (if it exists)  
    # 3. If CWE is None/empty, return "Not specified"
    return CWE_TITLES.get(cwe, cwe if cwe else "Not specified")