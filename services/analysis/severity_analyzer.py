from typing import Dict, Any
from collections import Counter
from services.data.api_client import api_client

def get_severity_card_counts() -> Dict[str, Any]:
    """Get severity counts for dashboard cards - LAZY LOAD"""
    print("[Severity Cards] Calculating severity distribution from API...")
    
    # Fetch CVEs when function is called, NOT at module level
    cves = api_client.get_cves_last_30_days(batch_size=200, offset=0)
    
    # Count by severity
    severity_counts = Counter()
    for cve in cves:
        severity = cve.get('Severity', 'UNKNOWN').upper()
        if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_counts[severity] += 1
        else:
            severity_counts['UNKNOWN'] += 1
    
    result = {
        'CRITICAL': severity_counts.get('CRITICAL', 0),
        'HIGH': severity_counts.get('HIGH', 0),
        'MEDIUM': severity_counts.get('MEDIUM', 0),
        'LOW': severity_counts.get('LOW', 0),
        'UNKNOWN': severity_counts.get('UNKNOWN', 0),
        'total_cves': len(cves)
    }
    
    print(f"[Severity Cards] Counts: Critical={result['CRITICAL']}, High={result['HIGH']}, Medium={result['MEDIUM']}, Low={result['LOW']}, Unknown={result['UNKNOWN']}")
    return result


def get_severity_percentages(counts: Dict[str, Any]) -> Dict[str, str]:
    """Calculate percentages that sum to 100% using proper rounding"""
    total = counts['total_cves']
    
    if total == 0:
        return {k: "0%" for k in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']}
    
    # Calculate exact percentages
    exact_percentages = {
        'CRITICAL': counts['CRITICAL'] * 100 / total,
        'HIGH': counts['HIGH'] * 100 / total,
        'MEDIUM': counts['MEDIUM'] * 100 / total,
        'LOW': counts['LOW'] * 100 / total,
        'UNKNOWN': counts['UNKNOWN'] * 100 / total
    }
    
    # Round to integers
    rounded_percentages = {k: round(v) for k, v in exact_percentages.items()}
    
    # Convert to strings with % symbol
    return {k: f"{v}%" for k, v in rounded_percentages.items()}


def get_severity_distribution_pie() -> Dict[str, Any]:
    """Get severity distribution for pie chart - includes UNKNOWN"""
    print("[Severity Distribution] Using severity card counts for pie chart...")
    
    counts = get_severity_card_counts()
    percentages = get_severity_percentages(counts)
    
    return {
        'counts': counts,
        'percentages': percentages
    }