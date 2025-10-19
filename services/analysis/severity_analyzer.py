from typing import Dict, Any
from collections import Counter

def get_severity_card_counts() -> Dict[str, Any]:
    """Get severity counts for dashboard cards - API ONLY"""
    # LAZY IMPORT - only when function is called
    from services.data.api_client import api_client
    
    print("[Severity Cards] Calculating severity distribution from API...")
    
    cves = api_client.get_cves_last_30_days()
    
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
        'total_cves': len(cves),
        'total_without_unknown': (severity_counts.get('CRITICAL', 0) + 
                                 severity_counts.get('HIGH', 0) + 
                                 severity_counts.get('MEDIUM', 0) + 
                                 severity_counts.get('LOW', 0))
    }
    
    print(f"[Severity Cards] Counts: Critical={result['CRITICAL']}, High={result['HIGH']}, Medium={result['MEDIUM']}, Low={result['LOW']}, Unknown={result['UNKNOWN']}")
    
    return result

def get_severity_percentages(counts: Dict[str, Any]) -> Dict[str, str]:
    """Calculate percentages that sum to 100% using proper rounding"""
    total = counts['total_cves']
    
    if total == 0:
        return {k: "0%" for k in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']}
    
    exact_percentages = {
        'CRITICAL': (counts['CRITICAL'] * 100 / total),
        'HIGH': (counts['HIGH'] * 100 / total),
        'MEDIUM': (counts['MEDIUM'] * 100 / total),
        'LOW': (counts['LOW'] * 100 / total),
        'UNKNOWN': (counts['UNKNOWN'] * 100 / total)
    }
    
    rounded_percentages = {k: round(v) for k, v in exact_percentages.items()}
    
    total_rounded = sum(rounded_percentages.values())
    difference = 100 - total_rounded
    
    if difference != 0:
        fractional_parts = {k: exact_percentages[k] - rounded_percentages[k]
                          for k in exact_percentages.keys()}
        
        if difference > 0:
            for _ in range(difference):
                max_key = max(fractional_parts.keys(), key=lambda k: fractional_parts[k])
                rounded_percentages[max_key] += 1
                fractional_parts[max_key] -= 1
        else:
            for _ in range(abs(difference)):
                min_key = min(fractional_parts.keys(), key=lambda k: fractional_parts[k])
                rounded_percentages[min_key] -= 1
                fractional_parts[min_key] += 1
    
    return {k: f"{v}%" for k, v in rounded_percentages.items()}

def get_severity_distribution_pie() -> Dict[str, Any]:
    """Get severity distribution for pie chart - includes UNKNOWN"""
    print("[Severity Distribution] Using severity card counts for pie chart...")
    
    counts = get_severity_card_counts()
    percentages = get_severity_percentages(counts)
    
    result = {
        'counts': counts,
        'percentages': percentages,
        'chart_data': {
            'labels': ['Critical', 'High', 'Medium', 'Low', 'Unknown'],
            'values': [
                counts['CRITICAL'],
                counts['HIGH'],
                counts['MEDIUM'],
                counts['LOW'],
                counts['UNKNOWN']
            ],
            'colors': ['#f55855', '#f8a541', '#3b8ded', '#42d392', '#6b7280']
        },
        'total_including_unknown': counts['total_cves']
    }
    
    print(f"[Severity Distribution] Pie chart data generated with {result['total_including_unknown']} total CVEs")
    
    return result