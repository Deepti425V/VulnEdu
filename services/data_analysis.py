from .fetch_CVE import get_all_cves, get_cached_timeline_data
from .group_CVE import group_by_severity, group_by_cwe, timeline_group, top_n_cwes
from .cwe_map import cwe_title, CWE_TITLES
from functools import lru_cache
from datetime import datetime
from collections import defaultdict

def get_dashboard_metrics():
    """Get counts for each severity level using real cached data"""
    cves = get_all_cves(days=30)  # This uses cache automatically
    return group_by_severity(cves)

def get_timeline_data():
    """Get timeline data using the new real caching system"""
    return get_cached_timeline_data()

def get_severity_stats():
    """Get severity distribution statistics using real data"""
    cves = get_all_cves(days=30)
    counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0
    }
    for cve in cves:
        sev = cve.get("Severity", "").upper()
        if sev in counts:
            counts[sev] += 1
    return counts

def get_cwe_radar():
    """Prepare data for CWE radar chart using real data"""
    cves = get_all_cves(days=30)
    cwe_counts = defaultdict(int)
    for cve in cves:
        cwe = cve.get("CWE")
        if cwe:
            cwe_counts[cwe] += 1
    
    top_cwes = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:7]
    return {
        "labels": [cwe_title(cwe) for cwe, _ in top_cwes],
        "values": [count for _, count in top_cwes]
    }

def get_yearly_trends():
    """Get yearly CVE counts using real timeline data"""
    timeline_data = get_cached_timeline_data()
    
    # Convert monthly data to yearly
    yearly_counts = defaultdict(int)
    for i, month_label in enumerate(timeline_data.get('labels', [])):
        if len(month_label) >= 4:  # Format: "YYYY-MM"
            year = int(month_label[:4])
            count = timeline_data.get('values', [])[i] if i < len(timeline_data.get('values', [])) else 0
            yearly_counts[year] += count
    
    # Get last 5 years
    current_year = datetime.now().year
    years = list(range(current_year - 4, current_year + 1))
    
    return {
        "labels": years,
        "values": [yearly_counts.get(year, 0) for year in years]
    }

def get_top_cwes(n=7):
    """Get top N CWEs by frequency using real data"""
    cves = get_all_cves(days=30)
    cwe_counts = group_by_cwe(cves)
    return [cwe_title(cwe) for cwe in top_n_cwes(cwe_counts, n=n)]

def get_latest_cves(n=5):
    """Get most recent N CVEs using real data"""
    cves = get_all_cves(days=30)
    sorted_cves = sorted(
        cves, 
        key=lambda x: x.get('Published') or '', 
        reverse=True
    )
    return [
        {
            "id": cve.get("ID"),
            "description": cve.get("Description"),
            "severity": cve.get("Severity", "UNKNOWN")
        } 
        for cve in sorted_cves[:n]
    ]

def get_product_count():
    """Count unique affected products using real data"""
    cves = get_all_cves(days=30)
    prods = set()
    for cve in cves:
        for prod in cve.get("Products", []):
            prods.add(prod)
    return len(prods)

def search_cves(q=None, severity=None):
    """Search CVEs by query and severity filter using real data"""
    cves = get_all_cves(days=30)  # You might want to increase this for search
    results = []
    for cve in cves:
        _id = cve.get("ID", "")
        _desc = cve.get("Description", "")
        _sev = cve.get("Severity", "UNKNOWN")
        
        if q and q.lower() not in _id.lower() and q.lower() not in _desc.lower():
            continue
        if severity and _sev.upper() != severity.upper():
            continue
            
        results.append({
            "id": _id,
            "description": _desc,
            "severity": _sev
        })
    return results

def get_cve_by_id(cve_id):
    """Get single CVE details by ID"""
    from .nvd_api import get_cve_detail
    return get_cve_detail(cve_id)

def get_cwe_severity_data():
    """For each CWE, count CVEs at each severity using real data"""
    cves = get_all_cves(days=30)
    cwe_severity = defaultdict(lambda: defaultdict(int))
    
    for cve in cves:
        cwe = cve.get('CWE')
        if cwe:
            severity = cve.get('Severity', 'UNKNOWN').upper()
            if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                cwe_severity[cwe][severity] += 1

    # Always include every CWE from CWE_TITLES, even if it's all zeros
    cwe_keys = list(CWE_TITLES.keys())
    return {
        'labels': [cwe_title(cwe) for cwe in cwe_keys],
        'data': {
            'CRITICAL': [cwe_severity[cwe].get('CRITICAL', 0) for cwe in cwe_keys],
            'HIGH': [cwe_severity[cwe].get('HIGH', 0) for cwe in cwe_keys],
            'MEDIUM': [cwe_severity[cwe].get('MEDIUM', 0) for cwe in cwe_keys],
            'LOW': [cwe_severity[cwe].get('LOW', 0) for cwe in cwe_keys]
        }
    }