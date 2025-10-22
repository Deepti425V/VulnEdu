from collections import Counter
from typing import Dict, Any
from datetime import datetime
from .utils import get_cwe_title

def get_vendor_risk_analysis() -> Dict[str, Any]:
    """Get CWE analysis from LAST 2 YEARS - USES HISTORICAL DATA"""
    print("[Vendor Risk Analysis] Analyzing CWE patterns from last 2 years...")
    
    try:
        from services.data.data_processor import historical_loader
        
        current_year = datetime.now().year
        years_to_analyze = [current_year - 1, current_year]  # Last 2 years
        
        print(f"[Vendor Risk Analysis] Analyzing years: {years_to_analyze}")
        
        cwe_counts = Counter()
        cwe_severity_matrix = {}
        total_cves = 0
        
        for year in years_to_analyze:
            try:
                print(f"[Vendor Risk Analysis] Loading {year}...")
                year_cves = historical_loader.get_year_data(year)
                print(f"[Vendor Risk Analysis] Processing {year}: {len(year_cves)} CVEs")
                
                total_cves += len(year_cves)
                
                for cve in year_cves:
                    cwe = cve.get('CWE')
                    if cwe and cwe.startswith('CWE'):
                        cwe_counts[cwe] += 1
                        if cwe not in cwe_severity_matrix:
                            cwe_severity_matrix[cwe] = Counter()
                        severity = cve.get('Severity', 'UNKNOWN').upper()
                        cwe_severity_matrix[cwe][severity] += 1
                
                # Clear cache after processing
                if str(year) in historical_loader._year_cache:
                    print(f"[Vendor Risk Analysis] Clearing cache for {year} to save memory")
                    del historical_loader._year_cache[str(year)]
            
            except Exception as e:
                print(f"[Vendor Risk Analysis] Error processing {year}: {e}")
                continue
        
        print("[Vendor Risk Analysis] Calculating 30-day CWE counts...")
        cwe_30_day_counts = get_cwe_30_day_counts()
        
        top_cwes = cwe_counts.most_common(20) if cwe_counts else []
        top_5_cwes = top_cwes[:5]
        top_10_cwes = top_cwes[:10]
        
        result = {
            'top_5_cwes': {
                'indices': [cwe for cwe, count in top_5_cwes],
                'labels': [get_cwe_title(cwe) for cwe, count in top_5_cwes],
                'values': [count for cwe, count in top_5_cwes]
            },
            'top_10_cwes': {
                'indices': [cwe for cwe, count in top_10_cwes],
                'labels': [get_cwe_title(cwe) for cwe, count in top_10_cwes],
                'values': [count for cwe, count in top_10_cwes]
            },
            'all_cwes': {
                'indices': [cwe for cwe, count in top_cwes],
                'labels': [get_cwe_title(cwe) for cwe, count in top_cwes],
                'values': [count for cwe, count in top_cwes]
            },
            'severity_matrix': {
                cwe: dict(severity_counts) for cwe, severity_counts in cwe_severity_matrix.items()
            },
            'cwe_30_day_counts': cwe_30_day_counts or {},
            'total_cves_analyzed': total_cves,
            'years_analyzed': years_to_analyze
        }
        
        print(f"[Vendor Risk Analysis] Analyzed {result['total_cves_analyzed']} CVEs, found {len(top_cwes)} unique CWEs")
        if top_5_cwes:
            print(f"[Vendor Risk Analysis] Top 5 CWEs: {[cwe for cwe, count in top_5_cwes]}")
        
        return result
        
    except Exception as e:
        print(f"[Vendor Risk Analysis] Error in analysis: {e}")
        import traceback
        traceback.print_exc()
        return {
            'top_5_cwes': {'indices': [], 'labels': [], 'values': []},
            'top_10_cwes': {'indices': [], 'labels': [], 'values': []},
            'all_cwes': {'indices': [], 'labels': [], 'values': []},
            'severity_matrix': {},
            'cwe_30_day_counts': {},
            'total_cves_analyzed': 0,
            'years_analyzed': []
        }

def get_cwe_30_day_counts() -> Dict[str, int]:
    """Get CWE counts for last 30 days from API data"""
    try:
        from services.data.api_client import api_client
        api_cves = api_client.get_cves_last_30_days()
        
        cwe_30_day_counts = Counter()
        for cve in api_cves:
            cwe = cve.get('CWE')
            if cwe and cwe.startswith('CWE'):
                cwe_30_day_counts[cwe] += 1
        
        print(f"[Vendor Risk Analysis] Found {len(cwe_30_day_counts)} unique CWEs in last 30 days")
        return dict(cwe_30_day_counts)
        
    except Exception as e:
        print(f"[Vendor Risk Analysis] Error getting 30-day CWE counts: {e}")
        return {}

def get_weighted_cwe_analysis() -> Dict[str, Any]:
    """Get weighted CWE analysis from last 2 years - MEMORY SAFE"""
    print("[Vendor Risk Analysis] Calculating weighted CWE scores from last 2 years...")
    
    try:
        from services.data.data_processor import historical_loader
        
        current_year = datetime.now().year
        years_to_analyze = [current_year - 1, current_year]  # Last 2 years
        
        severity_weights = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1,
            'UNKNOWN': 1
        }
        
        cwe_weighted_scores = Counter()
        
        for year in years_to_analyze:
            try:
                year_cves = historical_loader.get_year_data(year)
                
                for cve in year_cves:
                    cwe = cve.get('CWE')
                    if cwe and cwe.startswith('CWE'):
                        severity = cve.get('Severity', 'UNKNOWN').upper()
                        weight = severity_weights.get(severity, 1)
                        cwe_weighted_scores[cwe] += weight
                
                # Clear cache
                if str(year) in historical_loader._year_cache:
                    del historical_loader._year_cache[str(year)]
            
            except Exception as e:
                print(f"[Vendor Risk Analysis] Error processing {year} for weighted analysis: {e}")
                continue
        
        top_weighted = cwe_weighted_scores.most_common(10) if cwe_weighted_scores else []
        
        result = {
            'indices': [cwe for cwe, score in top_weighted],
            'labels': [get_cwe_title(cwe) for cwe, score in top_weighted],
            'values': [score for cwe, score in top_weighted]
        }
        
        print(f"[Vendor Risk Analysis] Weighted analysis complete: {len(top_weighted)} CWEs")
        return result
        
    except Exception as e:
        print(f"[Vendor Risk Analysis] Error in weighted analysis: {e}")
        import traceback
        traceback.print_exc()
        return {'indices': [], 'labels': [], 'values': []}