import requests
from config import NVD_API_URL, NVD_API_KEY
from datetime import datetime, timedelta, timezone
import os
import json
import threading
import time
import random
import math

# FIXED VERSION - GET ALL CVEs + PROPER GRAPH DATA
CACHE_PATH = "data/cache/cve_cache.json"
CACHE_TIME_MINUTES = 1440 # 24 hours
SCHEDULE_HOUR = 0

# Global timeout and circuit breaker settings
DEFAULT_TIMEOUT = 30  # Increased timeout
MAX_RETRIES = 3
CIRCUIT_BREAKER_FAILURES = 5
CIRCUIT_BREAKER_TIMEOUT = 600

# Circuit breaker state
circuit_breaker = {
    'failures': 0,
    'last_failure': None,
    'state': 'CLOSED'
}

def _is_circuit_open():
    """Check if circuit breaker is open"""
    global circuit_breaker
    if circuit_breaker['state'] == 'OPEN':
        if circuit_breaker['last_failure']:
            time_since_failure = time.time() - circuit_breaker['last_failure']
            if time_since_failure > CIRCUIT_BREAKER_TIMEOUT:
                circuit_breaker['state'] = 'HALF_OPEN'
                return False
            return True
    return False

def _record_failure():
    """Record a failure in the circuit breaker"""
    global circuit_breaker
    circuit_breaker['failures'] += 1
    circuit_breaker['last_failure'] = time.time()
    if circuit_breaker['failures'] >= CIRCUIT_BREAKER_FAILURES:
        circuit_breaker['state'] = 'OPEN'
        print(f"[Circuit Breaker] OPEN - Too many failures ({circuit_breaker['failures']})")

def _record_success():
    """Record a success in the circuit breaker"""
    global circuit_breaker
    circuit_breaker['failures'] = 0
    circuit_breaker['state'] = 'CLOSED'

def _is_cache_fresh():
    """Checks if local CVE cache is recent enough"""
    if not os.path.exists(CACHE_PATH):
        return False
    mtime = datetime.fromtimestamp(os.path.getmtime(CACHE_PATH))
    now = datetime.now()
    return (now - mtime).total_seconds() < CACHE_TIME_MINUTES * 60

def _load_from_cache():
    """Loads a cached batch of CVEs from disk"""
    if not os.path.exists(CACHE_PATH):
        return []
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        print(f"[CVE Cache] Loaded {len(data)} CVEs from cache")
        return data
    except Exception as e:
        print(f"[CVE Cache] Error loading cache: {e}")
        return []

def _save_to_cache(cves):
    """Dump the whole CVE list to disk (creates directory if needed)"""
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cves, f)
        print(f"[CVE Cache] Saved {len(cves)} CVEs to cache")
    except Exception as e:
        print(f"[CVE Cache] Error saving cache: {e}")

def _fetch_from_nvd_all_pages(days=30, timeout=DEFAULT_TIMEOUT):
    """
    FIXED: Fetch ALL CVEs from NVD API (not limited to 1000)
    This will get ALL available CVEs for the specified time period
    """
    if _is_circuit_open():
        print("[NVD API] Circuit breaker is OPEN, skipping API call")
        return []
        
    print(f"[NVD API] Fetching ALL CVEs for last {days} days (no limit)...")
    now_utc = datetime.now(timezone.utc)
    all_cves = []
    start_index = 0
    results_per_page = 2000  # Maximum allowed by NVD API
    pub_end = now_utc
    pub_start = pub_end - timedelta(days=days - 1)

    params = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
        "pubStartDate": pub_start.isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
        "pubEndDate": pub_end.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    }
    
    headers = {"apikey": NVD_API_KEY} if NVD_API_KEY else {}

    # Keep fetching until we get all pages
    page_count = 0
    max_pages = 50  # Safety limit to prevent infinite loops
    
    while page_count < max_pages:
        try:
            print(f"[NVD API] Fetching page {page_count + 1} (starting at index {start_index})...")
            response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=timeout)
            response.raise_for_status()
            data = response.json()
            _record_success()
            
        except Exception as e:
            print(f"[NVD API] Page {page_count + 1} failed: {e}")
            _record_failure()
            break

        vulnerabilities = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)
        
        if not vulnerabilities:
            print(f"[NVD API] No more vulnerabilities on page {page_count + 1}")
            break

        print(f"[NVD API] Processing {len(vulnerabilities)} vulnerabilities from page {page_count + 1}...")
        
        for item in vulnerabilities:
            cve = item.get("cve", {})
            published_str = cve.get("published", "")
            if not published_str:
                continue

            cve_id = cve.get("id", "")
            description = next(
                (desc["value"] for desc in cve.get("descriptions", []) if desc.get("lang") == "en"),
                ""
            )

            severity = "UNKNOWN"
            cvss = None
            metrics = cve.get("metrics", {})
            
            # Try CVSS v3.1, then v3.0, then v2
            if "cvssMetricV31" in metrics:
                sev_metric = metrics["cvssMetricV31"][0]
                severity = sev_metric["cvssData"].get("baseSeverity", severity)
                cvss = sev_metric["cvssData"].get("baseScore", cvss)
            elif "cvssMetricV30" in metrics:
                sev_metric = metrics["cvssMetricV30"][0]
                severity = sev_metric["cvssData"].get("baseSeverity", severity)
                cvss = sev_metric["cvssData"].get("baseScore", cvss)
            elif "cvssMetricV2" in metrics:
                sev_metric = metrics["cvssMetricV2"][0]
                severity = sev_metric.get("baseSeverity", severity)
                cvss = sev_metric["cvssData"].get("baseScore", cvss)

            # Pull out CWE if present
            cwe = None
            for weakness in cve.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwe = desc.get("value")
                        break
                if cwe:
                    break

            all_cves.append({
                "ID": cve_id,
                "Description": description,
                "Severity": severity,
                "CVSS_Score": cvss,
                "CWE": cwe,
                "Published": published_str,
                "References": [ref["url"] for ref in cve.get("references", [])],
                "Products": [],
                "metrics": metrics,
                "_real_data": True
            })

        # Check if we've got all results
        fetched_so_far = start_index + len(vulnerabilities)
        print(f"[NVD API] Fetched {fetched_so_far} of {total_results} total CVEs")
        
        if fetched_so_far >= total_results:
            print(f"[NVD API] Got all {total_results} available CVEs!")
            break
            
        # Prepare for next page
        start_index += results_per_page
        params["startIndex"] = start_index
        page_count += 1
        
        # Rate limiting - be nice to NVD API
        time.sleep(1)

    all_cves.sort(key=lambda x: x.get("Published") or "", reverse=True)
    print(f"[NVD API] Successfully fetched {len(all_cves)} REAL CVEs across {page_count + 1} pages")
    return all_cves

def get_all_cves(max_results=None, year=None, month=None, days=None, force_refresh=False, timeout=None):
    """
    FIXED VERSION: Get ALL available CVEs (not limited to 1000)
    """
    if days is None:
        days = 30
    actual_timeout = timeout if timeout else DEFAULT_TIMEOUT

    print(f"[CVEs] get_all_cves called with: max_results={max_results}, year={year}, month={month}, force_refresh={force_refresh}")

    # If asking for current data and cache is fresh, use cache
    if not year and not month and not force_refresh and _is_cache_fresh():
        cached_cves = _load_from_cache()
        if cached_cves:
            print(f"[CVEs] Using fresh cache data ({len(cached_cves)} CVEs)")
            result = cached_cves[:max_results] if max_results else cached_cves
            return result

    # Try to fetch ALL real data from NVD
    try:
        print(f"[CVEs] Attempting to fetch ALL REAL data from NVD API...")
        real_cves = _fetch_from_nvd_all_pages(days=days, timeout=actual_timeout)
        
        if real_cves and len(real_cves) > 0:
            print(f"[CVEs] Got {len(real_cves)} REAL CVEs from NVD API")
            # Save to cache
            _save_to_cache(real_cves)
            
            # Apply filtering if requested
            if year and month:
                filtered = [cve for cve in real_cves if cve.get("Published", "")[:7] == f"{year}-{month:02d}"]
                result = filtered[:max_results] if max_results else filtered
                print(f"[CVEs] Filtered to {len(result)} CVEs for {year}-{month:02d}")
                return result
            elif year:
                filtered = [cve for cve in real_cves if cve.get("Published", "")[:4] == str(year)]
                result = filtered[:max_results] if max_results else filtered
                print(f"[CVEs] Filtered to {len(result)} CVEs for year {year}")
                return result
            
            result = real_cves[:max_results] if max_results else real_cves
            return result
        else:
            print("[CVEs] NVD API returned no data")
            
    except Exception as e:
        print(f"[CVEs] Failed to fetch from NVD API: {e}")

    # Fallback to cache if API fails
    cached_cves = _load_from_cache()
    if cached_cves:
        print(f"[CVEs] Using cached data as fallback ({len(cached_cves)} CVEs)")
        result = cached_cves[:max_results] if max_results else cached_cves
        return result

    # Last resort: Empty list (better than fake data)
    print("[CVEs] No data available - returning empty list")
    return []

def get_daily_cve_data_for_30_days():
    """
    FIXED: Get REAL daily CVE data for last 30 days
    This generates proper 30-day graph data
    """
    print("[Daily CVE] Generating REAL 30-day data...")
    
    try:
        # Get CVEs for last 30 days
        cves = get_all_cves(days=30)
        
        # Create 30-day date range
        today = datetime.now(timezone.utc).date()
        dates = [today - timedelta(days=i) for i in range(29, -1, -1)]  # Last 30 days in order
        
        # Count CVEs per day
        daily_counts = {date: 0 for date in dates}
        
        for cve in cves:
            published_str = cve.get('Published', '')
            if published_str:
                try:
                    # Parse the published date
                    published_dt = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                    published_date = published_dt.date()
                    
                    if published_date in daily_counts:
                        daily_counts[published_date] += 1
                except Exception:
                    continue
        
        # Convert to chart format
        labels = [date.strftime('%Y-%m-%d') for date in dates]
        values = [daily_counts[date] for date in dates]
        
        total_cves = sum(values)
        print(f"[Daily CVE] Generated 30-day data: {total_cves} total CVEs across 30 days")
        
        return {
            'labels': labels,
            'values': values
        }
        
    except Exception as e:
        print(f"[Daily CVE] Error generating daily data: {e}")
        # Return empty 30-day structure
        today = datetime.now(timezone.utc).date()
        dates = [today - timedelta(days=i) for i in range(29, -1, -1)]
        return {
            'labels': [date.strftime('%Y-%m-%d') for date in dates],
            'values': [0] * 30
        }

def get_monthly_cve_data_for_5_years():
    """
    FIXED: Get REAL monthly CVE data for last 5 years
    This generates proper 5-year graph data
    """
    print("[Monthly CVE] Generating REAL 5-year data...")
    
    try:
        # Get CVEs for last 5 years (1825 days)
        cves = get_all_cves(days=1825)  # 5 years = 1825 days
        
        # Create 5-year month range
        now = datetime.now(timezone.utc)
        months = []
        
        # Generate last 60 months (5 years)
        for i in range(59, -1, -1):
            month_date = now - timedelta(days=30 * i)
            month_key = month_date.strftime('%Y-%m')
            if month_key not in [m[1] for m in months]:  # Avoid duplicates
                months.append((month_date.year, month_date.month, month_key))
        
        # Count CVEs per month
        monthly_counts = {month_key: 0 for _, _, month_key in months}
        
        for cve in cves:
            published_str = cve.get('Published', '')
            if published_str and len(published_str) >= 7:
                month_key = published_str[:7]  # YYYY-MM
                if month_key in monthly_counts:
                    monthly_counts[month_key] += 1
        
        # Convert to chart format (chronological order)
        sorted_months = sorted(monthly_counts.items())
        labels = [month for month, _ in sorted_months]
        values = [count for _, count in sorted_months]
        
        total_cves = sum(values)
        print(f"[Monthly CVE] Generated 5-year data: {total_cves} total CVEs across {len(labels)} months")
        
        return {
            'labels': labels,
            'values': values
        }
        
    except Exception as e:
        print(f"[Monthly CVE] Error generating monthly data: {e}")
        # Return empty 5-year structure
        now = datetime.now(timezone.utc)
        months = []
        for i in range(59, -1, -1):
            month_date = now - timedelta(days=30 * i)
            months.append(month_date.strftime('%Y-%m'))
        
        return {
            'labels': list(set(months))[:60],  # Last 60 months
            'values': [0] * 60
        }

def reset_circuit_breaker():
    """Manually reset circuit breaker"""
    global circuit_breaker
    circuit_breaker['failures'] = 0
    circuit_breaker['last_failure'] = None
    circuit_breaker['state'] = 'CLOSED'
    print("[Circuit Breaker] Manually reset to CLOSED state")

print("[CVEs] Enhanced fetch module loaded - can get ALL CVEs + proper graph data")