import requests
from config import NVD_API_URL, NVD_API_KEY
from datetime import datetime, timedelta, timezone
import os
import json
import threading
import time

#Where we'll keep scraped CVEs between sessions (local file cache)
CACHE_PATH = "data/cache/cve_cache.json"
CACHE_TIME_MINUTES = 60     # 1 hour for fresher data
SCHEDULE_HOUR = 0           # Midnight (server local time)

def _is_cache_fresh():
    """Checks if local CVE cache is recent enough"""
    if not os.path.exists(CACHE_PATH):
        return False
    try:
        mtime = datetime.fromtimestamp(os.path.getmtime(CACHE_PATH), tz=timezone.utc)
        now = datetime.now(timezone.utc)
        age_minutes = (now - mtime).total_seconds() / 60
        return age_minutes < CACHE_TIME_MINUTES
    except Exception:
        return False

def _load_from_cache():
    """Loads a cached batch of CVEs from disk"""
    if not os.path.exists(CACHE_PATH):
        return []
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            print(f"[CVEs] Loaded {len(data)} CVEs from cache")
            return data
    except Exception as e:
        print(f"[CVEs] Cache load error: {e}")
        return []

def _save_to_cache(cves):
    """Dump the whole CVE list to disk (creates directory if needed)"""
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cves, f)
        print(f"[CVEs] Saved {len(cves)} CVEs to cache")
    except Exception as e:
        print(f"[CVEs] Cache save error: {e}")

def _parse_cve_datetime(date_str):
    """Parse CVE datetime string into timezone-aware datetime object"""
    if not date_str:
        return None
    
    try:
        # Handle different formats from NVD
        if date_str.endswith('Z'):
            # Format: 2025-08-23T15:15:04.123Z
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        elif 'T' in date_str:
            # Format: 2025-08-23T15:15:04.123
            dt = datetime.fromisoformat(date_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        else:
            # Format: 2025-08-23
            return datetime.strptime(date_str[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError) as e:
        print(f"[CVEs] Warning: Could not parse date '{date_str}': {e}")
        return None

def _is_rejected_cve(cve_data):
    """Check if a CVE is rejected or invalid"""
    cve = cve_data.get("cve", {})
    
    # Check vulnerability status
    vuln_status = cve.get("vulnStatus", "").upper()
    if vuln_status in ["REJECTED", "WITHDRAWN"]:
        return True
    
    # Check description for rejection indicators
    descriptions = cve.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            desc_text = desc.get("value", "").lower()
            # Common rejection patterns
            rejection_indicators = [
                "rejected reason:",
                "not used",
                "** reject **",
                "** reserved **",
                "this cve id has been rejected",
                "this identifier was withdrawn",
                "duplicate of cve-"
            ]
            if any(indicator in desc_text for indicator in rejection_indicators):
                return True
    
    return False

def _fetch_from_nvd(days=30, year=None, month=None):
    """Grabs CVEs from NVD API for the specified time period"""
    now_utc = datetime.now(timezone.utc)
    all_cves = []
    start_index = 0
    results_per_page = 2000
    rejected_count = 0
    
    # Calculate date range based on parameters
    if year and month:
        # Specific month
        pub_start = datetime(year, month, 1, tzinfo=timezone.utc)
        if month == 12:
            pub_end = datetime(year + 1, 1, 1, tzinfo=timezone.utc) - timedelta(seconds=1)
        else:
            pub_end = datetime(year, month + 1, 1, tzinfo=timezone.utc) - timedelta(seconds=1)
    elif year:
        # Specific year
        pub_start = datetime(year, 1, 1, tzinfo=timezone.utc)
        pub_end = datetime(year + 1, 1, 1, tzinfo=timezone.utc) - timedelta(seconds=1)
    else:
        # Recent days
        if days == 1:
            # Today only
            pub_start = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
            pub_end = now_utc
        else:
            # Last N days
            pub_start = (now_utc - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
            pub_end = now_utc

    print(f"[CVEs] Fetching CVEs from {pub_start.isoformat()} to {pub_end.isoformat()}")

    params = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
        "pubStartDate": pub_start.isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
        "pubEndDate": pub_end.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    }
    
    headers = {}
    if NVD_API_KEY:
        headers["apikey"] = NVD_API_KEY
    
    # Loop through NVD pagination
    total_fetched = 0
    while True:
        try:
            print(f"[CVEs] Requesting page {start_index//results_per_page + 1} (start_index: {start_index})")
            response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=60)
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as e:
            print(f"[CVEs] Error fetching CVEs from NVD: {e}")
            break

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            print(f"[CVEs] No more vulnerabilities found")
            break
            
        page_added = 0
        for item in vulnerabilities:
            # Skip rejected CVEs
            if _is_rejected_cve(item):
                rejected_count += 1
                continue
                
            cve = item.get("cve", {})
            published_str = cve.get("published", "")
            if not published_str:
                continue
                
            # Parse and validate publish date
            published_dt = _parse_cve_datetime(published_str)
            if not published_dt:
                continue
                
            # Double-check date range (NVD sometimes returns data outside requested range)
            if not (pub_start <= published_dt <= pub_end):
                continue
                
            cve_id = cve.get("id", "")
            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Skip CVEs without proper descriptions
            if not description or len(description.strip()) < 10:
                continue
            
            severity = "UNKNOWN"
            cvss = None
            metrics = cve.get("metrics", {})
            
            # Try CVSS v3.1, then v3.0, then v2
            if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                sev_metric = metrics["cvssMetricV31"][0]
                severity = sev_metric["cvssData"].get("baseSeverity", severity)
                cvss = sev_metric["cvssData"].get("baseScore", cvss)
            elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                sev_metric = metrics["cvssMetricV30"][0]
                severity = sev_metric["cvssData"].get("baseSeverity", severity)
                cvss = sev_metric["cvssData"].get("baseScore", cvss)
            elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                sev_metric = metrics["cvssMetricV2"][0]
                severity = sev_metric.get("baseSeverity", severity)
                cvss = sev_metric["cvssData"].get("baseScore", cvss)
                
            # Extract CWE
            cwe = None
            for weakness in cve.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwe = desc.get("value")
                        break
                if cwe:
                    break
                    
            # Build CVE record
            cve_record = {
                "ID": cve_id,
                "Description": description,
                "Severity": severity.upper() if severity else "UNKNOWN",
                "CVSS_Score": cvss,
                "CWE": cwe,
                "Published": published_str,
                "References": [ref["url"] for ref in cve.get("references", [])],
                "Products": [],  # This could be enhanced by parsing configuration data
                "metrics": metrics
            }
            
            all_cves.append(cve_record)
            page_added += 1

        total_results = data.get("totalResults", 0)
        total_fetched += page_added
        print(f"[CVEs] Page {start_index//results_per_page + 1}: Added {page_added} valid CVEs, rejected {rejected_count} CVEs. Total so far: {total_fetched}/{total_results}")
        
        # Check if we have all results
        if start_index + results_per_page >= total_results or len(vulnerabilities) < results_per_page:
            print(f"[CVEs] Reached end of results")
            break
            
        start_index += results_per_page
        params["startIndex"] = start_index
        
        # Rate limiting: small delay between requests
        time.sleep(0.1)

    # Sort from newest to oldest
    all_cves.sort(key=lambda x: x.get("Published") or "", reverse=True)
    print(f"[CVEs] Fetch completed. Total valid CVEs: {len(all_cves)}, rejected CVEs filtered out: {rejected_count}")
    return all_cves

def _refresh_cache():
    """Force a cache update from NVD (used by dashboard and scheduler)"""
    print("[CVEs] Refreshing CVE cache from NVD...")
    try:
        cves = _fetch_from_nvd(days=30)  # Get last 30 days for dashboard
        _save_to_cache(cves)
        print(f"[CVEs] Cache refreshed successfully. Fetched {len(cves)} valid CVEs.")
    except Exception as e:
        print(f"[CVEs] Cache refresh failed: {e}")

def _auto_refresh_job():
    """Scheduler thread: wakes up periodically to update cache"""
    while True:
        try:
            # Refresh every hour instead of daily for more current data
            time.sleep(3600)  # 1 hour
            _refresh_cache()
        except Exception as e:
            print(f"[CVEs] Auto-refresh error: {e}")
            time.sleep(300)  # Wait 5 minutes before retrying

def start_auto_cache_scheduler():
    """Start the scheduler thread automatically"""
    t = threading.Thread(target=_auto_refresh_job, daemon=True)
    t.start()
    print("[CVEs] Auto-refresh scheduler started")

def get_all_cves(max_results=None, year=None, month=None, days=None, force_refresh=False):
    """
    Returns the latest CVEs. Uses local cache for dashboard, fresh data for filters.
    
    Args:
        max_results: Maximum number of results to return
        year: Filter by specific year
        month: Filter by specific month (requires year)
        days: Get data from last N days
        force_refresh: Force fresh fetch from NVD API
    """
    
    # If filtering by specific time periods or forced refresh, always fetch fresh
    if year or month or days or force_refresh:
        print(f"[CVEs] Fetching fresh data (year={year}, month={month}, days={days}, force={force_refresh})")
        cves = _fetch_from_nvd(days=days or 30, year=year, month=month)
        
        # Apply max_results limit if specified
        if max_results and len(cves) > max_results:
            cves = cves[:max_results]
            
        return cves
    
    # For dashboard (no filters), try to use cache first
    if _is_cache_fresh():
        print("[CVEs] Using cached data for dashboard")
        cached_cves = _load_from_cache()
        if cached_cves:
            if max_results and len(cached_cves) > max_results:
                return cached_cves[:max_results]
            return cached_cves
    
    # Cache is stale or empty, refresh it
    print("[CVEs] Cache is stale, refreshing...")
    _refresh_cache()
    cached_cves = _load_from_cache()
    
    if max_results and len(cached_cves) > max_results:
        return cached_cves[:max_results]
    return cached_cves

# Start the auto-refresh scheduler when module is imported
start_auto_cache_scheduler()