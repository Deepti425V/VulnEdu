import requests
from config import NVD_API_URL, NVD_API_KEY
from datetime import datetime, timedelta, timezone
import os
import json
import threading
import time

#Where we'll keep scraped CVEs between sessions (local file cache)
CACHE_PATH = "data/cache/cve_cache.json"
CACHE_TIME_MINUTES = 240  # 4 hours - much longer to prevent constant refetching
SCHEDULE_HOUR = 0           # Midnight (server local time)

def _is_cache_fresh():
    """Checks if local CVE cache is recent enough"""
    if not os.path.exists(CACHE_PATH):
        return False
    try:
        mtime = datetime.fromtimestamp(os.path.getmtime(CACHE_PATH), tz=timezone.utc)
        now = datetime.now(timezone.utc)
        age_minutes = (now - mtime).total_seconds() / 60
        print(f"[CVEs] Cache age: {age_minutes:.1f} minutes (fresh if < {CACHE_TIME_MINUTES})")
        return age_minutes < CACHE_TIME_MINUTES
    except Exception as e:
        print(f"[CVEs] Error checking cache freshness: {e}")
        return False

def _load_from_cache():
    """Loads a cached batch of CVEs from disk - ROBUST JSON ONLY"""
    if not os.path.exists(CACHE_PATH):
        print("[CVEs] No cache file found")
        return []
    
    try:
        print(f"[CVEs] Loading cache from {CACHE_PATH}")
        file_size = os.path.getsize(CACHE_PATH)
        print(f"[CVEs] Cache file size: {file_size} bytes")
        
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            # Try to load as JSON
            data = json.load(f)
            
            # Validate the data structure
            if not isinstance(data, list):
                print(f"[CVEs] Cache data is not a list, got {type(data)}")
                return []
            
            # Quick validation of first few items
            valid_count = 0
            for i, item in enumerate(data[:5]):  # Check first 5 items
                if isinstance(item, dict) and 'ID' in item:
                    valid_count += 1
            
            if valid_count == 0:
                print("[CVEs] Cache contains no valid CVE records")
                return []
            
            print(f"[CVEs] Successfully loaded {len(data)} CVEs from cache")
            return data
            
    except json.JSONDecodeError as e:
        print(f"[CVEs] JSON decode error in cache file: {e}")
        print("[CVEs] Corrupted cache detected, will regenerate")
        # Delete corrupted cache
        try:
            os.remove(CACHE_PATH)
            print("[CVEs] Deleted corrupted cache file")
        except:
            pass
        return []
    except Exception as e:
        print(f"[CVEs] Unexpected error loading cache: {e}")
        return []

def _save_to_cache(cves):
    """Dump the whole CVE list to disk as JSON (creates directory if needed)"""
    try:
        print(f"[CVEs] Saving {len(cves)} CVEs to cache...")
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        
        # Validate data before saving
        if not isinstance(cves, list):
            print(f"[CVEs] Error: Cannot save non-list data to cache: {type(cves)}")
            return
        
        # Write atomically - write to temp file first, then rename
        temp_path = CACHE_PATH + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(cves, f, indent=None, separators=(',', ':'))
        
        # Atomic rename
        os.replace(temp_path, CACHE_PATH)
        
        # Verify the save
        saved_size = os.path.getsize(CACHE_PATH)
        print(f"[CVEs] Successfully saved {len(cves)} CVEs to cache ({saved_size} bytes)")
        
    except Exception as e:
        print(f"[CVEs] Error saving cache: {e}")
        # Clean up temp file if it exists
        temp_path = CACHE_PATH + ".tmp"
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass

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
    """Grabs CVEs from NVD API for the specified time period - ONLY WHEN ABSOLUTELY NECESSARY"""
    print(f"[CVEs] WARNING: Making expensive API call! (days={days}, year={year}, month={month})")
    
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
            # Only refresh every 4 hours to avoid excessive API calls
            time.sleep(14400)  # 4 hours
            if not _is_cache_fresh():  # Only refresh if cache is actually stale
                _refresh_cache()
            else:
                print("[CVEs] Cache still fresh, skipping auto-refresh")
        except Exception as e:
            print(f"[CVEs] Auto-refresh error: {e}")
            time.sleep(1800)  # Wait 30 minutes before retrying

def start_auto_cache_scheduler():
    """Start the scheduler thread automatically"""
    t = threading.Thread(target=_auto_refresh_job, daemon=True)
    t.start()
    print("[CVEs] Auto-refresh scheduler started")

def get_all_cves(max_results=None, year=None, month=None, days=None, force_refresh=False):
    """
    Returns the latest CVEs. PRIORITY: Use cached data unless absolutely necessary.
    
    Args:
        max_results: Maximum number of results to return
        year: Filter by specific year
        month: Filter by specific month (requires year)
        days: Get data from last N days
        force_refresh: Force fresh fetch from NVD API (USE SPARINGLY!)
    """
    
    print(f"[CVEs] Request: year={year}, month={month}, days={days}, force_refresh={force_refresh}")
    
    # CRITICAL: Always try cache first, regardless of parameters
    cached_cves = _load_from_cache()
    cache_is_fresh = _is_cache_fresh()
    
    # If we have fresh cached data, use it for most requests
    if cached_cves and cache_is_fresh and not force_refresh:
        print(f"[CVEs] Using cached data ({len(cached_cves)} CVEs)")
        
        # Apply filters to cached data if needed
        filtered_cves = cached_cves
        
        if year:
            filtered_cves = [cve for cve in filtered_cves if cve.get('Published', '')[:4] == str(year)]
            
        if month and year:
            month_str = f"{year}-{month:02d}"
            filtered_cves = [cve for cve in filtered_cves if cve.get('Published', '')[:7] == month_str]
            
        if max_results and len(filtered_cves) > max_results:
            filtered_cves = filtered_cves[:max_results]
            
        print(f"[CVEs] Filtered to {len(filtered_cves)} CVEs from cache")
        return filtered_cves
    
    # Only make API calls if absolutely necessary
    if force_refresh or not cached_cves or not cache_is_fresh:
        print(f"[CVEs] Making API call - force_refresh={force_refresh}, has_cache={bool(cached_cves)}, cache_fresh={cache_is_fresh}")
        
        try:
            # Fetch fresh data
            if year and month:
                fresh_cves = _fetch_from_nvd(year=year, month=month)
            elif year:
                fresh_cves = _fetch_from_nvd(year=year)
            elif days:
                fresh_cves = _fetch_from_nvd(days=days)
            else:
                fresh_cves = _fetch_from_nvd(days=30)
            
            # Update cache with fresh data (but only for recent data)
            if not year and not month:  # Only cache recent data
                _save_to_cache(fresh_cves)
            
            if max_results and len(fresh_cves) > max_results:
                fresh_cves = fresh_cves[:max_results]
                
            return fresh_cves
            
        except Exception as e:
            print(f"[CVEs] API call failed: {e}")
            # Fall back to cached data even if stale
            if cached_cves:
                print(f"[CVEs] Falling back to stale cached data ({len(cached_cves)} CVEs)")
                if max_results and len(cached_cves) > max_results:
                    return cached_cves[:max_results]
                return cached_cves
            else:
                print("[CVEs] No cached data available, returning empty list")
                return []
    
    # This should never be reached, but just in case
    return cached_cves or []

# Start the auto-refresh scheduler when module is imported
start_auto_cache_scheduler()