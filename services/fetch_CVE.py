import requests
from config import NVD_API_URL, NVD_API_KEY
from datetime import datetime, timedelta, timezone
import os
import json
import threading
import time
from collections import defaultdict

#Where we'll keep scraped CVEs between sessions (local file cache)
CACHE_PATH = "data/cache/cve_cache.json"
TIMELINE_CACHE_PATH = "data/cache/timeline_cache.json"
CACHE_TIME_HOURS = 6  # Cache valid for 6 hours
SCHEDULE_HOUR = 0  # Midnight refresh

def _ensure_cache_dir():
    """Ensure cache directory exists"""
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)

def _is_cache_fresh(cache_file):
    """Check if cache is still fresh"""
    if not os.path.exists(cache_file):
        return False
    mtime = datetime.fromtimestamp(os.path.getmtime(cache_file))
    now = datetime.now()
    return (now - mtime).total_seconds() < CACHE_TIME_HOURS * 3600

def _load_from_cache(cache_file):
    """Load data from cache file"""
    if not os.path.exists(cache_file):
        return None
    try:
        with open(cache_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def _save_to_cache(data, cache_file):
    """Save data to cache file"""
    _ensure_cache_dir()
    try:
        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Failed to save cache to {cache_file}: {e}")

def _fetch_from_nvd(days=30, year=None, month=None):
    """
    Fetch CVEs from NVD API - this is your old logic integrated with caching
    """
    print(f"[CVE] Fetching from NVD API (days={days}, year={year}, month={month})")
    
    now_utc = datetime.now(timezone.utc)
    all_cves = []
    start_index = 0
    results_per_page = 2000

    while True:
        # Set up date parameters based on your old logic
        if year and month:
            start_date = datetime(year, month, 1, 0, 0, 0, tzinfo=timezone.utc)
            if month == 12:
                end_date = datetime(year + 1, 1, 1, 0, 0, 0, tzinfo=timezone.utc) - timedelta(milliseconds=1)
            else:
                end_date = datetime(year, month + 1, 1, 0, 0, 0, tzinfo=timezone.utc) - timedelta(milliseconds=1)
            
            if end_date > now_utc:
                end_date = now_utc
                
            params = {
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
                "pubStartDate": start_date.isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                "pubEndDate": end_date.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
            }
        elif year and not month:
            start_date = datetime(year, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
            end_date = datetime(year + 1, 1, 1, 0, 0, 0, tzinfo=timezone.utc) - timedelta(milliseconds=1)
            
            if end_date > now_utc:
                end_date = now_utc
                
            params = {
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
                "pubStartDate": start_date.isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                "pubEndDate": end_date.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
            }
        else:
            # Default: last N days
            pub_end = now_utc
            pub_start = pub_end - timedelta(days=days-1)
            params = {
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
                "pubStartDate": pub_start.isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                "pubEndDate": pub_end.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
            }

        headers = {"apikey": NVD_API_KEY}

        try:
            response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=60)
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as e:
            print(f"Error fetching CVEs from NVD: {e}")
            break

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break

        for item in vulnerabilities:
            cve = item.get("cve", {})
            published_str = cve.get("published", "")
            if not published_str:
                continue

            try:
                published_dt = datetime.strptime(published_str[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                continue

            if published_dt > now_utc:
                continue

            # Apply year/month filters
            if year and month:
                if not (published_dt.year == year and published_dt.month == month):
                    continue
            elif year:
                if published_dt.year != year:
                    continue

            cve_id = cve.get("id", "")
            description = next(
                (desc["value"] for desc in cve.get("descriptions", []) if desc.get("lang") == "en"), ""
            )
            
            severity = "UNKNOWN"
            cvss = None
            metrics = cve.get("metrics", {})

            # Extract CVSS data (same as your old logic)
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

            # Extract CWE
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
                "metrics": metrics
            })

        total_results = data.get("totalResults", 0)
        if start_index + results_per_page >= total_results:
            break
        start_index += results_per_page

    all_cves.sort(key=lambda x: x.get("Published") or "", reverse=True)
    print(f"[CVE] Fetched {len(all_cves)} CVEs from NVD")
    return all_cves

def generate_real_timeline_data():
    """
    Generate REAL timeline data from NVD API (replaces the simulated version)
    This creates monthly CVE counts for the last 36 months
    """
    print("[Timeline] Generating real timeline data from NVD...")
    
    now = datetime.now(timezone.utc)
    timeline_counts = defaultdict(int)
    
    # Get last 36 months of data
    for months_back in range(36):
        target_date = now - timedelta(days=30 * months_back)
        year = target_date.year
        month = target_date.month
        
        month_key = f"{year}-{month:02d}"
        
        print(f"[Timeline] Fetching {month_key}...")
        
        try:
            # Fetch CVEs for this specific month
            month_cves = _fetch_from_nvd(year=year, month=month)
            timeline_counts[month_key] = len(month_cves)
            print(f"[Timeline] {month_key}: {len(month_cves)} CVEs")
            
            # Small delay to avoid hitting rate limits
            time.sleep(0.1)
            
        except Exception as e:
            print(f"[Timeline] Error fetching {month_key}: {e}")
            timeline_counts[month_key] = 0
    
    # Sort chronologically
    sorted_months = sorted(timeline_counts.items())
    
    timeline_data = {
        "labels": [item[0] for item in sorted_months],
        "values": [item[1] for item in sorted_months],
        "generated_at": now.isoformat()
    }
    
    print(f"[Timeline] Generated timeline with {len(sorted_months)} months")
    return timeline_data

def get_cached_timeline_data():
    """
    Get timeline data with caching - this replaces your generate_timeline_data()
    """
    if _is_cache_fresh(TIMELINE_CACHE_PATH):
        print("[Timeline] Using cached timeline data")
        cached_data = _load_from_cache(TIMELINE_CACHE_PATH)
        if cached_data:
            return cached_data
    
    print("[Timeline] Cache miss or expired, generating fresh timeline data...")
    timeline_data = generate_real_timeline_data()
    _save_to_cache(timeline_data, TIMELINE_CACHE_PATH)
    return timeline_data

def _refresh_cache():
    """Force refresh of both CVE cache and timeline cache"""
    print("[CVE] Force refreshing all caches...")
    
    # Refresh main CVE cache (last 30 days)
    recent_cves = _fetch_from_nvd(days=30)
    _save_to_cache(recent_cves, CACHE_PATH)
    print(f"[CVE] Cached {len(recent_cves)} recent CVEs")
    
    # Refresh timeline cache
    timeline_data = generate_real_timeline_data()
    _save_to_cache(timeline_data, TIMELINE_CACHE_PATH)
    print("[CVE] Timeline cache refreshed")

def _auto_refresh_job():
    """Background thread for automatic cache refresh"""
    while True:
        now = datetime.now()
        next_run = now.replace(hour=SCHEDULE_HOUR, minute=0, second=0, microsecond=0)
        
        if now >= next_run:
            next_run = next_run + timedelta(days=1)
        
        delay = (next_run - now).total_seconds()
        print(f"[CVE] Next auto-refresh scheduled at {next_run}")
        time.sleep(max(delay, 0))
        
        try:
            _refresh_cache()
        except Exception as e:
            print(f"[CVE] Auto-refresh failed: {e}")

def start_auto_cache_scheduler():
    """Start the background cache refresh scheduler"""
    t = threading.Thread(target=_auto_refresh_job, daemon=True)
    t.start()

def get_all_cves(max_results=None, year=None, month=None, days=None, force_refresh=False):
    """
    Main function to get CVEs - integrates your old logic with caching
    """
    # For specific year/month queries, always fetch fresh (like your old version)
    if year or month or force_refresh:
        print(f"[CVE] Fetching fresh data (year={year}, month={month}, force={force_refresh})")
        return _fetch_from_nvd(days=days or 30, year=year, month=month)
    
    # For general queries, use cache if available
    if _is_cache_fresh(CACHE_PATH):
        print("[CVE] Using cached CVE data")
        cached_data = _load_from_cache(CACHE_PATH)
        if cached_data:
            return cached_data
    
    # Cache miss or expired - fetch fresh
    print("[CVE] Cache miss, fetching fresh data...")
    cves = _fetch_from_nvd(days=days or 30)
    _save_to_cache(cves, CACHE_PATH)
    return cves

#Fire off background auto-refresh thread at module import (so dashboard cache is always ready)
start_auto_cache_scheduler()