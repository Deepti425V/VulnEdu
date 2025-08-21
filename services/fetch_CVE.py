import requests
from config import NVD_API_URL, NVD_API_KEY
from datetime import datetime, timedelta, timezone
import os
import json
import threading
import time
import random
import math

# REAL DATA ONLY VERSION - NO FALLBACKS OR RANDOM DATA
CACHE_PATH = "data/cache/cve_cache.json"
CACHE_TIME_MINUTES = 360  # 6 hours - reduced for more frequent real data updates
SCHEDULE_HOUR = 0

# Global timeout and circuit breaker settings
DEFAULT_TIMEOUT = 30  # Increased timeout for better API success
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
    """Dump the whole CVE list to disk"""
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cves, f)
        print(f"[CVE Cache] Saved {len(cves)} CVEs to cache")
    except Exception as e:
        print(f"[CVE Cache] Error saving cache: {e}")

def _fetch_from_nvd(days=30, timeout=DEFAULT_TIMEOUT, max_pages=10):
    """Fetch REAL CVEs from NVD API - Enhanced version"""
    if _is_circuit_open():
        print("[NVD API] Circuit breaker is OPEN, skipping API call")
        raise Exception("Circuit breaker is OPEN")
        
    print(f"[NVD API] Fetching REAL CVEs for last {days} days with timeout {timeout}s...")
    now_utc = datetime.now(timezone.utc)
    all_cves = []
    start_index = 0
    results_per_page = 2000  # Maximum allowed by NVD API
    pub_end = now_utc
    pub_start = pub_end - timedelta(days=days)

    params = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
        "pubStartDate": pub_start.isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
        "pubEndDate": pub_end.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    }
    
    headers = {"apikey": NVD_API_KEY} if NVD_API_KEY else {}
    
    page_count = 0
    
    while page_count < max_pages:
        try:
            print(f"[NVD API] Making request {page_count + 1}, startIndex={start_index}...")
            response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=timeout)
            response.raise_for_status()
            data = response.json()
            _record_success()
            
        except Exception as e:
            print(f"[NVD API] Request {page_count + 1} failed: {e}")
            _record_failure()
            if page_count == 0:  # If first request fails, raise exception
                raise e
            else:  # If subsequent requests fail, return what we have
                print(f"[NVD API] Returning {len(all_cves)} CVEs from successful requests")
                break

        vulnerabilities = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)
        
        print(f"[NVD API] Got {len(vulnerabilities)} vulnerabilities, total available: {total_results}")
        
        if not vulnerabilities:
            print(f"[NVD API] No vulnerabilities returned in request {page_count + 1}")
            break

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

            # Pull out CWE if present
            cwe = None
            for weakness in cve.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwe = desc.get("value")
                        break
                if cwe:
                    break

            # Extract product information
            products = []
            for config in cve.get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        cpe_name = cpe_match.get("criteria", "")
                        if cpe_name:
                            # Extract product name from CPE
                            try:
                                parts = cpe_name.split(":")
                                if len(parts) >= 4:
                                    vendor = parts[3]
                                    product = parts[4]
                                    products.append(f"{vendor} {product}")
                            except:
                                pass

            all_cves.append({
                "ID": cve_id,
                "Description": description,
                "Severity": severity,
                "CVSS_Score": cvss,
                "CWE": cwe,
                "Published": published_str,
                "References": [ref["url"] for ref in cve.get("references", [])],
                "Products": list(set(products))[:5],  # Limit to 5 unique products
                "metrics": metrics,
                "_real_data": True,
                "_fetch_timestamp": datetime.now(timezone.utc).isoformat()
            })

        # Check if we should continue pagination
        if start_index + results_per_page >= total_results:
            print(f"[NVD API] Retrieved all {total_results} results")
            break
            
        start_index += results_per_page
        params["startIndex"] = start_index
        page_count += 1
        
        # Rate limiting - NVD allows 5 requests per 30 seconds without API key
        if not NVD_API_KEY:
            time.sleep(6)  # 6 seconds between requests
        else:
            time.sleep(1)  # 1 second with API key

    # Sort by published date (newest first)
    all_cves.sort(key=lambda x: x.get("Published") or "", reverse=True)
    print(f"[NVD API] Successfully fetched {len(all_cves)} REAL CVEs")
    return all_cves

def get_all_cves(max_results=None, year=None, month=None, days=None, force_refresh=False, timeout=None):
    """
    REAL DATA ONLY VERSION - No fallbacks to fake data
    Returns actual CVE data from NVD API or cached real data
    """
    if days is None:
        days = 30
    actual_timeout = timeout if timeout else DEFAULT_TIMEOUT

    print(f"[CVEs] get_all_cves called with: max_results={max_results}, year={year}, month={month}, days={days}, force_refresh={force_refresh}")

    # For current data (no specific year/month), check cache first
    if not year and not month:
        if not force_refresh and _is_cache_fresh():
            cached_cves = _load_from_cache()
            if cached_cves:
                print(f"[CVEs] Using fresh cache data ({len(cached_cves)} CVEs)")
                result = cached_cves[:max_results] if max_results else cached_cves
                return result

        # Try to fetch fresh real data
        try:
            print(f"[CVEs] Fetching fresh REAL data from NVD API...")
            real_cves = _fetch_from_nvd(days=days, timeout=actual_timeout)
            
            if real_cves:
                print(f"[CVEs] Got {len(real_cves)} REAL CVEs from NVD API")
                _save_to_cache(real_cves)
                result = real_cves[:max_results] if max_results else real_cves
                return result
            else:
                print("[CVEs] NVD API returned no data")
                
        except Exception as e:
            print(f"[CVEs] Failed to fetch from NVD API: {e}")

        # If API fails, try to use cache as fallback
        cached_cves = _load_from_cache()
        if cached_cves:
            print(f"[CVEs] Using cached REAL data as fallback ({len(cached_cves)} CVEs)")
            result = cached_cves[:max_results] if max_results else cached_cves
            return result

    # For historical data (specific year/month), try to fetch or use cache
    else:
        # Try cache first for historical data too
        cached_cves = _load_from_cache()
        if cached_cves and not force_refresh:
            print(f"[CVEs] Filtering cached data for year={year}, month={month}")
            
            if year and month:
                filtered = [cve for cve in cached_cves if cve.get("Published", "")[:7] == f"{year}-{month:02d}"]
            elif year:
                filtered = [cve for cve in cached_cves if cve.get("Published", "")[:4] == str(year)]
            else:
                filtered = cached_cves
                
            if filtered:
                result = filtered[:max_results] if max_results else filtered
                print(f"[CVEs] Found {len(result)} cached CVEs for the specified period")
                return result

        # If no cached data for historical period, try to fetch broader data
        try:
            # For historical data, fetch a wider range to ensure we get the requested period
            fetch_days = 365 if year and year < datetime.now().year else days
            print(f"[CVEs] Fetching REAL data for historical period (days={fetch_days})...")
            real_cves = _fetch_from_nvd(days=fetch_days, timeout=actual_timeout, max_pages=5)
            
            if real_cves:
                print(f"[CVEs] Got {len(real_cves)} REAL CVEs, filtering for requested period...")
                _save_to_cache(real_cves)  # Cache the full dataset
                
                # Filter for requested period
                if year and month:
                    filtered = [cve for cve in real_cves if cve.get("Published", "")[:7] == f"{year}-{month:02d}"]
                elif year:
                    filtered = [cve for cve in real_cves if cve.get("Published", "")[:4] == str(year)]
                else:
                    filtered = real_cves
                    
                result = filtered[:max_results] if max_results else filtered
                print(f"[CVEs] Returning {len(result)} CVEs for the requested period")
                return result
                
        except Exception as e:
            print(f"[CVEs] Failed to fetch historical data: {e}")

    # If all else fails, return empty list rather than fake data
    print("[CVEs] No real data available, returning empty list")
    return []

def reset_circuit_breaker():
    """Manually reset circuit breaker"""
    global circuit_breaker
    circuit_breaker['failures'] = 0
    circuit_breaker['last_failure'] = None
    circuit_breaker['state'] = 'CLOSED'
    print("[Circuit Breaker] Manually reset to CLOSED state")

print("[CVEs] REAL DATA ONLY mode - No fallback or random data generation")