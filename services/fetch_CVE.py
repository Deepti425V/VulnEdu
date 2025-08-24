# fetch_CVE.py - COMPLETE REPLACEMENT FILE
import requests
from datetime import datetime, timedelta, timezone
import os
import json
import threading
import time

# Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
CACHE_PATH = "data/cache/cve_cache.json"
CACHE_TIME_MINUTES = 1440  # 24 hours
API_TIMEOUT = 25  # Render timeout is 30s, leave 5s buffer

# Circuit breaker for API failures
class CircuitBreaker:
    def __init__(self, failure_threshold=3, timeout=300):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'
    
    def call(self, func, *args, **kwargs):
        if self.state == 'OPEN':
            if time.time() - self.last_failure_time > self.timeout:
                self.state = 'HALF_OPEN'
            else:
                raise Exception("Circuit breaker is OPEN - API temporarily unavailable")
        
        try:
            result = func(*args, **kwargs)
            if self.state == 'HALF_OPEN':
                self.state = 'CLOSED'
                self.failure_count = 0
            return result
        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()
            if self.failure_count >= self.failure_threshold:
                self.state = 'OPEN'
            raise e

# Global circuit breaker
circuit_breaker = CircuitBreaker()

def _is_cache_fresh():
    """Check if cache is recent enough"""
    if not os.path.exists(CACHE_PATH):
        return False
    
    try:
        mtime = datetime.fromtimestamp(os.path.getmtime(CACHE_PATH))
        now = datetime.now()
        return (now - mtime).total_seconds() < CACHE_TIME_MINUTES * 60
    except Exception:
        return False

def _load_from_cache():
    """Load cached CVEs"""
    if not os.path.exists(CACHE_PATH):
        return []
    
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[CVEs] Cache load error: {e}")
        return []

def _save_to_cache(cves):
    """Save CVEs to cache"""
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cves, f)
        print(f"[CVEs] Cached {len(cves)} CVEs")
    except Exception as e:
        print(f"[CVEs] Cache save error: {e}")

def _fetch_from_nvd(days=30, max_results=1000):
    """Fetch CVEs from NVD API with strict limits"""
    print(f"[CVEs] Fetching last {days} days (max {max_results})")
    
    now_utc = datetime.now(timezone.utc)
    all_cves = []
    
    # Calculate date range
    if days == 1:
        pub_start = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
        pub_end = now_utc
    else:
        pub_start = (now_utc - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
        pub_end = now_utc
    
    # API parameters - REDUCED page size
    params = {
        "resultsPerPage": 500,  # Smaller page size
        "startIndex": 0,
        "pubStartDate": pub_start.isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
        "pubEndDate": pub_end.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    }
    
    headers = {}
    if NVD_API_KEY:
        headers["apikey"] = NVD_API_KEY
    
    # Limit to 2 requests maximum to prevent timeouts
    request_count = 0
    max_requests = 2
    
    while len(all_cves) < max_results and request_count < max_requests:
        try:
            print(f"[CVEs] Request {request_count + 1}/{max_requests}")
            
            def make_request():
                return requests.get(NVD_API_URL, params=params, headers=headers, timeout=API_TIMEOUT)
            
            response = circuit_breaker.call(make_request)
            response.raise_for_status()
            
            # Parse JSON with error handling
            try:
                data = response.json()
            except json.JSONDecodeError as e:
                print(f"[CVEs] JSON error: {e}")
                break
            
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break
            
            # Process vulnerabilities quickly
            batch_cves = []
            for item in vulnerabilities[:500]:  # Limit processing
                if len(all_cves) + len(batch_cves) >= max_results:
                    break
                
                try:
                    cve = item.get("cve", {})
                    published_str = cve.get("published", "")
                    if not published_str:
                        continue
                    
                    # Basic validation
                    cve_id = cve.get("id", "")
                    if not cve_id:
                        continue
                    
                    # Extract description
                    description = ""
                    for desc in cve.get("descriptions", []):
                        if desc.get("lang") == "en":
                            description = desc.get("value", "")
                            break
                    
                    # Extract severity
                    severity = "UNKNOWN"
                    cvss = None
                    metrics = cve.get("metrics", {})
                    
                    # Try different CVSS versions
                    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if version in metrics and metrics[version]:
                            metric = metrics[version][0]
                            if version == "cvssMetricV2":
                                severity = metric.get("baseSeverity", severity)
                                cvss = metric.get("cvssData", {}).get("baseScore", cvss)
                            else:
                                cvss_data = metric.get("cvssData", {})
                                severity = cvss_data.get("baseSeverity", severity)
                                cvss = cvss_data.get("baseScore", cvss)
                            break
                    
                    # Extract CWE
                    cwe = None
                    for weakness in cve.get("weaknesses", []):
                        for desc in weakness.get("description", []):
                            if desc.get("lang") == "en":
                                cwe = desc.get("value")
                                break
                        if cwe:
                            break
                    
                    # Create CVE record
                    batch_cves.append({
                        "ID": cve_id,
                        "Description": description,
                        "Severity": severity,
                        "CVSS_Score": cvss,
                        "CWE": cwe,
                        "Published": published_str,
                        "References": [ref.get("url", "") for ref in cve.get("references", [])][:3],  # Limit refs
                        "Products": []
                    })
                    
                except Exception as e:
                    print(f"[CVEs] Error processing CVE: {e}")
                    continue
            
            all_cves.extend(batch_cves)
            print(f"[CVEs] Processed {len(batch_cves)} CVEs (total: {len(all_cves)})")
            
            # Check if we need more
            total_results = data.get("totalResults", 0)
            if params["startIndex"] + 500 >= total_results or len(batch_cves) == 0:
                break
            
            # Next page
            params["startIndex"] += 500
            request_count += 1
            
            # Rate limiting
            if NVD_API_KEY:
                time.sleep(0.1)
            else:
                time.sleep(1)
                
        except Exception as e:
            print(f"[CVEs] Request error: {e}")
            break
    
    # Sort by date
    all_cves.sort(key=lambda x: x.get("Published") or "", reverse=True)
    print(f"[CVEs] Fetch complete: {len(all_cves)} CVEs")
    return all_cves

def _refresh_cache():
    """Refresh cache with error handling"""
    print("[CVEs] Refreshing cache...")
    try:
        cves = _fetch_from_nvd(days=7, max_results=500)  # Reduced scope
        _save_to_cache(cves)
        print(f"[CVEs] Cache refreshed: {len(cves)} CVEs")
    except Exception as e:
        print(f"[CVEs] Cache refresh failed: {e}")

def get_all_cves(max_results=None, year=None, month=None, days=None, force_refresh=False):
    """Get CVEs with caching and limits"""
    
    # Use cache for dashboard
    if not year and not month and not days and not force_refresh:
        if _is_cache_fresh():
            cached = _load_from_cache()
            return cached[:max_results] if max_results else cached
        else:
            # Refresh cache if stale
            _refresh_cache()
            cached = _load_from_cache()
            return cached[:max_results] if max_results else cached
    
    # For filters, fetch limited live data
    fetch_limit = min(max_results or 500, 500)
    cves = _fetch_from_nvd(days=days or 7, max_results=fetch_limit)
    
    # Apply year/month filtering
    if year and month:
        filtered = []
        for cve in cves:
            pub = cve.get("Published", "")
            if pub and len(pub) >= 7:
                try:
                    if pub[:4] == str(year) and int(pub[5:7]) == int(month):
                        filtered.append(cve)
                except (ValueError, IndexError):
                    continue
        return filtered
    
    elif year:
        filtered = []
        for cve in cves:
            pub = cve.get("Published", "")
            if pub and len(pub) >= 4:
                try:
                    if pub[:4] == str(year):
                        filtered.append(cve)
                except (ValueError, IndexError):
                    continue
        return filtered
    
    return cves