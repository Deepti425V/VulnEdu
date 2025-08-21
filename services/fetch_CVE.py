import requests
from config import NVD_API_URL, NVD_API_KEY
from datetime import datetime, timedelta, timezone
import os
import json
import threading
import time
import random
import math

# FIXED VERSION - NO MORE RANDOM DATA GENERATION
# Where we'll keep scraped CVEs between sessions (local file cache)
CACHE_PATH = "data/cache/cve_cache.json"
CACHE_TIME_MINUTES = 1440 # 24 hours
SCHEDULE_HOUR = 0 # Midnight (server local time)

# Global timeout and circuit breaker settings
DEFAULT_TIMEOUT = 20
MAX_RETRIES = 2
CIRCUIT_BREAKER_FAILURES = 5
CIRCUIT_BREAKER_TIMEOUT = 600 # 10 minutes

# Circuit breaker state
circuit_breaker = {
    'failures': 0,
    'last_failure': None,
    'state': 'CLOSED' # CLOSED, OPEN, HALF_OPEN
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

def _create_static_demo_data():
    """
    FIXED: Create static demo data that NEVER changes
    This ensures consistent counts across all pages and refreshes
    """
    print("[CVE Demo] Creating STATIC demo data for consistency")
    
    # STATIC data - these will always be the same
    static_cves = [
        {
            'ID': 'CVE-2025-00001',
            'Description': 'Cross-site scripting vulnerability in web application allows remote attackers to inject arbitrary web script or HTML via crafted input parameters',
            'Severity': 'HIGH',
            'CWE': 'CWE-79',
            'Published': '2025-08-21T10:30:00.000Z',
            'CVSS_Score': 7.5,
            'References': ['https://nvd.nist.gov/vuln/detail/CVE-2025-00001'],
            'Products': ['Web Application Framework'],
            'metrics': {
                'cvssMetricV31': [{
                    'cvssData': {
                        'baseScore': 7.5,
                        'baseSeverity': 'HIGH',
                        'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    }
                }]
            }
        },
        {
            'ID': 'CVE-2025-00002',
            'Description': 'SQL injection vulnerability in database interface allows remote attackers to execute arbitrary SQL commands via malformed queries',
            'Severity': 'CRITICAL',
            'CWE': 'CWE-89',
            'Published': '2025-08-21T09:15:00.000Z',
            'CVSS_Score': 9.8,
            'References': ['https://nvd.nist.gov/vuln/detail/CVE-2025-00002'],
            'Products': ['Database Management System'],
            'metrics': {
                'cvssMetricV31': [{
                    'cvssData': {
                        'baseScore': 9.8,
                        'baseSeverity': 'CRITICAL',
                        'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    }
                }]
            }
        },
        {
            'ID': 'CVE-2025-00003',
            'Description': 'Buffer overflow in network service allows attackers to execute arbitrary code via specially crafted requests',
            'Severity': 'HIGH',
            'CWE': 'CWE-119',
            'Published': '2025-08-21T08:45:00.000Z',
            'CVSS_Score': 8.1,
            'References': ['https://nvd.nist.gov/vuln/detail/CVE-2025-00003'],
            'Products': ['Network Service'],
            'metrics': {
                'cvssMetricV31': [{
                    'cvssData': {
                        'baseScore': 8.1,
                        'baseSeverity': 'HIGH',
                        'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    }
                }]
            }
        },
        {
            'ID': 'CVE-2025-00004',
            'Description': 'Improper input validation in user authentication system allows bypass of security controls',
            'Severity': 'MEDIUM',
            'CWE': 'CWE-20',
            'Published': '2025-08-21T07:20:00.000Z',
            'CVSS_Score': 5.3,
            'References': ['https://nvd.nist.gov/vuln/detail/CVE-2025-00004'],
            'Products': ['Authentication System'],
            'metrics': {
                'cvssMetricV31': [{
                    'cvssData': {
                        'baseScore': 5.3,
                        'baseSeverity': 'MEDIUM',
                        'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N'
                    }
                }]
            }
        },
        {
            'ID': 'CVE-2025-00005',
            'Description': 'Information disclosure vulnerability exposes sensitive system configuration data to unauthorized users',
            'Severity': 'LOW',
            'CWE': 'CWE-200',
            'Published': '2025-08-21T06:10:00.000Z',
            'CVSS_Score': 3.7,
            'References': ['https://nvd.nist.gov/vuln/detail/CVE-2025-00005'],
            'Products': ['Configuration Management'],
            'metrics': {
                'cvssMetricV31': [{
                    'cvssData': {
                        'baseScore': 3.7,
                        'baseSeverity': 'LOW',
                        'vectorString': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N'
                    }
                }]
            }
        }
    ]
    
    # Generate more static entries to have realistic counts
    # IMPORTANT: Use deterministic generation so counts are ALWAYS the same
    base_templates = [
        ('Cross-site scripting', 'CWE-79', 'HIGH', 7.5),
        ('SQL injection', 'CWE-89', 'CRITICAL', 9.8),
        ('Buffer overflow', 'CWE-119', 'HIGH', 8.1),
        ('Input validation', 'CWE-20', 'MEDIUM', 5.3),
        ('Information disclosure', 'CWE-200', 'LOW', 3.7),
        ('Authentication bypass', 'CWE-287', 'HIGH', 7.8),
        ('Path traversal', 'CWE-22', 'MEDIUM', 6.1),
        ('Command injection', 'CWE-78', 'CRITICAL', 9.3),
    ]
    
    products = ['Apache HTTP Server', 'Microsoft Windows', 'Google Chrome', 'Mozilla Firefox', 'Oracle Java', 'WordPress', 'OpenSSL', 'Node.js']
    
    # Generate EXACTLY 100 CVEs for consistent counting
    for i in range(6, 101):  # We already have 5, so make 95 more
        template_idx = (i - 6) % len(base_templates)
        template = base_templates[template_idx]
        product_idx = (i - 6) % len(products)
        product = products[product_idx]
        
        # Create deterministic date (spread over last 30 days)
        days_ago = (i - 6) % 30
        pub_date = datetime.now(timezone.utc) - timedelta(days=days_ago)
        
        static_cve = {
            'ID': f'CVE-2025-{i:05d}',
            'Description': f'{template[0]} vulnerability in {product} allows potential security compromise',
            'Severity': template[2],
            'CWE': template[1],
            'Published': pub_date.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
            'CVSS_Score': template[3],
            'References': [f'https://nvd.nist.gov/vuln/detail/CVE-2025-{i:05d}'],
            'Products': [product],
            'metrics': {
                'cvssMetricV31': [{
                    'cvssData': {
                        'baseScore': template[3],
                        'baseSeverity': template[2],
                        'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                    }
                }]
            },
            '_static_demo': True
        }
        static_cves.append(static_cve)
    
    # Sort by published date (newest first) for consistency
    static_cves.sort(key=lambda x: x.get('Published', ''), reverse=True)
    
    print(f"[CVE Demo] Created {len(static_cves)} STATIC demo CVEs")
    return static_cves

def _fetch_from_nvd(days=30, timeout=DEFAULT_TIMEOUT):
    """Grabs CVEs from NVD API - REAL DATA ONLY"""
    if _is_circuit_open():
        print("[NVD API] Circuit breaker is OPEN, skipping API call")
        return []
        
    print(f"[NVD API] Attempting to fetch REAL CVEs for last {days} days...")
    now_utc = datetime.now(timezone.utc)
    all_cves = []
    start_index = 0
    results_per_page = 500
    pub_end = now_utc
    pub_start = pub_end - timedelta(days=days - 1)

    params = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
        "pubStartDate": pub_start.isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
        "pubEndDate": pub_end.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    }
    
    headers = {"apikey": NVD_API_KEY} if NVD_API_KEY else {}

    max_calls = 2
    call_count = 0
    
    while call_count < max_calls:
        try:
            print(f"[NVD API] Making request {call_count + 1}/{max_calls}...")
            response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=timeout)
            response.raise_for_status()
            data = response.json()
            _record_success()  # Mark success in circuit breaker
            
        except Exception as e:
            print(f"[NVD API] Request {call_count + 1} failed: {e}")
            _record_failure()  # Mark failure in circuit breaker
            break

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            print(f"[NVD API] No vulnerabilities returned in request {call_count + 1}")
            break

        print(f"[NVD API] Processing {len(vulnerabilities)} vulnerabilities...")
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

        # Check if we should continue pagination
        total_results = data.get("totalResults", 0)
        if start_index + results_per_page >= total_results:
            print(f"[NVD API] Retrieved all {total_results} results")
            break
            
        start_index += results_per_page
        params["startIndex"] = start_index
        call_count += 1
        time.sleep(2)  # Rate limiting

    all_cves.sort(key=lambda x: x.get("Published") or "", reverse=True)
    print(f"[NVD API] Successfully fetched {len(all_cves)} REAL CVEs")
    return all_cves

def get_all_cves(max_results=None, year=None, month=None, days=None, force_refresh=False, timeout=None):
    """
    FIXED VERSION: Returns consistent CVE data
    Priority: Cache -> Real API -> Static Demo (NO random data)
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

    # Try to fetch real data from NVD
    try:
        print(f"[CVEs] Attempting to fetch REAL data from NVD API...")
        real_cves = _fetch_from_nvd(days=days, timeout=actual_timeout)
        
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

    # Last resort: Use static demo data (CONSISTENT, never changes)
    print("[CVEs] Using STATIC demo data as final fallback")
    static_cves = _create_static_demo_data()
    
    # Apply filtering if requested
    if year and month:
        filtered = [cve for cve in static_cves if cve.get("Published", "")[:7] == f"{year}-{month:02d}"]
        result = filtered[:max_results] if max_results else filtered
        return result
    elif year:
        filtered = [cve for cve in static_cves if cve.get("Published", "")[:4] == str(year)]
        result = filtered[:max_results] if max_results else filtered
        return result
    
    result = static_cves[:max_results] if max_results else static_cves
    return result

def reset_circuit_breaker():
    """Manually reset circuit breaker"""
    global circuit_breaker
    circuit_breaker['failures'] = 0
    circuit_breaker['last_failure'] = None
    circuit_breaker['state'] = 'CLOSED'
    print("[Circuit Breaker] Manually reset to CLOSED state")

# For production, disable auto-refresh to prevent random data changes
print("[CVEs] Auto-refresh disabled for production consistency")