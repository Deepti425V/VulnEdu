import requests
from config import NVD_API_URL, NVD_API_KEY
from datetime import datetime, timedelta, timezone
import os
import json
import threading
import time

CACHE_PATH = "data/cache/cve_cache.json"
CACHE_TIME_MINUTES = 1440  # 24 hours
SCHEDULE_HOUR = 0  # Midnight (server local time)

def _is_cache_fresh():
    if not os.path.exists(CACHE_PATH):
        return False
    mtime = datetime.fromtimestamp(os.path.getmtime(CACHE_PATH))
    now = datetime.now()
    return (now - mtime).total_seconds() < CACHE_TIME_MINUTES * 60

def _load_from_cache():
    if not os.path.exists(CACHE_PATH):
        return []
    try:
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def _save_to_cache(cves):
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    with open(CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(cves, f)

def _fetch_from_nvd(days=30):
    now_utc = datetime.now(timezone.utc)
    all_cves = []
    start_index = 0
    results_per_page = 2000
    pub_end = now_utc
    pub_start = pub_end - timedelta(days=days - 1)
    params = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
        "pubStartDate": pub_start.isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
        "pubEndDate": pub_end.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    }
    headers = {"apikey": NVD_API_KEY}
    while True:
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
            cve_id = cve.get("id", "")
            description = next((desc["value"] for desc in cve.get("descriptions", []) if desc.get("lang") == "en"), "")
            severity = "UNKNOWN"
            cvss = None
            metrics = cve.get("metrics", {})
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
        params["startIndex"] = start_index
    all_cves.sort(key=lambda x: x.get("Published") or "", reverse=True)
    return all_cves

def _refresh_cache():
    print("[CVEs] Auto-refreshing CVE cache from NVD...")
    cves = _fetch_from_nvd(days=30)
    _save_to_cache(cves)
    print(f"[CVEs] Cache refreshed. Fetched {len(cves)} CVEs.")

def _auto_refresh_job():
    while True:
        now = datetime.now()
        next_run = now.replace(hour=SCHEDULE_HOUR, minute=0, second=0, microsecond=0)
        if now >= next_run:
            next_run = next_run + timedelta(days=1)
        delay = (next_run - now).total_seconds()
        print(f"[CVEs] Next auto-refresh scheduled at {next_run}. Sleeping {int(delay)} seconds...")
        time.sleep(max(delay, 0))
        try:
            _refresh_cache()
        except Exception as e:
            print(f"[CVEs] Cache refresh FAILED: {e}")

def start_auto_cache_scheduler():
    t = threading.Thread(target=_auto_refresh_job, daemon=True)
    t.start()

def get_all_cves(max_results=None, year=None, month=None, days=None, force_refresh=False):
    """
    Returns CVEs from cache. NEVER fetches in a user request.
    Background thread is responsible for keeping cache fresh.
    """
    # Background scheduler autostarts when module is imported
    # Only return from cache for user-facing functions
    cves = []
    if _is_cache_fresh():
        cves = _load_from_cache()
    elif os.path.exists(CACHE_PATH):
        # serve stale cache if needed
        cves = _load_from_cache()
    else:
        print("[CVEs] No cache available. Returning empty list.")
        return []
    # Filtering (if year/month/days)
    filtered_cves = []
    if year and month:
        for cve in cves:
            pub = cve.get("Published", "")
            if len(pub) >= 7:
                if pub[:4] == str(year) and int(pub[5:7]) == int(month):
                    filtered_cves.append(cve)
        return filtered_cves
    elif year:
        for cve in cves:
            pub = cve.get("Published", "")
            if len(pub) >= 4 and pub[:4] == str(year):
                filtered_cves.append(cve)
        return filtered_cves
    elif max_results is not None:
        return cves[:max_results]
    else:
        return cves

# Fire off cache auto-refresh background thread at import
start_auto_cache_scheduler()
