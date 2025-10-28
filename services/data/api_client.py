import requests
import json
import time
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
import config
import threading
import logging
import gc

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NVDApiClient:
    """Enhanced NVD API client compatible with VulnEdu orchestrator"""
    def __init__(self):
        self.base_url = config.NVD_API_URL
        self.api_key = config.NVD_API_KEY
        self.timeout = config.API_TIMEOUT
        self.last_request_time = 0

        # Rate limiting
        if self.api_key:
            self.min_request_interval = 30 / 50  # 50 requests per 30 seconds with key
        else:
            self.min_request_interval = 30 / 5   # 5 requests per 30 seconds without key

        # Session for persistent connections
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})

        # Lightweight in-memory cache
        self._cache_30_days: Optional[List[Dict[str, Any]]] = None
        self._cache_lock = threading.Lock()

        # Database integration
        from database import db_manager
        self.db = db_manager

        # Cache manager for memory optimization
        from services.cache.cache_manager import cache_manager
        self.cache_manager = cache_manager

        logger.info("[API Client] Initialized with API key: %s", bool(self.api_key))

    def _rate_limit(self):
        """Ensure requests respect the NVD API limits"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            time.sleep(self.min_request_interval - elapsed)
        self.last_request_time = time.time()

    def _process_cve_item(self, cve_data: Dict) -> Optional[Dict]:
        """Process raw NVD CVE item to internal format"""
        try:
            if not cve_data:
                return None
            cve_id = cve_data.get("id")
            if not cve_id:
                return None

            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            severity = "UNKNOWN"
            cvss_score = None
            metrics = cve_data.get("metrics", {})
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(version)
                if metric_list:
                    metric = metric_list[0]
                    cvss_data = metric.get("cvssData", {})
                    severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
                    cvss_score = cvss_data.get("baseScore", None)
                    break

            cwe = None
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        val = desc.get("value")
                        if val and val.startswith("CWE"):
                            cwe = val
                            break
                if cwe:
                    break

            references = [r["url"] for r in cve_data.get("references", [])[:5] if "url" in r]

            return {
                "ID": cve_id,
                "Description": description or "No description available",
                "Severity": severity,
                "CVSS_Score": cvss_score,
                "CWE": cwe,
                "Published": cve_data.get("published", ""),
                "lastModified": cve_data.get("lastModified", ""),
                "References": references,
                "Products": [],
                "metrics": {}
            }
        except Exception as e:
            logger.error(f"Error processing CVE {cve_data.get('id', 'unknown')}: {e}")
            return None

    def get_cves_last_30_days(self) -> List[Dict[str, Any]]:
        """Return CVEs from last 30 days, always as a list"""
        with self._cache_lock:
            if self._cache_30_days is not None and isinstance(self._cache_30_days, list):
                logger.info("[API Client] Using cached CVE data (%d CVEs)", len(self._cache_30_days))
                return self._cache_30_days
            elif self._cache_30_days is not None:
                logger.warning("[API Client] Cache returned unexpected type - ignoring cached value")

        logger.info("[API Client] Fetching fresh CVE data from API")
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=30)

        all_cves: List[Dict[str, Any]] = []
        start_index = 0
        results_per_page = 2000

        try:
            while True:
                self._rate_limit()
                params = {
                    "resultsPerPage": results_per_page,
                    "startIndex": start_index,
                    "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
                }
                response = self.session.get(self.base_url, params=params, timeout=self.timeout)
                if response.status_code != 200:
                    logger.error(f"API request failed: {response.status_code} - {response.text}")
                    break

                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                total_results = data.get("totalResults", 0)

                if not vulnerabilities:
                    break

                processed_batch = [self._process_cve_item(item.get("cve", {})) for item in vulnerabilities]
                processed_batch = [p for p in processed_batch if p is not None]

                if processed_batch and self.db.use_database:
                    self.db.save_cves_batch(processed_batch)

                all_cves.extend(processed_batch)
                gc.collect()

                start_index += results_per_page
                if start_index >= total_results:
                    break

            all_cves.sort(key=lambda x: x.get('Published', ''), reverse=True)

            with self._cache_lock:
                self._cache_30_days = all_cves

            logger.info(f"[API Client] Successfully fetched and cached {len(all_cves)} CVEs")
            return all_cves

        except Exception as e:
            logger.error(f"Error fetching CVEs: {e}")
            if self.db.use_database:
                logger.info("Using database fallback")
                return self.db.get_all_cves(limit=1000)
            return []

    def get_cve_detail(self, cve_id: str) -> Dict[str, Any]:
        """Get details for a specific CVE"""
        try:
            if self.db.use_database:
                db_cve = self.db.get_cve_detail(cve_id)
                if db_cve:
                    return db_cve

            cached_cves = self.get_cves_last_30_days()
            match = next((cve for cve in cached_cves if cve['ID'] == cve_id), None)
            if match:
                return match

            logger.info(f"[API Client] Fetching CVE {cve_id} from API")
            self._rate_limit()
            response = self.session.get(f"{self.base_url}?cveId={cve_id}", timeout=self.timeout)
            if response.status_code != 200:
                return self._generate_fallback_cve(cve_id, f"Status {response.status_code}")

            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return self._generate_fallback_cve(cve_id, "No vulnerability data")

            processed = self._process_cve_item(vulns[0].get("cve", {}))
            if not processed:
                return self._generate_fallback_cve(cve_id, "Processing failed")

            if self.db.use_database:
                self.db.save_cve_detail(processed)

            return processed
        except Exception as e:
            logger.error(f"Error getting CVE detail for {cve_id}: {e}")
            return self._generate_fallback_cve(cve_id, str(e))

    def _generate_fallback_cve(self, cve_id: str, error_message: str = "") -> Dict[str, Any]:
        """Fallback CVE structure if API or processing fails"""
        return {
            "ID": cve_id,
            "Description": f"No details available for {cve_id}. {error_message}",
            "Severity": "UNKNOWN",
            "CVSS_Score": None,
            "CWE": "Unknown",
            "Published": "",
            "lastModified": "",
            "References": [],
            "Products": [],
            "metrics": {},
            "Error": error_message
        }

    def clear_cache(self):
        """Clear all cached data"""
        with self._cache_lock:
            self._cache_30_days = None
        if self.db.use_database:
            self.db.clear_all_cves()
        logger.info("[API Client] Cache cleared")

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._cache_lock:
            stats = {
                "cache_30_days_entries": len(self._cache_30_days) if self._cache_30_days else 0,
            }
            if self.db.use_database:
                stats["database"] = self.db.get_stats()
            return stats


# Global API client instance
api_client = NVDApiClient()
