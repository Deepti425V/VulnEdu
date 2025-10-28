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
    """Enhanced NVD API client with database support and aggressive memory optimization"""
    def __init__(self):
        self.base_url = config.NVD_API_URL
        self.api_key = config.NVD_API_KEY
        self.timeout = config.API_TIMEOUT
        self.last_request_time = 0
        
        # Proper rate limiting based on API key availability
        if self.api_key:
            self.min_request_interval = 30 / 50  # 50 requests per 30 seconds with key
        else:
            self.min_request_interval = 30 / 5  # 5 requests per 30 seconds without key
        
        # Session for connection reuse
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})
        
        # Lightweight cache for metadata only
        self._cache_timestamps = {}
        self._cache_lock = threading.Lock()
        
        # Database integration
        from database import db_manager
        self.db = db_manager
        
        # Import cache manager for memory optimization
        from services.cache.cache_manager import cache_manager
        self.cache_manager = cache_manager
        
        logger.info("[API Client] Initialized with API key: %s", bool(self.api_key))

    def _rate_limit(self):
        """Proper rate limiting with logging"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            sleep_time = self.min_request_interval - elapsed
            logger.debug("Rate limiting - sleeping for %.2f seconds", sleep_time)
            time.sleep(sleep_time)
        self.last_request_time = time.time()

    def _is_cache_valid(self, cache_key: str, max_age: int = 900) -> bool:
        """Check if cache entry is still valid (default 15 minutes)"""
        with self._cache_lock:
            if cache_key not in self._cache_timestamps:
                return False
            age = time.time() - self._cache_timestamps[cache_key]
            return age < max_age

    def _set_cache_timestamp(self, cache_key: str):
        """Set cache timestamp"""
        with self._cache_lock:
            self._cache_timestamps[cache_key] = time.time()

    def get_cves_last_30_days(self) -> List[Dict[str, Any]]:
        """Get CVEs from last 30 days - OPTIMIZED for memory

        Returns a list of processed CVE dicts. This method is robust:
         - Accepts cached data of different shapes (list/dict) but only uses lists.
         - Handles both 'vulnerabilities' (NVD v2) and 'CVE_Items' (legacy) API formats.
         - Guards against infinite loops and runaway memory usage.
         - Always returns a list (never bool), so callers can safely call len().
        """
        cache_key = "cves_30_days"
        # Check memory usage via cache manager (may clear caches proactively)
        try:
            self.cache_manager.check_memory_usage()
        except Exception:
            # Cache manager may raise in edge cases; don't crash the whole flow
            logger.debug("[API Client] cache_manager.check_memory_usage() failed (non-fatal)", exc_info=True)

        # Try cache first (call once and inspect type)
        try:
            cached_raw = self.cache_manager.get_api_data_30_days()
        except Exception:
            cached_raw = None

        if cached_raw:
            # Accept either a list, or a dict containing a list under a known key
            if isinstance(cached_raw, list):
                cached_cves = cached_raw
            elif isinstance(cached_raw, dict) and "cves" in cached_raw and isinstance(cached_raw["cves"], list):
                cached_cves = cached_raw["cves"]
            else:
                logger.warning("[API Client] Cache returned unexpected type (%s) - ignoring cached value", type(cached_raw).__name__)
                cached_cves = None

            if cached_cves is not None:
                logger.info("[API Client] Using cached CVE data (%d CVEs)", len(cached_cves))
                # If DB is enabled, prefer reading from DB for consistent paging
                if self.db.use_database:
                    try:
                        return self.db.get_cves_by_filter(limit=2000)
                    except Exception:
                        logger.debug("[API Client] db.get_cves_by_filter failed - falling back to cached list", exc_info=True)
                return cached_cves

        # Not cached - fetch fresh
        logger.info("[API Client] Fetching fresh CVE data from API")

        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=30)
        all_cves: List[Dict[str, Any]] = []
        start_index = 0
        results_per_page = 2000

        # Safety caps to avoid runaway loops on constrained hosts (Render, etc.)
        max_results = getattr(config, "API_MAX_RESULTS_SAFE", 20000)  # configurable via config
        safety_counter = 0
        max_iterations = getattr(config, "API_MAX_ITERATIONS_SAFE", 25)

        try:
            while True:
                safety_counter += 1
                if safety_counter > max_iterations:
                    logger.error("[API Client] Safety stop: too many iterations (%d)", safety_counter)
                    break

                # Ask cache manager to check memory between pages
                try:
                    self.cache_manager.check_memory_usage()
                except Exception:
                    logger.debug("[API Client] cache_manager.check_memory_usage() failed during loop (non-fatal)", exc_info=True)

                params = {
                    "resultsPerPage": results_per_page,
                    "startIndex": start_index,
                    "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
                }

                logger.info(f"API request: startIndex={start_index}, resultsPerPage={results_per_page}")
                self._rate_limit()

                try:
                    response = self.session.get(self.base_url, params=params, timeout=self.timeout)
                except requests.exceptions.RequestException as e:
                    logger.error(f"API request exception: {e}")
                    break

                if response.status_code != 200:
                    logger.error(f"API request failed: {response.status_code} - {response.text}")
                    break

                try:
                    data = response.json()
                except json.JSONDecodeError:
                    logger.error("[API Client] Failed to parse JSON response")
                    break

                # Support new and legacy response formats
                vulnerabilities = []
                if isinstance(data, dict):
                    if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
                        vulnerabilities = data["vulnerabilities"]
                    elif "CVE_Items" in data and isinstance(data["CVE_Items"], list):
                        # Convert legacy CVE_Items into v2-like objects: {"cve": {...}}
                        vulnerabilities = [{"cve": item.get("cve", {})} for item in data["CVE_Items"]]
                    else:
                        # Unexpected top-level keys — log and break to avoid misbehaviour
                        logger.warning("[API Client] Unexpected API response keys: %s", list(data.keys()))
                        # still try to recover by checking for list-like responses
                        if isinstance(data, list):
                            # treat as a list of CVE entries (best-effort)
                            for entry in data:
                                if isinstance(entry, dict) and "cve" in entry:
                                    vulnerabilities.append({"cve": entry.get("cve", {})})
                else:
                    # If data is not dict, bail
                    logger.error("[API Client] Unexpected JSON type from API: %s", type(data).__name__)
                    break

                total_results = data.get("totalResults", len(vulnerabilities) if isinstance(vulnerabilities, list) else 0)
                logger.info(f"Got {len(vulnerabilities)} CVEs (total available: {total_results})")

                # Ensure vulnerabilities is a list
                if not isinstance(vulnerabilities, list):
                    logger.error("[API Client] 'vulnerabilities' is not a list; stopping")
                    break

                if not vulnerabilities:
                    # No items in this page — stop fetching further
                    break

                # Process the page into our internal, memory-optimized representation
                processed_batch: List[Dict[str, Any]] = []
                for item in vulnerabilities:
                    # item may already be {'cve': {...}} or might be the cve object itself
                    if isinstance(item, dict) and "cve" in item:
                        cve_data = item.get("cve", {}) or {}
                    elif isinstance(item, dict):
                        cve_data = item
                    else:
                        cve_data = {}

                    processed = self._process_cve_item(cve_data)
                    if processed:
                        processed_batch.append(processed)

                # Persist small batches to DB if available (helps memory)
                if processed_batch and self.db.use_database:
                    try:
                        self.db.save_cves_batch(processed_batch)
                    except Exception:
                        logger.debug("[API Client] db.save_cves_batch failed (non-fatal)", exc_info=True)

                all_cves.extend(processed_batch)

                # Force GC to keep memory low on constrained hosts
                try:
                    gc.collect()
                except Exception:
                    pass

                # Advance start index BEFORE evaluating break conditions to avoid repeating same page
                start_index += results_per_page

                # Break if we've consumed all available results
                if start_index >= int(total_results):
                    break

                # If last page (fewer items than page size), break
                if len(vulnerabilities) < results_per_page:
                    break

                # Safety cap on how many CVEs we accumulate
                if len(all_cves) >= max_results:
                    logger.warning("[API Client] Hit safety limit of %d results; stopping fetch", max_results)
                    break

                # small sleep to reduce risk of being throttled
                time.sleep(0.1)

            # End while loop

            if not all_cves:
                logger.warning("[API Client] No CVEs processed - this may indicate a parsing or API format issue")
            else:
                logger.info("[API Client] Successfully processed %d CVEs", len(all_cves))

            # Sort by published date (newest first) if values present
            try:
                all_cves.sort(key=lambda x: x.get('Published', ''), reverse=True)
            except Exception:
                logger.debug("[API Client] Sorting processed CVEs failed (non-fatal)", exc_info=True)

            # Cache results (store list)
            try:
                self.cache_manager.set_api_data_30_days(all_cves)
            except Exception:
                logger.debug("[API Client] cache_manager.set_api_data_30_days() failed (non-fatal)", exc_info=True)

            # Record timestamp in our lightweight timestamp map
            try:
                self._set_cache_timestamp(cache_key)
            except Exception:
                pass

            logger.info("Successfully fetched and cached %d CVEs", len(all_cves))

            # Ensure we always return a list (avoid returning bool/None)
            if not isinstance(all_cves, list):
                return []
            return all_cves

        except Exception as e:
            logger.error(f"Error fetching CVEs: {e}", exc_info=True)
            # Fallback to DB if available
            try:
                if self.db.use_database:
                    logger.info("[API Client] Using database fallback")
                    return self.db.get_all_cves(limit=1000) or []
            except Exception:
                logger.debug("[API Client] Database fallback failed (non-fatal)", exc_info=True)
            return []

    def _process_cve_item(self, cve_data: Dict) -> Optional[Dict]:
        """Convert NVD CVE format to internal format - MEMORY OPTIMIZED"""
        try:
            if not cve_data or not isinstance(cve_data, dict):
                return None

            # Accept both v2-style 'id' and legacy CVE_data_meta ID field
            cve_id = cve_data.get("id") or cve_data.get("CVE_data_meta", {}).get("ID")
            if not cve_id:
                return None

            # Extract description (support multiple schema variants)
            description = ""
            # v2 style: descriptions -> list of dicts with 'lang'/'value'
            for desc in cve_data.get("descriptions", []) or []:
                if isinstance(desc, dict) and desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            # legacy style: description.description_data
            if not description and isinstance(cve_data.get("description"), dict):
                for desc in cve_data["description"].get("description_data", []) or []:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break

            # Extract severity and CVSS
            severity = "UNKNOWN"
            cvss_score = None
            metrics = cve_data.get("metrics", {}) or {}

            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(version)
                if metric_list:
                    try:
                        metric = metric_list[0]
                        cvss_data = metric.get("cvssData", {}) or {}
                        potential_severity = cvss_data.get("baseSeverity") or cvss_data.get("severity")
                        potential_score = cvss_data.get("baseScore") or cvss_data.get("score")
                        if potential_severity:
                            severity = str(potential_severity).upper()
                            cvss_score = potential_score
                            break
                    except Exception:
                        continue

            # Extract CWE (best-effort)
            cwe = None
            for weakness in cve_data.get("weaknesses", []) or []:
                for desc in weakness.get("description", []) or []:
                    if desc.get("lang") == "en":
                        cwe_value = desc.get("value")
                        if cwe_value and str(cwe_value).upper().startswith("CWE"):
                            cwe = cwe_value
                            break
                if cwe:
                    break

            # Extract references (limit to first 5)
            references = []
            if "references" in cve_data and isinstance(cve_data.get("references"), list):
                for ref in cve_data.get("references", [])[:5]:
                    if isinstance(ref, dict):
                        url = ref.get("url") or ref.get("reference") or None
                        if url:
                            references.append(url)
            # legacy structure: references.reference_data
            elif isinstance(cve_data.get("references"), dict):
                for ref in cve_data["references"].get("reference_data", [])[:5]:
                    url = ref.get("url")
                    if url:
                        references.append(url)

            published = cve_data.get("published") or cve_data.get("publishedDate") or ""
            last_modified = cve_data.get("lastModified") or cve_data.get("lastModifiedDate") or ""

            return {
                "ID": cve_id,
                "Description": description or "No description available",
                "Severity": severity or "UNKNOWN",
                "CVSS_Score": cvss_score,
                "CWE": cwe,
                "Published": published,
                "lastModified": last_modified,
                "References": references,
                "Products": [],  # Skip heavy product lists to save memory
                "metrics": {}
            }
        except Exception as e:
            logger.error(f"Error processing CVE {cve_data.get('id', 'unknown')}: {e}", exc_info=True)
            return None

    def get_cve_detail(self, cve_id: str) -> Dict[str, Any]:
        """Get details for a specific CVE"""
        try:
            # 1. Check database first
            if self.db.use_database:
                try:
                    db_cve = self.db.get_cve_detail(cve_id)
                    if db_cve:
                        logger.info(f"CVE {cve_id} retrieved from database")
                        return db_cve
                except Exception:
                    logger.debug("[API Client] db.get_cve_detail failed (non-fatal)", exc_info=True)

            # 2. Check local cached recent CVEs
            try:
                local_cves = self.get_cves_last_30_days()
                if isinstance(local_cves, list):
                    matching_cve = next((cve for cve in local_cves if cve.get('ID') == cve_id), None)
                    if matching_cve:
                        logger.info(f"CVE {cve_id} retrieved from local cache")
                        return matching_cve
            except Exception:
                logger.debug("[API Client] local cache lookup failed (non-fatal)", exc_info=True)

            # 3. Fetch from NVD API
            logger.info(f"Attempting to fetch CVE {cve_id} from NVD API")
            self._rate_limit()

            response = self.session.get(
                f"{self.base_url}?cveId={cve_id}",
                timeout=self.timeout
            )

            logger.info(f"API Response Status: {response.status_code}")

            if response.status_code != 200:
                logger.warning(f"API request failed for {cve_id}: {response.status_code}")
                return self._generate_fallback_cve(cve_id, f"API request failed with status {response.status_code}")

            try:
                data = response.json()
            except json.JSONDecodeError:
                logger.error(f"Failed to parse JSON for {cve_id}")
                return self._generate_fallback_cve(cve_id, "Invalid API response format")

            vulnerabilities = []
            if isinstance(data, dict):
                if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
                    vulnerabilities = data["vulnerabilities"]
                elif "CVE_Items" in data and isinstance(data["CVE_Items"], list):
                    vulnerabilities = [{"cve": item.get("cve", {})} for item in data["CVE_Items"]]
            else:
                logger.warning(f"Unexpected API payload type when fetching {cve_id}: {type(data).__name__}")

            if not vulnerabilities:
                logger.warning(f"No vulnerability data found for {cve_id}")
                return self._generate_fallback_cve(cve_id, "No vulnerability data available")

            # Process the first vulnerability (assuming single CVE)
            cve_entry = vulnerabilities[0]
            if isinstance(cve_entry, dict) and "cve" in cve_entry:
                cve_data = cve_entry.get("cve", {}) or {}
            else:
                cve_data = cve_entry if isinstance(cve_entry, dict) else {}

            processed_cve = self._process_cve_item(cve_data)

            if not processed_cve:
                logger.warning(f"Unable to process CVE details for {cve_id}")
                return self._generate_fallback_cve(cve_id, "Unable to process CVE details")

            # Save to database
            if self.db.use_database:
                try:
                    self.db.save_cve_detail(processed_cve)
                except Exception:
                    logger.debug("[API Client] db.save_cve_detail failed (non-fatal)", exc_info=True)

            return processed_cve

        except Exception as e:
            logger.error(f"Unexpected error retrieving CVE {cve_id}: {e}", exc_info=True)
            return self._generate_fallback_cve(cve_id, str(e))

    def _generate_fallback_cve(self, cve_id: str, error_message: str = "") -> Dict[str, Any]:
        """Generate a fallback CVE structure when no details are available"""
        return {
            'ID': cve_id,
            'Description': f'No details available for {cve_id}. {error_message}',
            'Severity': 'UNKNOWN',
            'CVSS_Score': None,
            'CWE': 'Unknown',
            'Published': '',
            'lastModified': '',
            'References': [],
            'Products': [],
            'metrics': {},
            'Error': error_message
        }

    def clear_cache(self):
        """Clear all cached data"""
        with self._cache_lock:
            self._cache_timestamps.clear()
        
        # Clear database cache if available
        try:
            if self.db.use_database:
                self.db.clear_all_cves()
        except Exception:
            logger.debug("[API Client] db.clear_all_cves failed (non-fatal)", exc_info=True)
            
        try:
            # best-effort clear cache manager if present
            self.cache_manager.clear_api_data_30_days()
        except Exception:
            # not fatal
            pass
            
        logger.info("Cache cleared")

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._cache_lock:
            stats = {
                'cached_entries': len(self._cache_timestamps),
                'cache_ages': {}
            }
            
            current_time = time.time()
            for key, timestamp in self._cache_timestamps.items():
                age_minutes = int((current_time - timestamp) / 60)
                stats['cache_ages'][key] = f"{age_minutes} minutes"
            
            # Add database stats if available
            try:
                if self.db.use_database:
                    stats['database'] = self.db.get_stats()
            except Exception:
                logger.debug("[API Client] db.get_stats failed (non-fatal)", exc_info=True)
                
            return stats

# Global API client instance
api_client = NVDApiClient()
