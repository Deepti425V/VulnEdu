import requests
import json
import time
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
import config
import threading
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NVDApiClient:
    """Enhanced NVD API client with proper rate limiting and caching"""
    
    def __init__(self):
        self.base_url = config.NVD_API_URL
        self.api_key = config.NVD_API_KEY
        self.timeout = config.API_TIMEOUT
        self.last_request_time = 0
        # Proper rate limiting based on API key availability
        if self.api_key:
            self.min_request_interval = 30 / 50  # 50 requests per 30 seconds with key
        else:
            self.min_request_interval = 30 / 5   # 5 requests per 30 seconds without key
        
        # Session for connection reuse
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})
        
        # Cache for storing data
        self._cache = {}
        self._cache_timestamps = {}
        self._cache_lock = threading.Lock()

    def _rate_limit(self):
        """Proper rate limiting with logging"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            sleep_time = self.min_request_interval - elapsed
            logger.info(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
        self.last_request_time = time.time()

    def _is_cache_valid(self, cache_key: str, max_age: int = 900) -> bool:
        """Check if cache entry is still valid (default 15 minutes)"""
        with self._cache_lock:
            if cache_key not in self._cache_timestamps:
                return False
            age = time.time() - self._cache_timestamps[cache_key]
            return age < max_age

    def _set_cache(self, cache_key: str, data: Any):
        """Set cache entry with timestamp"""
        with self._cache_lock:
            self._cache[cache_key] = data
            self._cache_timestamps[cache_key] = time.time()

    def _get_cache(self, cache_key: str) -> Any:
        """Get cache entry"""
        with self._cache_lock:
            return self._cache.get(cache_key)

    def get_cves_last_30_days(self) -> List[Dict[str, Any]]:
        """Get CVEs from last 30 days with proper caching"""
        cache_key = "cves_30_days"
        
        # Check cache first
        if self._is_cache_valid(cache_key, max_age=900):  # 15 minutes
            logger.info("Using cached 30-day CVE data")
            return self._get_cache(cache_key)
        
        logger.info("Fetching fresh CVE data from API")
        
        # Calculate date range
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=30)
        
        all_cves = []
        start_index = 0
        results_per_page = 2000
        max_results = 10000  # Limit to prevent excessive API calls
        
        try:
            while start_index < max_results:
                params = {
                    "resultsPerPage": results_per_page,
                    "startIndex": start_index,
                    "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
                }
                
                logger.info(f"API request: startIndex={start_index}, resultsPerPage={results_per_page}")
                
                self._rate_limit()
                
                response = self.session.get(
                    self.base_url,
                    params=params,
                    timeout=self.timeout
                )
                
                if response.status_code != 200:
                    logger.error(f"API request failed: {response.status_code} - {response.text}")
                    break
                
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                total_results = data.get("totalResults", 0)
                
                logger.info(f"Got {len(vulnerabilities)} CVEs (total available: {total_results})")
                
                if not vulnerabilities:
                    break
                
                # Process CVEs
                for item in vulnerabilities:
                    cve_data = item.get("cve", {})
                    processed = self._process_cve_item(cve_data)
                    if processed:
                        all_cves.append(processed)
                
                # Check if we've got all results or hit our limit
                if len(vulnerabilities) < results_per_page or start_index + len(vulnerabilities) >= total_results:
                    break
                    
                start_index += len(vulnerabilities)
                
                # Safety limit
                if start_index >= max_results:
                    logger.warning(f"Hit safety limit of {max_results} results")
                    break
            
            # Sort by published date (newest first)
            all_cves.sort(key=lambda x: x.get('Published', ''), reverse=True)
            
            # Cache the results
            self._set_cache(cache_key, all_cves)
            
            logger.info(f"Successfully fetched and cached {len(all_cves)} CVEs")
            return all_cves
            
        except requests.exceptions.RequestException as e:
            logger.error(f"API request exception: {e}")
            # Return cached data if available, even if expired
            cached_data = self._get_cache(cache_key)
            if cached_data:
                logger.info("Returning expired cached data due to API error")
                return cached_data
            return []
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            # Return cached data if available
            cached_data = self._get_cache(cache_key)
            if cached_data:
                return cached_data
            return []

    def _process_cve_item(self, cve_data: Dict) -> Optional[Dict]:
        """Convert NVD CVE format to internal format"""
        try:
            cve_id = cve_data.get("id", "")
            if not cve_id:
                return None

            # Extract description
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Extract severity and CVSS
            severity = "UNKNOWN"
            cvss_score = None
            metrics = cve_data.get("metrics", {})

            # Try different CVSS versions
            for version in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics and metrics[version]:
                    try:
                        metric = metrics[version][0]
                        cvss_data = metric.get("cvssData", {})
                        potential_severity = cvss_data.get("baseSeverity", "")
                        potential_score = cvss_data.get("baseScore", None)
                        
                        if potential_severity and potential_severity.upper() != "UNKNOWN":
                            severity = potential_severity.upper()
                            cvss_score = potential_score
                            break
                    except (IndexError, KeyError):
                        continue

            # Extract CWE
            cwe = None
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        cwe_value = desc.get("value")
                        if cwe_value and cwe_value.startswith("CWE"):
                            cwe = cwe_value
                            break
                if cwe:
                    break

            # Extract references
            references = []
            for ref in cve_data.get("references", []):
                url = ref.get("url")
                if url:
                    references.append(url)

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
                "metrics": metrics
            }

        except Exception as e:
            logger.error(f"Error processing CVE: {e}")
            return None

    def clear_cache(self):
        """Clear all cached data"""
        with self._cache_lock:
            self._cache.clear()
            self._cache_timestamps.clear()
        logger.info("Cache cleared")

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._cache_lock:
            stats = {
                'cached_entries': len(self._cache),
                'cache_ages': {}
            }
            
            current_time = time.time()
            for key, timestamp in self._cache_timestamps.items():
                age_minutes = int((current_time - timestamp) / 60)
                stats['cache_ages'][key] = f"{age_minutes} minutes"
            
            return stats

# Global API client instance
api_client = NVDApiClient()