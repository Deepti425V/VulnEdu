import requests
import json
import time
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
import config
import threading
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NVDApiClient:
    """Memory-optimized NVD API client - only fetches last 30 days by default"""
    
    def __init__(self):
        self.base_url = config.NVD_API_URL
        self.api_key = config.NVD_API_KEY
        self.timeout = config.API_TIMEOUT
        self.last_request_time = 0
        
        if self.api_key:
            self.min_request_interval = 30 / 50
        else:
            self.min_request_interval = 30 / 5
            
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})
            
        # LIGHTWEIGHT in-memory cache - only metadata
        self._cache_timestamp = None
        self._cache_lock = threading.Lock()
        
        from database import db_manager
        self.db = db_manager
    
    def _rate_limit(self):
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_request_interval:
            sleep_time = self.min_request_interval - elapsed
            time.sleep(sleep_time)
        self.last_request_time = time.time()
    
    def get_cves_last_30_days(self) -> List[Dict[str, Any]]:
        """Get CVEs from last 30 days - MEMORY OPTIMIZED"""
        
        # Check database first if available
        if self.db.use_database:
            metadata = self.db.get_cache_metadata('cves_30_days')
            if metadata:
                last_updated = metadata.get('last_updated')
                if last_updated:
                    age = datetime.now(timezone.utc) - last_updated.replace(tzinfo=timezone.utc)
                    if age.total_seconds() < 900:  # 15 minutes
                        logger.info("Using database cached CVE data")
                        cves = self.db.get_all_cves()
                        if cves:
                            return cves
        
        logger.info("Fetching fresh CVE data from API")
        
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=30)
        
        all_cves = []
        start_index = 0
        results_per_page = 2000
        max_results = 5000  # Limit to 5000 for memory
        
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
                
                response = self.session.get(self.base_url, params=params, timeout=self.timeout)
                
                if response.status_code != 200:
                    logger.error(f"API request failed: {response.status_code}")
                    break
                
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                total_results = data.get("totalResults", 0)
                
                logger.info(f"Got {len(vulnerabilities)} CVEs (total available: {total_results})")
                
                if not vulnerabilities:
                    break
                
                # Process in smaller batches
                batch = []
                for item in vulnerabilities:
                    cve_data = item.get("cve", {})
                    processed = self._process_cve_item(cve_data)
                    if processed:
                        batch.append(processed)
                    
                    # Save every 500 to reduce memory
                    if len(batch) >= 500 and self.db.use_database:
                        self.db.save_cves_batch(batch)
                        all_cves.extend(batch)
                        batch = []
                
                if batch:
                    if self.db.use_database:
                        self.db.save_cves_batch(batch)
                    all_cves.extend(batch)
                    batch = []
                
                if len(vulnerabilities) < results_per_page or start_index + len(vulnerabilities) >= total_results:
                    break
                
                start_index += len(vulnerabilities)
                
                if start_index >= max_results:
                    logger.warning(f"Hit safety limit of {max_results} results")
                    break
            
            all_cves.sort(key=lambda x: x.get('Published', ''), reverse=True)
            
            if self.db.use_database:
                self.db.update_cache_metadata('cves_30_days', len(all_cves))
            
            with self._cache_lock:
                self._cache_timestamp = time.time()
            
            logger.info(f"Successfully fetched and cached {len(all_cves)} CVEs")
            return all_cves
            
        except Exception as e:
            logger.error(f"API request exception: {e}")
            if self.db.use_database:
                cves = self.db.get_all_cves()
                if cves:
                    return cves
            return []
    
    def get_cves_for_date_range(self, year=None, month=None, day=None) -> List[Dict[str, Any]]:
        """Get CVEs for specific date range - ON DEMAND ONLY"""
        
        if not year:
            return self.get_cves_last_30_days()
        
        logger.info(f"Fetching CVEs for {year}-{month or 'all'}-{day or 'all'}")
        
        # Build date range
        if day and month:
            start_date = datetime(year, month, day, 0, 0, 0, tzinfo=timezone.utc)
            end_date = datetime(year, month, day, 23, 59, 59, tzinfo=timezone.utc)
        elif month:
            start_date = datetime(year, month, 1, 0, 0, 0, tzinfo=timezone.utc)
            if month == 12:
                end_date = datetime(year, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
            else:
                end_date = datetime(year, month + 1, 1, 0, 0, 0, tzinfo=timezone.utc) - timedelta(seconds=1)
        else:
            start_date = datetime(year, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
            end_date = datetime(year, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        
        all_cves = []
        start_index = 0
        results_per_page = 2000
        max_results = 10000  # Limit for memory
        
        try:
            while start_index < max_results:
                params = {
                    "resultsPerPage": results_per_page,
                    "startIndex": start_index,
                    "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
                }
                
                self._rate_limit()
                response = self.session.get(self.base_url, params=params, timeout=self.timeout)
                
                if response.status_code != 200:
                    break
                
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                total_results = data.get("totalResults", 0)
                
                if not vulnerabilities:
                    break
                
                for item in vulnerabilities:
                    cve_data = item.get("cve", {})
                    processed = self._process_cve_item(cve_data)
                    if processed:
                        all_cves.append(processed)
                
                if len(vulnerabilities) < results_per_page or start_index + len(vulnerabilities) >= total_results:
                    break
                
                start_index += len(vulnerabilities)
                
                if start_index >= max_results:
                    break
            
            all_cves.sort(key=lambda x: x.get('Published', ''), reverse=True)
            return all_cves
            
        except Exception as e:
            logger.error(f"Error fetching date range: {e}")
            return []
    
    def get_cve_detail(self, cve_id: str) -> Dict[str, Any]:
        """Get single CVE detail"""
        try:
            self._rate_limit()
            params = {"cveId": cve_id}
            response = self.session.get(self.base_url, params=params, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    cve_data = vulnerabilities[0].get("cve", {})
                    return self._process_cve_item(cve_data) or {'ID': cve_id, 'Description': 'CVE details not available'}
            
            return {'ID': cve_id, 'Description': 'CVE details not available'}
        except Exception as e:
            logger.error(f"Error fetching CVE detail: {e}")
            return {'ID': cve_id, 'Description': 'Error loading CVE details'}
    
    def _process_cve_item(self, cve_data: Dict) -> Optional[Dict]:
        """Convert NVD CVE format to internal format - MEMORY OPTIMIZED"""
        try:
            cve_id = cve_data.get("id", "")
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
            
            references = []
            for ref in cve_data.get("references", [])[:3]:  # Only first 3
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
                "metrics": {}
            }
        except Exception as e:
            logger.error(f"Error processing CVE: {e}")
            return None
    
    def clear_cache(self):
        with self._cache_lock:
            self._cache_timestamp = None
        if self.db.use_database:
            self.db.clear_all_cves()
        logger.info("Cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        stats = {'cached_entries': 0, 'cache_ages': {}}
        
        with self._cache_lock:
            if self._cache_timestamp:
                age_minutes = int((time.time() - self._cache_timestamp) / 60)
                stats['cache_ages']['api_30_days'] = f"{age_minutes} minutes"
        
        if self.db.use_database:
            stats['database'] = self.db.get_stats()
        
        return stats

api_client = NVDApiClient()