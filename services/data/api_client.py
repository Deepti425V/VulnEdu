import requests
import json
import os
import time
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta
import config
from database import db_manager
import logging
import traceback

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NVDApiClient:
    """NVD API Client with PAGINATION and GZIP support"""
    
    def __init__(self):
        self.api_url = config.NVD_API_URL
        self.api_key = config.NVD_API_KEY
        self.cache_dir = config.CACHE_DIR
        self.cache_duration = config.CACHE_DURATION
        self.db = db_manager
        self.request_count = 0
        self.last_request_window = time.time()
        
        # Enable gzip compression
        self.enable_gzip = config.ENABLE_GZIP_COMPRESSION
        
        logger.info(f"[API Client] Initialized with GZIP={'enabled' if self.enable_gzip else 'disabled'}")
        
        os.makedirs(self.cache_dir, exist_ok=True)
    
    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with gzip support"""
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        
        # Enable gzip compression for requests
        if self.enable_gzip:
            headers['Accept-Encoding'] = 'gzip, deflate'
        
        return headers
    
    def _make_request(self, params: Dict[str, Any]) -> Optional[Dict]:
        """Make API request with rate limiting and gzip support"""
        self._rate_limit()
        
        try:
            headers = self._get_headers()
            
            logger.info(f"[API] Making request with params: {params}")
            response = requests.get(
                self.api_url,
                params=params,
                headers=headers,
                timeout=config.API_TIMEOUT
            )
            
            response.raise_for_status()
            
            # Just use standard JSON parsing - NVD API handles compression automatically
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"[API] Request failed: {e}")
            return None
    
    def _rate_limit(self):
        """Rate limiting for API requests"""
        current_time = time.time()
        time_since_window_start = current_time - self.last_request_window
        
        if time_since_window_start >= 30:
            self.request_count = 0
            self.last_request_window = current_time
        
        if self.request_count >= config.API_REQUESTS_PER_30_SECONDS:
            sleep_time = 30 - time_since_window_start + 1
            logger.info(f"[API] Rate limit reached, sleeping for {sleep_time:.2f}s")
            time.sleep(sleep_time)
            self.request_count = 0
            self.last_request_window = time.time()
        
        self.request_count += 1
    
    def get_cves_last_30_days(self, batch_size: int = None, offset: int = 0) -> List[Dict[str, Any]]:
        """Get CVEs from last 30 days - SINGLE BATCH ONLY"""
        
        # ===== DEBUG: FIND WHO IS CALLING THIS DURING STARTUP =====
        print("=" * 80)
        print("[DEBUG] get_cves_last_30_days() called from:")
        traceback.print_stack()
        print("=" * 80)
        # ===== END DEBUG =====
        
        if batch_size is None:
            batch_size = config.API_BATCH_SIZE
        
        cache_key = f"cves_last_30_days_{batch_size}_{offset}"
        
        # Try database first
        if self.db.use_database:
            cached_meta = self.db.get_cache_metadata(cache_key)
            if cached_meta:
                cache_time = cached_meta['last_updated']
                if datetime.now() - cache_time < self.cache_duration:
                    logger.info(f"[API] Using database cache for last 30 days (offset={offset})")
                    return self.db.get_all_cves(limit=batch_size, offset=offset)
        
        # Calculate date range
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=30)
        
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'resultsPerPage': batch_size,
            'startIndex': offset
        }
        
        logger.info(f"[API] Fetching CVEs (batch_size={batch_size}, offset={offset})")
        
        data = self._make_request(params)
        if not data:
            logger.warning("[API] No data received from API")
            return []
        
        vulnerabilities = data.get('vulnerabilities', [])
        total_results = data.get('totalResults', 0)
        logger.info(f"[API] Retrieved {len(vulnerabilities)} CVEs out of {total_results} total")
        
        processed_cves = []
        for item in vulnerabilities:
            processed = self._process_cve_item(item)
            if processed:
                processed_cves.append(processed)
        
        # Save to database
        if self.db.use_database and processed_cves:
            self.db.save_cves_batch(processed_cves)
            self.db.update_cache_metadata(cache_key, len(processed_cves))
        
        return processed_cves
    
    def get_cves_for_date_range(self, year: int, month: int = None, day: int = None, 
                                batch_size: int = None, offset: int = 0) -> List[Dict[str, Any]]:
        """Get CVEs for specific date range with PAGINATION"""
        if batch_size is None:
            batch_size = config.API_BATCH_SIZE
        
        try:
            if day:
                start_date = datetime(year, month, day, tzinfo=timezone.utc)
                end_date = start_date + timedelta(days=1)
            elif month:
                start_date = datetime(year, month, 1, tzinfo=timezone.utc)
                if month == 12:
                    end_date = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
                else:
                    end_date = datetime(year, month + 1, 1, tzinfo=timezone.utc)
            else:
                start_date = datetime(year, 1, 1, tzinfo=timezone.utc)
                end_date = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
            
            params = {
                'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'resultsPerPage': batch_size,
                'startIndex': offset
            }
            
            logger.info(f"[API] Fetching CVEs for {year}-{month or 'all'}-{day or 'all'} (batch_size={batch_size}, offset={offset})")
            
            all_cves = []
            current_offset = offset
            
            # Paginate through all results
            while True:
                params['startIndex'] = current_offset
                
                data = self._make_request(params)
                if not data:
                    break
                
                vulnerabilities = data.get('vulnerabilities', [])
                total_results = data.get('totalResults', 0)
                
                if not vulnerabilities:
                    break
                
                for item in vulnerabilities:
                    processed = self._process_cve_item(item)
                    if processed:
                        all_cves.append(processed)
                
                logger.info(f"[API] Loaded {len(all_cves)}/{total_results} CVEs")
                
                # Check if there are more results
                if len(all_cves) >= total_results:
                    logger.info(f"[API] Reached total results: {total_results}")
                    break
                
                # Update offset for next batch
                current_offset += len(vulnerabilities)
                
                # If we got less than requested, there's no more data
                if len(vulnerabilities) < batch_size:
                    logger.info(f"[API] Got {len(vulnerabilities)} < {batch_size}, no more data")
                    break
                
                # Safety limit to prevent infinite loops
                if len(all_cves) >= 10000:
                    logger.warning("[API] Reached safety limit of 10000 CVEs")
                    break
            
            logger.info(f"[API] Retrieved total {len(all_cves)} CVEs for date range")
            
            # Save to database in batches
            if self.db.use_database and all_cves:
                for i in range(0, len(all_cves), 100):
                    batch = all_cves[i:i+100]
                    self.db.save_cves_batch(batch)
            
            return all_cves
            
        except Exception as e:
            logger.error(f"[API] Error fetching CVEs for date range: {e}")
            return []
    
    def get_cve_detail(self, cve_id: str) -> Dict[str, Any]:
        """Get detailed information for a specific CVE"""
        cache_file = os.path.join(self.cache_dir, f"{cve_id}.json")
        
        # Try cache first
        if os.path.exists(cache_file):
            cache_age = time.time() - os.path.getmtime(cache_file)
            if cache_age < self.cache_duration.total_seconds():
                logger.info(f"[API] Using cache for {cve_id}")
                with open(cache_file, 'r') as f:
                    return json.load(f)
        
        # Fetch from API
        params = {'cveId': cve_id}
        data = self._make_request(params)
        
        if not data or 'vulnerabilities' not in data:
            return {'ID': cve_id, 'Description': 'CVE details not found', 'Severity': 'UNKNOWN'}
        
        processed = self._process_cve_item(data['vulnerabilities'][0])
        
        # Save to cache
        with open(cache_file, 'w') as f:
            json.dump(processed, f)
        
        return processed
    
    def clear_cache(self):
        """Clear file cache"""
        try:
            for filename in os.listdir(self.cache_dir):
                file_path = os.path.join(self.cache_dir, filename)
                if os.path.isfile(file_path):
                    os.remove(file_path)
            logger.info("[API] Cache cleared successfully")
        except Exception as e:
            logger.error(f"[API] Error clearing cache: {e}")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            cache_files = os.listdir(self.cache_dir)
            return {
                'cached_items': len(cache_files),
                'cache_directory': self.cache_dir
            }
        except Exception as e:
            logger.error(f"[API] Error getting cache stats: {e}")
            return {'cached_items': 0, 'cache_directory': self.cache_dir}
    
    def _process_cve_item(self, item: Dict) -> Optional[Dict[str, Any]]:
        """Process a single CVE item from API response"""
        try:
            cve = item.get('cve', {})
            cve_id = cve.get('id', '')
            
            if not cve_id:
                return None
            
            # Get description
            description = ''
            for desc in cve.get('descriptions', []):
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Get CVSS metrics
            metrics = cve.get('metrics', {})
            cvss_score = None
            severity = 'UNKNOWN'
            
            for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if version in metrics and metrics[version]:
                    metric_data = metrics[version][0]
                    cvss_data = metric_data.get('cvssData', {})
                    cvss_score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity", metric_data.get("baseSeverity", "UNKNOWN"))
                    break
            
            # Get CWE
            weaknesses = cve.get("weaknesses", [])
            cwe = "CWE-NVD-noinfo"
            if weaknesses:
                descriptions = weaknesses[0].get("description", [])
                if descriptions:
                    cwe = descriptions[0].get("value", "CWE-NVD-noinfo")
            
            # Get references
            references = cve.get("references", [])
            reference_links = [ref.get("url", "") for ref in references]
            
            # Get dates
            published = cve.get("published", "")
            last_modified = cve.get("lastModified", "")
            
            return {
                "ID": cve_id,
                "Description": description,
                "Severity": severity,
                "CVSSScore": cvss_score,
                "CWE": cwe,
                "Published": published,
                "LastModified": last_modified,
                "References": reference_links
            }
        except Exception as e:
            logger.error(f"Error processing CVE item: {e}")
            return None
    
    def search_cves(self, keyword: str, limit=50) -> List[Dict[str, Any]]:
        """Search CVEs by keyword - FROM DATABASE"""
        logger.info(f"Searching CVEs for keyword: {keyword} (limit={limit})")
        
        if self.db.use_database:
            results = self.db.search_cves(keyword, limit=limit)
            if results:
                return results
        
        logger.warning(f"No results found for keyword: {keyword}, returning empty list")
        return []

# Create global instance for use throughout the application
api_client = NVDApiClient()
