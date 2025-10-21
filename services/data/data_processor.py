# Operating system interface for file and directory operations
import os
# JSON parsing for processing NVD vulnerability data files
import json
# Gzip compression handling for compressed NVD data files
import gzip
# Type annotations for function signatures and data structures
from typing import List, Dict, Any
# Date operations for calculating year ranges
from datetime import datetime
# HTTP requests for GitHub data fetching
import requests
# Temporary file handling
import tempfile
# Application configuration for directory paths and settings
import config

class DataProcessor:
    """Process and extract insights from historical NVD data"""
    
    # Return empty immediately - no historical data
    def get_last_5_years_data(self) -> Dict[str, List[Dict]]:
    """Disabled - no historical data to save memory"""
    return {}

    def get_year_data(self, year: int) -> List[Dict]:
    """Disabled - no historical data"""
    return []

    
    def __init__(self):
        # Load directory paths from centralized configuration
        self.historical_dir = config.NVD_HISTORICAL_DIR
        self.processed_dir = config.NVD_PROCESSED_DIR
        self.use_github = config.USE_GITHUB_DATA
        self.github_base_url = config.GITHUB_RAW_BASE_URL if self.use_github else None
    
    def get_last_5_years_data(self) -> Dict[str, List[Dict]]:
        """Load last 5 years of historical data - with caching"""
        # Check cache first to avoid expensive reprocessing
        from services.cache.cache_manager import cache_manager
        cached_data = cache_manager.get_historical_data()
        if cached_data:
            return cached_data
        
        # Calculate current year and create 5-year range
        current_year = datetime.now().year
        # Include current year and last 4 years for total of 5 years
        years = list(range(current_year - 4, current_year + 1))
        
        print(f"[Historical] Loading data for years: {years}")
        
        # Load data for each year in the range
        all_data = {}
        for year in years:
            print(f"[Historical] Loading {year} data...")
            year_data = self._load_year_file(year)
            all_data[str(year)] = year_data
            print(f"[Historical] Loaded {len(year_data)} CVEs for {year}")
        
        # Cache the complete results for future requests
        cache_manager.set_historical_data(all_data)
        
        return all_data
    
    def get_year_data(self, year: int) -> List[Dict]:
        """Load CVEs from a specific year file"""
        return self._load_year_file(year)
    
    def get_multiple_years_data(self, years: List[int]) -> Dict[str, List[Dict]]:
        """Load CVEs from multiple specific years"""
        all_data = {}
        for year in years:
            print(f"[Historical] Loading {year} data...")
            year_data = self._load_year_file(year)
            all_data[str(year)] = year_data
            print(f"[Historical] Loaded {len(year_data)} CVEs for {year}")
        return all_data
    
    def _fetch_from_github(self, filename: str) -> bytes:
        """Fetch file from GitHub repository"""
        if not self.use_github or not self.github_base_url:
            raise Exception("GitHub data fetching is not enabled")
        
        url = f"{self.github_base_url}/{filename}"
        print(f"[Historical] Fetching from GitHub: {url}")
        
        try:
            response = requests.get(url, timeout=60)  # 60 second timeout for large files
            if response.status_code == 200:
                print(f"[Historical] Successfully fetched {filename} from GitHub ({len(response.content)} bytes)")
                return response.content
            else:
                print(f"[Historical] GitHub fetch failed: HTTP {response.status_code}")
                raise Exception(f"Failed to fetch from GitHub: HTTP {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[Historical] GitHub fetch error: {e}")
            raise Exception(f"GitHub fetch error: {e}")
    
    def _load_year_file(self, year: int) -> List[Dict]:
        """Load CVEs from a specific year file - GitHub or local fallback"""
        try:
            # Try different file patterns
            possible_filenames = [
                f"CVE-{year}.json.gz",
                f"nvdcve-1.1-{year}.json.gz",
                f"nvdcve-2.0-{year}.json.gz",
                f"CVE-{year}.json",
                f"nvdcve-1.1-{year}.json",
                f"nvdcve-2.0-{year}.json"
            ]
            
            data = None
            filename_used = None
            
            # Try GitHub first if enabled
            if self.use_github:
                for filename in possible_filenames:
                    try:
                        file_content = self._fetch_from_github(filename)
                        filename_used = filename
                        
                        # Handle gzipped files
                        if filename.endswith('.gz'):
                            file_content = gzip.decompress(file_content)
                            print(f"[Historical] Decompressed gzipped file for {year}")
                        
                        # Parse JSON
                        data = json.loads(file_content.decode('utf-8'))
                        print(f"[Historical] Successfully loaded {filename} from GitHub for {year}")
                        break
                    except Exception as e:
                        # Try next filename pattern
                        continue
            
            # Fallback to local files if GitHub fails or is disabled
            if data is None:
                print(f"[Historical] GitHub fetch failed or disabled, trying local files for {year}")
                
                if os.path.exists(self.historical_dir):
                    files = os.listdir(self.historical_dir)
                    print(f"[Historical] Local files available: {files[:10]}...")
                else:
                    print(f"[Historical] Local directory does not exist: {self.historical_dir}")
                    return []
                
                # Find the first available file from the pattern list
                target_file = None
                for filename in possible_filenames:
                    file_path = os.path.join(self.historical_dir, filename)
                    if os.path.exists(file_path):
                        target_file = file_path
                        filename_used = filename
                        print(f"[Historical] Found local file: {filename}")
                        break
                
                if not target_file:
                    print(f"[Historical] No file found for {year}. Tried: {possible_filenames}")
                    return []
                
                print(f"[Historical] Processing local file: {target_file}")
                
                # Load the file based on extension
                if target_file.endswith('.gz'):
                    # Handle gzipped files
                    with gzip.open(target_file, 'rt', encoding='utf-8') as f:
                        data = json.load(f)
                    print(f"[Historical] Successfully loaded local gzipped file for {year}")
                else:
                    # Handle plain JSON files
                    with open(target_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    print(f"[Historical] Successfully loaded local plain JSON file for {year}")
            
            if not data:
                print(f"[Historical] No data loaded for {year}")
                return []
            
            # Process CVEs based on detected format
            cves = []
            
            # Try JSON 2.0 format first (newer format)
            vulnerabilities = data.get("vulnerabilities", [])
            if vulnerabilities:
                print(f"[Historical] Found {len(vulnerabilities)} vulnerabilities in JSON 2.0 format")
                for item in vulnerabilities:
                    processed = self._process_json_2_0_cve(item)
                    if processed:
                        cves.append(processed)
            else:
                # Try JSON 1.1 format (legacy format)
                cve_items = data.get("CVE_Items", [])
                if cve_items:
                    print(f"[Historical] Found {len(cve_items)} CVE_Items in JSON 1.1 format")
                    for item in cve_items:
                        processed = self._process_json_1_1_cve(item)
                        if processed:
                            cves.append(processed)
                else:
                    print(f"[Historical] No recognized data format found")
                    print(f"[Historical] Top-level keys: {list(data.keys())}")
            
            print(f"[Historical] Successfully processed {len(cves)} CVEs for {year}")
            return cves
            
        except Exception as e:
            print(f"[Historical] Error loading {year}: {e}")
            # Print full traceback for debugging complex issues
            import traceback
            traceback.print_exc()
            return []
    
    def _process_json_2_0_cve(self, item: Dict) -> Dict:
        """Process JSON 2.0 format CVE"""
        try:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "")
            
            if not cve_id:
                return None
            
            # Extract English description from descriptions array
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Extract severity with CVSS version preference (newer versions first)
            severity = "UNKNOWN"
            metrics = cve_data.get("metrics", {})
            for version in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics and metrics[version]:
                    try:
                        metric = metrics[version][0]
                        cvss_data = metric.get("cvssData", {})
                        potential_severity = cvss_data.get("baseSeverity", "")
                        if potential_severity and potential_severity.upper() != "UNKNOWN":
                            severity = potential_severity.upper()
                            break
                    except (IndexError, KeyError):
                        continue
            
            # Extract CWE (Common Weakness Enumeration) classification
            cwe = None
            for weakness in cve_data.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en":
                        value = desc.get("value", "")
                        if value.startswith("CWE"):
                            cwe = value
                            break
                if cwe:
                    break
            
            # Return standardized internal format
            return {
                "ID": cve_id,
                "Description": description,
                "Severity": severity,
                "CWE": cwe,
                "Published": cve_data.get("published", ""),
                "lastModified": cve_data.get("lastModified", ""),
                "References": [],  # Not extracted in current implementation
                "Products": [],  # Not extracted in current implementation
                "CVSS_Score": None,  # Could be extracted if needed
                "metrics": {}  # Simplified for current use
            }
        except Exception as e:
            print(f"[Historical] Error processing JSON 2.0 CVE: {e}")
            return None
    
    def _process_json_1_1_cve(self, item: Dict) -> Dict:
        """Process JSON 1.1 format CVE"""
        try:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("CVE_data_meta", {}).get("ID", "")
            
            if not cve_id:
                return None
            
            # Extract English description from nested description structure
            description = ""
            descriptions = cve_data.get("description", {}).get("description_data", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Extract severity from impact section with version preference
            severity = "UNKNOWN"
            impact = item.get("impact", {})
            if "baseMetricV3" in impact:
                # Use CVSS v3 severity if available
                severity = impact["baseMetricV3"].get("cvssV3", {}).get("baseSeverity", "UNKNOWN").upper()
            elif "baseMetricV2" in impact:
                # Convert CVSS v2 score to severity level using standard thresholds
                score = impact["baseMetricV2"].get("cvssV2", {}).get("baseScore", 0)
                if score >= 7.0:
                    severity = "HIGH"
                elif score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            
            # Extract CWE from problemtype section
            cwe = None
            problem_types = cve_data.get("problemtype", {}).get("problemtype_data", [])
            for problem_type in problem_types:
                for desc in problem_type.get("description", []):
                    if desc.get("lang") == "en":
                        value = desc.get("value", "")
                        if value.startswith("CWE"):
                            cwe = value
                            break
                if cwe:
                    break
            
            # Return standardized internal format compatible with other components
            return {
                "ID": cve_id,
                "Description": description,
                "Severity": severity,
                "CWE": cwe,
                "Published": cve_data.get("publishedDate", ""),
                "lastModified": cve_data.get("lastModifiedDate", ""),
                "References": [],  # Not extracted in current implementation
                "Products": [],  # Not extracted in current implementation
                "CVSS_Score": None,  # Could be extracted if needed
                "metrics": {}  # Simplified for current use
            }
        except Exception as e:
            # Log processing errors but continue with batch processing
            print(f"[Historical] Error processing JSON 1.1 CVE: {e}")
            return None


# Global historical loader instance for application-wide use (maintaining interface compatibility)
historical_loader = DataProcessor()