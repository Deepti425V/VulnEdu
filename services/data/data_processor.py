import os
import json
import gzip
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import config
from database.db_manager import db_manager
from services.cache.cache_manager import cache_manager
import gc
import psutil
import ijson  # For streaming JSON parsing

class DataProcessor:
    """Process and extract insights from historical NVD data with streaming and lazy loading"""
    
    def __init__(self):
        self.historical_dir = config.NVD_HISTORICAL_DIR
        self.processed_dir = config.NVD_PROCESSED_DIR
        
        # CRITICAL: Memory-efficient caching - only 1 year at a time
        self._year_cache = {}
        self._max_cache_size = config.MAX_YEAR_CACHE_SIZE  # Only 1 year
        self._years_available = set()
        self._batch_size = config.BATCH_SIZE  # Process in batches
        
        print(f"[DataProcessor] Initialized with streaming support")
        print(f"[DataProcessor] Max cache size: {self._max_cache_size} year(s)")
        print(f"[DataProcessor] Batch size: {self._batch_size} CVEs")
        
        # Check available files
        self._check_available_files()
        self._monitor_memory()
    
    def _monitor_memory(self):
        """Monitor current memory usage"""
        try:
            process = psutil.Process(os.getpid())
            mem_mb = process.memory_info().rss / 1024 / 1024
            print(f"[Memory] Current usage: {mem_mb:.2f} MB / {config.MAX_MEMORY_USAGE_MB} MB limit")
            
            if mem_mb > config.MAX_MEMORY_USAGE_MB:
                print(f"[Memory] WARNING: Exceeding limit! Clearing caches...")
                self._emergency_memory_cleanup()
        except Exception as e:
            print(f"[Memory] Error monitoring: {e}")
    
    def _emergency_memory_cleanup(self):
        """Emergency memory cleanup when approaching limits"""
        print("[Memory] Emergency cleanup initiated")
        
        # Clear all in-memory caches
        self._year_cache.clear()
        cache_manager.clear_cache()
        
        # Force garbage collection
        gc.collect()
        
        # Monitor result
        try:
            process = psutil.Process(os.getpid())
            mem_mb = process.memory_info().rss / 1024 / 1024
            print(f"[Memory] After cleanup: {mem_mb:.2f} MB")
        except:
            pass
    
    def _check_available_files(self):
        """Check what historical files are available"""
        self._years_available.clear()
        
        if not os.path.exists(self.historical_dir):
            print(f"[DataProcessor] Creating directory: {self.historical_dir}")
            os.makedirs(self.historical_dir, exist_ok=True)
            return
        
        files = os.listdir(self.historical_dir)
        for file in files:
            if file.startswith(('CVE-', 'nvdcve-')):
                year = None
                # Extract year from filename
                if file.startswith("CVE-") and "." in file:
                    year_str = file[4:file.find(".")]
                    if year_str.isdigit() and len(year_str) == 4:
                        year = int(year_str)
                
                if year and 2000 <= year <= 2050:
                    self._years_available.add(year)
        
        print(f"[DataProcessor] Available years: {sorted(self._years_available)}")
    
    def get_available_years(self) -> List[int]:
        """Get list of available years"""
        if not self._years_available:
            self._check_available_files()
        return sorted(self._years_available, reverse=True)
    
    def get_year_data(self, year: int) -> List[Dict]:
        """Load CVEs for a specific year with database caching and memory management"""
        year_str = str(year)
        
        # Monitor memory before loading
        self._monitor_memory()
        
        # First check database
        if db_manager.use_database:
            cves = db_manager.get_cves_by_filter(year=year_str)
            if cves:
                print(f"[DataProcessor] Retrieved {len(cves)} CVEs for {year} from database")
                return cves
        
        # Check memory cache (only if we have room)
        if year_str in self._year_cache:
            print(f"[DataProcessor] Using cached data for {year}")
            return self._year_cache[year_str]
        
        # Clear cache if at limit
        if len(self._year_cache) >= self._max_cache_size:
            oldest_year = next(iter(self._year_cache))
            print(f"[DataProcessor] Evicting {oldest_year} from cache to save memory")
            del self._year_cache[oldest_year]
            gc.collect()
        
        # Load from file with streaming if large
        data = self._load_year_file_streaming(year)
        
        # Save to database
        if db_manager.use_database and data:
            print(f"[DataProcessor] Saving {len(data)} CVEs to database")
            # Save in batches to avoid memory spike
            for i in range(0, len(data), self._batch_size):
                batch = data[i:i+self._batch_size]
                db_manager.save_cves_batch(batch)
        
        # Only cache if memory usage is reasonable
        process = psutil.Process(os.getpid())
        mem_mb = process.memory_info().rss / 1024 / 1024
        if mem_mb < config.MAX_MEMORY_USAGE_MB * 0.8:  # 80% threshold
            self._year_cache[year_str] = data
            print(f"[DataProcessor] Cached {len(data)} CVEs for {year} (memory OK)")
        else:
            print(f"[DataProcessor] Not caching {year} data (memory usage high: {mem_mb:.2f} MB)")
        
        return data
    
    def _load_year_file_streaming(self, year: int) -> List[Dict]:
        """Load CVEs with streaming for large files"""
        # Find the file
        possible_filenames = [
            f"CVE-{year}.json.gz",
            f"CVE-{year}.json",
            f"nvdcve-1.1-{year}.json.gz",
            f"nvdcve-1.1-{year}.json",
        ]
        
        target_file = None
        is_gzipped = False
        
        for filename in possible_filenames:
            file_path = os.path.join(self.historical_dir, filename)
            if os.path.exists(file_path):
                target_file = file_path
                is_gzipped = filename.endswith('.gz')
                break
        
        if not target_file:
            print(f"[DataProcessor] No file found for {year}")
            return []
        
        # Check file size
        file_size = os.path.getsize(target_file)
        file_size_mb = file_size / 1024 / 1024
        print(f"[DataProcessor] Loading {target_file} ({file_size_mb:.2f} MB)")
        
        # Use streaming for large files (>10MB)
        if file_size_mb > 10 and config.STREAM_JSON_ENABLED:
            return self._stream_parse_json(target_file, is_gzipped)
        else:
            return self._load_json_traditional(target_file, is_gzipped)
    
    def _stream_parse_json(self, filepath: str, is_gzipped: bool) -> List[Dict]:
        """Stream parse JSON to avoid loading entire file into memory"""
        print(f"[DataProcessor] Using streaming parser for {filepath}")
        cves = []
        
        try:
            if is_gzipped:
                file_obj = gzip.open(filepath, 'rb')
            else:
                file_obj = open(filepath, 'rb')
            
            # Use ijson for streaming
            parser = ijson.items(file_obj, 'vulnerabilities.item')
            
            batch_count = 0
            for item in parser:
                processed = self._process_json_2_0_cve(item)
                if processed:
                    cves.append(processed)
                
                # Process in batches to manage memory
                if len(cves) % self._batch_size == 0:
                    batch_count += 1
                    print(f"[DataProcessor] Processed batch {batch_count} ({len(cves)} CVEs)")
                    gc.collect()  # Force garbage collection between batches
            
            file_obj.close()
            print(f"[DataProcessor] Stream parsed {len(cves)} CVEs")
            
        except Exception as e:
            print(f"[DataProcessor] Stream parsing failed, falling back to traditional: {e}")
            return self._load_json_traditional(filepath, is_gzipped)
        
        return cves
    
    def _load_json_traditional(self, filepath: str, is_gzipped: bool) -> List[Dict]:
        """Traditional JSON loading (for smaller files)"""
        try:
            if is_gzipped:
                with gzip.open(filepath, 'rt', encoding='utf-8') as f:
                    data = json.load(f)
            else:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            
            cves = []
            
            # Process based on format
            vulnerabilities = data.get("vulnerabilities", [])
            if vulnerabilities:
                print(f"[DataProcessor] Processing {len(vulnerabilities)} items (JSON 2.0)")
                # Process in batches
                for i in range(0, len(vulnerabilities), self._batch_size):
                    batch = vulnerabilities[i:i+self._batch_size]
                    for item in batch:
                        processed = self._process_json_2_0_cve(item)
                        if processed:
                            cves.append(processed)
                    gc.collect()
            else:
                # Try JSON 1.1 format
                cve_items = data.get("CVE_Items", [])
                if cve_items:
                    print(f"[DataProcessor] Processing {len(cve_items)} items (JSON 1.1)")
                    for i in range(0, len(cve_items), self._batch_size):
                        batch = cve_items[i:i+self._batch_size]
                        for item in batch:
                            processed = self._process_json_1_1_cve(item)
                            if processed:
                                cves.append(processed)
                        gc.collect()
            
            # Clear raw data immediately
            del data
            gc.collect()
            
            print(f"[DataProcessor] Loaded {len(cves)} CVEs")
            return cves
            
        except Exception as e:
            print(f"[DataProcessor] Error loading {filepath}: {e}")
            return []
    
    def _process_json_2_0_cve(self, item: Dict) -> Optional[Dict]:
        """Process JSON 2.0 format CVE - memory optimized"""
        try:
            cve_data = item.get("cve", {})
            if not cve_data:
                return None
            
            cve_id = cve_data.get("id", "")
            if not cve_id:
                return None
            
            # Extract only essential fields to save memory
            description = ""
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")[:500]  # Limit description length
                    break
            
            # Extract severity
            severity = "UNKNOWN"
            cvss_score = None
            metrics = cve_data.get("metrics", {})
            
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics and metrics[version]:
                    try:
                        metric = metrics[version][0]
                        cvss_data = metric.get("cvssData", {})
                        severity = cvss_data.get("baseSeverity", "UNKNOWN").upper()
                        cvss_score = cvss_data.get("baseScore")
                        break
                    except:
                        continue
            
            # Extract CWE
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
            
            return {
                "ID": cve_id,
                "Description": description,
                "Severity": severity,
                "CWE": cwe,
                "Published": cve_data.get("published", ""),
                "lastModified": cve_data.get("lastModified", ""),
                "References": [],  # Empty to save memory
                "Products": [],  # Empty to save memory
                "CVSS_Score": cvss_score,
                "metrics": {}  # Empty to save memory
            }
            
        except Exception:
            return None
    
    def _process_json_1_1_cve(self, item: Dict) -> Optional[Dict]:
        """Process JSON 1.1 format CVE - memory optimized"""
        try:
            cve_data = item.get("cve", {})
            if not cve_data:
                return None
            
            cve_id = cve_data.get("CVE_data_meta", {}).get("ID", "")
            if not cve_id:
                return None
            
            # Extract description (limited length)
            description = ""
            descriptions = cve_data.get("description", {}).get("description_data", [])
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")[:500]
                    break
            
            # Extract severity
            severity = "UNKNOWN"
            cvss_score = None
            impact = item.get("impact", {})
            
            if "baseMetricV3" in impact:
                severity = impact["baseMetricV3"].get("cvssV3", {}).get("baseSeverity", "UNKNOWN").upper()
                cvss_score = impact["baseMetricV3"].get("cvssV3", {}).get("baseScore")
            elif "baseMetricV2" in impact:
                score = impact["baseMetricV2"].get("cvssV2", {}).get("baseScore", 0)
                cvss_score = score
                if score >= 7.0:
                    severity = "HIGH"
                elif score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            
            # Extract CWE
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
            
            return {
                "ID": cve_id,
                "Description": description,
                "Severity": severity,
                "CWE": cwe,
                "Published": item.get("publishedDate", ""),
                "lastModified": item.get("lastModifiedDate", ""),
                "References": [],  # Empty to save memory
                "Products": [],  # Empty to save memory
                "CVSS_Score": cvss_score,
                "metrics": {}  # Empty to save memory
            }
            
        except Exception:
            return None
    
    def get_filtered_cves_for_year(self, year: int, month: Optional[int] = None, 
                                  day: Optional[int] = None) -> List[Dict]:
        """Get filtered CVEs with memory-efficient processing"""
        # Try database first
        if db_manager.use_database:
            year_str = str(year)
            month_str = str(month).zfill(2) if month is not None else None
            day_str = str(day).zfill(2) if day is not None else None
            
            cves = db_manager.get_cves_by_filter(
                year=year_str,
                month=month_str,
                day=day_str
            )
            if cves:
                print(f"[DataProcessor] Retrieved filtered CVEs from database")
                return cves
        
        # Load year data
        all_cves = self.get_year_data(year)
        
        if not month and not day:
            return all_cves
        
        # Filter efficiently
        filtered_cves = []
        for cve in all_cves:
            published = cve.get('Published', '')
            if not published:
                continue
            
            try:
                # Parse date
                if 'T' in published:
                    dt = datetime.fromisoformat(published.replace('Z', '+00:00'))
                else:
                    dt = datetime.strptime(published[:10], '%Y-%m-%d')
                
                # Apply filters
                if month is not None and dt.month != month:
                    continue
                if day is not None and dt.day != day:
                    continue
                
                filtered_cves.append(cve)
            except:
                continue
        
        return filtered_cves
    
    def calculate_vulnerabilities_timeline(self, years=1) -> Dict[str, Any]:
        """Calculate timeline with memory-efficient processing"""
        # Try cache first
        cached_timeline = cache_manager.get_timeline_data(years)
        if cached_timeline and cached_timeline.get('labels'):
            print(f"[DataProcessor] Using cached timeline data")
            return cached_timeline
        
        current_year = datetime.now().year
        year_range = list(range(current_year - years + 1, current_year + 1))
        
        result = {
            'labels': [],
            'values': [],
            'total_cves': 0,
            'months_covered': 0,
            'raw_data': {}
        }
        
        for year in year_range:
            if year not in self._years_available:
                continue
            
            # Process year data
            cves = self.get_year_data(year)
            print(f"[DataProcessor] Processing timeline for {year}: {len(cves)} CVEs")
            
            # Group by month
            month_counts = {}
            for cve in cves:
                published = cve.get('Published', '')
                if not published:
                    continue
                
                try:
                    if 'T' in published:
                        dt = datetime.fromisoformat(published.replace('Z', '+00:00'))
                    else:
                        dt = datetime.strptime(published[:10], '%Y-%m-%d')
                    
                    month_key = f"{dt.year}-{dt.month:02d}"
                    month_counts[month_key] = month_counts.get(month_key, 0) + 1
                except:
                    continue
            
            # Clear year data immediately to save memory
            if str(year) in self._year_cache:
                del self._year_cache[str(year)]
                gc.collect()
            
            # Add to results
            for month_key, count in sorted(month_counts.items()):
                result['labels'].append(month_key)
                result['values'].append(count)
                result['raw_data'][month_key] = count
                result['total_cves'] += count
        
        result['months_covered'] = len(result['labels'])
        
        # Cache the results
        cache_manager.set_timeline_data(result)
        
        return result
    
    def clear_cache(self):
        """Clear all in-memory caches"""
        self._year_cache.clear()
        gc.collect()
        print("[DataProcessor] Cache cleared")

# Global instance
historical_loader = DataProcessor()