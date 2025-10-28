import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import json
import gc
import psutil
import os
import config
from database.db_manager import db_manager

class CacheManager:
    """Lightweight caching with aggressive memory management for Render's 512MB limit"""
    
    def __init__(self):
        self._cache_timestamps = {}
        self._cves_30_days: List[Dict[str, Any]] = []
        self._historical_data: Dict[int, List[Dict[str, Any]]] = {}
        self._historical_loaded = False
        self._lock = threading.Lock()
        
        # Memory management
        self._last_memory_check = time.time()
        self._memory_check_interval = config.MEMORY_CHECK_INTERVAL
        self._max_memory_mb = config.MAX_MEMORY_USAGE_MB
        
        # Cache durations
        self.API_CACHE_DURATION = 24 * 60 * 60  # 24 hours
        self.HISTORICAL_CACHE_DURATION = 7 * 24 * 60 * 60  # 7 days
        
        self.db_manager = db_manager
        
        print(f"[Cache] Initialized with {self._max_memory_mb}MB memory limit")
        
        # Start memory monitoring thread
        self._start_memory_monitor()
    
    def _start_memory_monitor(self):
        """Start background thread to monitor memory usage"""
        def monitor():
            while True:
                time.sleep(self._memory_check_interval)
                self._check_and_manage_memory()
        
        monitor_thread = threading.Thread(target=monitor, daemon=True)
        monitor_thread.start()
        print("[Cache] Memory monitor thread started")
    
    def _check_and_manage_memory(self):
        """Check memory usage and evict caches if needed"""
        try:
            mem_mb = self.check_memory_usage()
            mem_percent = (mem_mb / self._max_memory_mb) * 100
            
            if mem_percent > 90:  # Critical - above 90%
                print(f"[Cache] CRITICAL: Memory at {mem_mb:.2f}MB ({mem_percent:.1f}%) - Emergency cleanup!")
                self._emergency_cleanup()
            elif mem_percent > 80:  # Warning - above 80%
                print(f"[Cache] WARNING: Memory at {mem_mb:.2f}MB ({mem_percent:.1f}%) - Clearing historical data")
                with self._lock:
                    self._historical_data.clear()
                    gc.collect()
            elif mem_percent > 70:  # Caution - above 70%
                print(f"[Cache] CAUTION: Memory at {mem_mb:.2f}MB ({mem_percent:.1f}%) - Reducing cache")
                self._reduce_cache_size()
            
            # Log memory status periodically
            if time.time() - self._last_memory_check > 60:  # Every minute
                print(f"[Cache] Memory status: {mem_mb:.2f}MB / {self._max_memory_mb}MB ({mem_percent:.1f}%)")
                self._last_memory_check = time.time()
                
        except Exception as e:
            print(f"[Cache] Memory check error: {e}")
    
    def check_memory_usage(self) -> float:
        """Return current memory usage in MB"""
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / 1024 / 1024
    
    def _emergency_cleanup(self):
        """Emergency memory cleanup"""
        with self._lock:
            self._cves_30_days = []
            self._historical_data.clear()
            self._cache_timestamps.clear()
            self._historical_loaded = False
        
        for _ in range(3):
            gc.collect()
        
        print("[Cache] Emergency cleanup completed")
    
    def _reduce_cache_size(self):
        """Reduce cache size by evicting oldest data"""
        with self._lock:
            if len(self._historical_data) > 1:
                oldest_year = min(self._historical_data.keys())
                del self._historical_data[oldest_year]
                print(f"[Cache] Evicted historical data for year {oldest_year}")
        
        gc.collect()
    
    # ---- 30-day API CVE cache ----
    
    def get_api_data_30_days(self) -> Optional[List[Dict[str, Any]]]:
        """Return cached 30-day CVEs if valid"""
        cache_key = "api_30_days"
        
        if self.db_manager.use_database:
            cached = self.db_manager.get_cves_by_filter(limit=1000)
            if cached:
                print(f"[Cache] Using database cache: {len(cached)} CVEs")
                return cached
        
        with self._lock:
            if self._cves_30_days and cache_key in self._cache_timestamps:
                age = time.time() - self._cache_timestamps[cache_key]
                if age < self.API_CACHE_DURATION:
                    print(f"[Cache] Using memory cache: {len(self._cves_30_days)} CVEs")
                    return self._cves_30_days
        
        return None
    
    def set_api_data_30_days(self, data: List[Dict[str, Any]]):
        """Set cache for 30-day CVEs with memory check"""
        mem_mb = self.check_memory_usage()
        
        if mem_mb > self._max_memory_mb * 0.9:
            print(f"[Cache] Memory too high ({mem_mb:.2f}MB), skipping memory cache")
            if self.db_manager.use_database:
                batch_size = 500
                for i in range(0, len(data), batch_size):
                    self.db_manager.save_cves_batch(data[i:i+batch_size])
            return
        
        with self._lock:
            self._cves_30_days = data  # Keep all 30-day CVEs
            self._cache_timestamps["api_30_days"] = time.time()
        
        if self.db_manager.use_database:
            self.db_manager.update_cache_metadata(
                "api_30_days",
                len(data),
                {"last_check": datetime.now(timezone.utc).isoformat(), "type": "api_30_days"}
            )
        
        print(f"[Cache] Cached {len(self._cves_30_days)} CVEs for last 30 days")
    
    # ---- Historical data cache ----
    
    def get_historical_data(self, year: int) -> Optional[List[Dict[str, Any]]]:
        if self.db_manager.use_database:
            data = self.db_manager.get_cves_by_filter(year=str(year))
            if data:
                print(f"[Cache] Retrieved {len(data)} historical CVEs for {year} from database")
                return data
        
        with self._lock:
            if year in self._historical_data:
                print(f"[Cache] Using memory cache for year {year}")
                return self._historical_data[year]
        
        return None
    
    def set_historical_data(self, year: int, data: List[Dict[str, Any]]):
        mem_mb = self.check_memory_usage()
        
        if mem_mb > self._max_memory_mb * 0.85:
            print(f"[Cache] Memory too high ({mem_mb:.2f}MB), saving to database only")
            if self.db_manager.use_database:
                batch_size = 500
                for i in range(0, len(data), batch_size):
                    self.db_manager.save_cves_batch(data[i:i+batch_size])
            return
        
        with self._lock:
            if len(self._historical_data) >= 1:
                self._historical_data.clear()
                gc.collect()
            self._historical_data[year] = data
        
        if self.db_manager.use_database:
            self.db_manager.save_historical_cves(year, data)
        
        print(f"[Cache] Cached {len(data)} historical CVEs for {year}")
    
    def is_historical_loaded(self) -> bool:
        if self.db_manager.use_database:
            metadata = self.db_manager.get_cache_metadata("historical_loaded")
            if metadata:
                return True
        return self._historical_loaded
    
    # ---- Summary stats ----
    
    def get_summary_stats(self, key: str) -> Optional[Dict[str, Any]]:
        if self.db_manager.use_database:
            return self.db_manager.get_summary_stats(key)
        return None
    
    def set_summary_stats(self, key: str, count: int, data: Dict[str, Any]):
        if self.db_manager.use_database:
            self.db_manager.save_summary_stats(key, count, data)
            print(f"[Cache] Saved summary stats for {key}")
    
    # ---- Timeline data ----
    
    def get_timeline_data(self, years=1) -> Optional[Dict[str, Any]]:
        if self.db_manager.use_database:
            return self.db_manager.get_timeline_data(years)
        return None
    
    def set_timeline_data(self, data: Dict[str, Any]):
        if self.db_manager.use_database and 'raw_data' in data:
            year_month_counts = {}
            for date_str, count in data['raw_data'].items():
                parts = date_str.split('-')
                if len(parts) >= 2:
                    year = int(parts[0])
                    month = int(parts[1])
                    year_month_counts[(year, month)] = count
            self.db_manager.save_timeline_data(year_month_counts)
            print(f"[Cache] Saved timeline data ({len(year_month_counts)} records)")
    
    # ---- Cache management ----
    
    def get_cache_stats(self) -> Dict[str, Any]:
        try:
            mem_mb = self.check_memory_usage()
            mem_percent = (mem_mb / self._max_memory_mb) * 100
        except:
            mem_mb = 0
            mem_percent = 0
        
        with self._lock:
            stats = {
                'memory_usage_mb': round(mem_mb, 2),
                'memory_usage_percent': round(mem_percent, 1),
                'memory_limit_mb': self._max_memory_mb,
                'cached_timestamps': len(self._cache_timestamps),
                'historical_loaded': self._historical_loaded,
                'cached_30_day_cves': len(self._cves_30_days),
                'cached_historical_years': list(self._historical_data.keys()),
                'database_enabled': self.db_manager.use_database,
                'cache_ages': {}
            }
            
            now = time.time()
            for key, ts in self._cache_timestamps.items():
                stats['cache_ages'][key] = f"{int((now - ts)/60)} minutes"
            
            if self.db_manager.use_database:
                stats.update(self.db_manager.get_stats())
        
        return stats
    
    def clear_cache(self):
        with self._lock:
            self._cves_30_days = []
            self._historical_data.clear()
            self._historical_loaded = False
            self._cache_timestamps.clear()
        
        if self.db_manager.use_database:
            self.db_manager.clear_all_cves()
        
        gc.collect()
        print("[Cache] All caches cleared")
    
    def clear_all(self):
        self.clear_cache()
        print("[Cache] All caches cleared including database")
    
    def warm_up_cache(self):
        mem_mb = self.check_memory_usage()
        
        if mem_mb > self._max_memory_mb * 0.5:
            print(f"[Cache] Skipping warm-up (memory at {mem_mb:.2f}MB)")
            return False
        
        if self.db_manager.use_database:
            print("[Cache] Warming up from database")
            self.db_manager.get_stats()
            return True
        
        return False

# Global instance
cache_manager = CacheManager()
