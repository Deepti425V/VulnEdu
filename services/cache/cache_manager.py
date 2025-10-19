import json
import os
import time
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
import config

class CacheManager:
    """Enhanced caching system - NO warm-up on init"""
    
    def __init__(self):
        # In-memory cache storage
        self._memory_cache = {}
        self._cache_timestamps = {}
        
        # Historical data storage
        self._historical_data = None
        self._historical_loaded = False
        
        # Background task tracking
        self._background_tasks = {}
        
        # Thread lock for concurrent access
        self._lock = threading.Lock()
        
        # Cache durations
        self.API_CACHE_DURATION = 24 * 60 * 60  # 24 hours
        self.HISTORICAL_CACHE_DURATION = 7 * 24 * 60 * 60  # 7 days
        self.PAGINATION_CACHE_DURATION = 12 * 60 * 60  # 12 hours
    
    def get_api_data_30_days(self) -> Optional[List[Dict[str, Any]]]:
        """Get cached 30-day API data if valid"""
        cache_key = "api_30_days"
        
        with self._lock:
            if cache_key in self._memory_cache:
                timestamp = self._cache_timestamps.get(cache_key, 0)
                age = datetime.now().timestamp() - timestamp
                
                if age < self.API_CACHE_DURATION:
                    print(f"[Cache] Using cached 30-day API data (age: {int(age/60)} minutes)")
                    return self._memory_cache[cache_key]
        
        return None
    
    def set_api_data_30_days(self, data: List[Dict[str, Any]]):
        """Cache 30-day API data"""
        cache_key = "api_30_days"
        
        with self._lock:
            self._memory_cache[cache_key] = data
            self._cache_timestamps[cache_key] = datetime.now().timestamp()
        
        print(f"[Cache] Cached 30-day API data ({len(data)} CVEs)")
    
    def get_paginated_api_data(self, page_size: int = 1000, page: int = 1) -> Optional[Dict[str, Any]]:
        """Get paginated API data from cache"""
        cache_key = f"api_paginated_{page_size}_{page}"
        
        with self._lock:
            if cache_key in self._memory_cache:
                timestamp = self._cache_timestamps.get(cache_key, 0)
                age = datetime.now().timestamp() - timestamp
                
                if age < self.PAGINATION_CACHE_DURATION:
                    print(f"[Cache] Using cached paginated data page {page}")
                    return self._memory_cache[cache_key]
        
        return None
    
    def set_paginated_api_data(self, data: Dict[str, Any], page_size: int = 1000, page: int = 1):
        """Cache paginated API data"""
        cache_key = f"api_paginated_{page_size}_{page}"
        
        with self._lock:
            self._memory_cache[cache_key] = data
            self._cache_timestamps[cache_key] = datetime.now().timestamp()
        
        print(f"[Cache] Cached paginated data page {page} ({len(data.get('cves', []))} CVEs)")
    
    def get_processed_dashboard_data(self) -> Optional[Dict[str, Any]]:
        """Get cached processed dashboard data"""
        cache_key = "dashboard_processed"
        
        with self._lock:
            if cache_key in self._memory_cache:
                timestamp = self._cache_timestamps.get(cache_key, 0)
                age = datetime.now().timestamp() - timestamp
                
                if age < self.API_CACHE_DURATION:
                    print(f"[Cache] Using cached dashboard data (age: {int(age/60)} minutes)")
                    return self._memory_cache[cache_key]
        
        return None
    
    def set_processed_dashboard_data(self, data: Dict[str, Any]):
        """Cache processed dashboard data"""
        cache_key = "dashboard_processed"
        
        with self._lock:
            self._memory_cache[cache_key] = data
            self._cache_timestamps[cache_key] = datetime.now().timestamp()
        
        print(f"[Cache] Cached processed dashboard data")
    
    def get_historical_data(self) -> Optional[Dict[str, List[Dict]]]:
        """Get cached historical data if valid"""
        if self._historical_loaded and self._historical_data:
            print("[Cache] Using cached historical data")
            return self._historical_data
        
        return None
    
    def set_historical_data(self, data: Dict[str, List[Dict]]):
        """Cache historical data"""
        with self._lock:
            self._historical_data = data
            self._historical_loaded = True
        
        total_cves = sum(len(year_data) for year_data in data.values())
        print(f"[Cache] Cached historical data ({total_cves} CVEs across {len(data)} years)")
    
    def start_background_load(self, task_name: str, target_function, *args, **kwargs):
        """Start a background task for loading data"""
        def background_task():
            try:
                print(f"[Cache] Starting background task: {task_name}")
                result = target_function(*args, **kwargs)
                
                with self._lock:
                    self._background_tasks[task_name] = {
                        'status': 'completed',
                        'result': result,
                        'timestamp': datetime.now().timestamp()
                    }
                
                print(f"[Cache] Background task completed: {task_name}")
            except Exception as e:
                print(f"[Cache] Background task failed: {task_name} - {e}")
                with self._lock:
                    self._background_tasks[task_name] = {
                        'status': 'failed',
                        'error': str(e),
                        'timestamp': datetime.now().timestamp()
                    }
        
        with self._lock:
            self._background_tasks[task_name] = {
                'status': 'running',
                'timestamp': datetime.now().timestamp()
            }
        
        thread = threading.Thread(target=background_task)
        thread.daemon = True
        thread.start()
        
        print(f"[Cache] Started background task: {task_name}")
    
    def get_background_task_status(self, task_name: str) -> Optional[Dict[str, Any]]:
        """Get the status of a background task"""
        with self._lock:
            return self._background_tasks.get(task_name)
    
    def get_background_task_result(self, task_name: str) -> Optional[Any]:
        """Get the result of a completed background task"""
        with self._lock:
            task = self._background_tasks.get(task_name)
            if task and task.get('status') == 'completed':
                return task.get('result')
        
        return None
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            stats = {
                'memory_cache_entries': len(self._memory_cache),
                'historical_loaded': self._historical_loaded,
                'background_tasks': len(self._background_tasks),
                'cache_ages': {}
            }
            
            current_time = datetime.now().timestamp()
            for key, timestamp in self._cache_timestamps.items():
                age_minutes = int((current_time - timestamp) / 60)
                stats['cache_ages'][key] = f"{age_minutes} minutes"
            
            stats['background_task_statuses'] = {}
            for task_name, task_info in self._background_tasks.items():
                stats['background_task_statuses'][task_name] = task_info.get('status', 'unknown')
            
            return stats
    
    def clear_expired_cache(self):
        """Clear expired cache entries"""
        current_time = datetime.now().timestamp()
        expired_keys = []
        
        with self._lock:
            for key, timestamp in self._cache_timestamps.items():
                age = current_time - timestamp
                
                if key.startswith('api_'):
                    expiry_time = self.API_CACHE_DURATION
                elif key.startswith('dashboard_'):
                    expiry_time = self.API_CACHE_DURATION
                else:
                    expiry_time = self.HISTORICAL_CACHE_DURATION
                
                if age > expiry_time:
                    expired_keys.append(key)
            
            for key in expired_keys:
                if key in self._memory_cache:
                    del self._memory_cache[key]
                if key in self._cache_timestamps:
                    del self._cache_timestamps[key]
        
        if expired_keys:
            print(f"[Cache] Cleared {len(expired_keys)} expired cache entries")
    
    def clear_cache(self):
        """Clear all cached data"""
        with self._lock:
            self._memory_cache.clear()
            self._cache_timestamps.clear()
            self._historical_data = None
            self._historical_loaded = False
            self._background_tasks.clear()
        
        print("[Cache] All caches cleared")
    
    def warm_up_cache(self):
        """NO-OP - Cache builds on demand"""
        print("[Cache] Cache system initialized (no startup preload)")
        # CRITICAL: Do NOT load anything here

# Global cache instance - NO execution on instantiation
cache_manager = CacheManager()