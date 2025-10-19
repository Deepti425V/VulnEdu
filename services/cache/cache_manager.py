# JSON serialization for potential cache persistence (not currently used)
import json
# Operating system interface for file operations (not currently used)
import os
# Time operations for performance measurement (not currently used)
import time
# Thread management for background processing and synchronization
import threading
# Date/time operations for cache expiration and timestamps
from datetime import datetime, timezone, timedelta
# Type hints for function parameters and return values
from typing import Dict, List, Any, Optional
# Application configuration (not currently used)
import config

class CacheManager:
    """Enhanced caching system with long-term persistence for live presentations"""
    def __init__(self):
        # In-memory cache storage for fast data access
        self._memory_cache = {}
        # Timestamp tracking for cache expiration management
        self._cache_timestamps = {}
        # Historical data storage and loading state
        self._historical_data = None
        self._historical_loaded = False
        # Background task tracking for async operations
        self._background_tasks = {}
        # Thread lock for concurrent access safety
        self._lock = threading.Lock()
        # EXTENDED cache durations for live presentation
        self.API_CACHE_DURATION = 24 * 60 * 60  # 24 hours for API data
        self.HISTORICAL_CACHE_DURATION = 7 * 24 * 60 * 60  # 7 days for historical data
        self.PAGINATION_CACHE_DURATION = 12 * 60 * 60  # 12 hours for paginated results

    def get_api_data_30_days(self) -> Optional[List[Dict[str, Any]]]:
        """Get cached 30-day API data if valid"""
        cache_key = "api_30_days"
        # Thread-safe cache access
        with self._lock:
            if cache_key in self._memory_cache:
                timestamp = self._cache_timestamps.get(cache_key, 0)
                age = datetime.now().timestamp() - timestamp
                # Check if data is still fresh
                if age < self.API_CACHE_DURATION:
                    print(f"[Cache] Using cached 30-day API data (age: {int(age/60)} minutes)")
                    return self._memory_cache[cache_key]
        return None

    def set_api_data_30_days(self, data: List[Dict[str, Any]]):
        """Cache 30-day API data"""
        cache_key = "api_30_days"
        # Thread-safe cache storage
        with self._lock:
            self._memory_cache[cache_key] = data
            self._cache_timestamps[cache_key] = datetime.now().timestamp()
        print(f"[Cache] Cached 30-day API data ({len(data)} CVEs)")

    def get_paginated_api_data(self, page_size: int = 1000, page: int = 1) -> Optional[Dict[str, Any]]:
        """Get paginated API data from cache"""
        # Create page-specific cache key
        cache_key = f"api_paginated_{page_size}_{page}"
        with self._lock:
            if cache_key in self._memory_cache:
                timestamp = self._cache_timestamps.get(cache_key, 0)
                age = datetime.now().timestamp() - timestamp
                # Check pagination cache expiration
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
                # Use same expiration as API data for dashboard freshness
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
        # Historical data cached until explicitly cleared
        if self._historical_loaded and self._historical_data:
            print("[Cache] Using cached historical data")
            return self._historical_data
        return None

    def set_historical_data(self, data: Dict[str, List[Dict]]):
        """Cache historical data"""
        with self._lock:
            self._historical_data = data
            self._historical_loaded = True
        # Calculate total CVEs across all years for logging
        total_cves = sum(len(year_data) for year_data in data.values())
        print(f"[Cache] Cached historical data ({total_cves} CVEs across {len(data)} years)")

    def start_background_load(self, task_name: str, target_function, *args, **kwargs):
        """Start a background task for loading data"""
        def background_task():
            try:
                print(f"[Cache] Starting background task: {task_name}")
                # Execute the target function with provided arguments
                result = target_function(*args, **kwargs)
                # Store successful result
                with self._lock:
                    self._background_tasks[task_name] = {
                        'status': 'completed',
                        'result': result,
                        'timestamp': datetime.now().timestamp()
                    }
                print(f"[Cache] Background task completed: {task_name}")
            except Exception as e:
                # Store error information for debugging
                print(f"[Cache] Background task failed: {task_name} - {e}")
                with self._lock:
                    self._background_tasks[task_name] = {
                        'status': 'failed',
                        'error': str(e),
                        'timestamp': datetime.now().timestamp()
                    }

        # Initialize task status as running
        with self._lock:
            self._background_tasks[task_name] = {
                'status': 'running',
                'timestamp': datetime.now().timestamp()
            }
        
        # Create and start daemon thread for background execution
        thread = threading.Thread(target=background_task)
        thread.daemon = True  # Don't prevent application shutdown
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

    def preload_data_async(self):
        """Minimal preload - no longer used on startup"""
        print("[Cache] Preload skipped - cache builds on-demand")
        pass

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            stats = {
                'memory_cache_entries': len(self._memory_cache),
                'historical_loaded': self._historical_loaded,
                'background_tasks': len(self._background_tasks),
                'cache_ages': {}
            }
            
            # Calculate human-readable cache ages
            current_time = datetime.now().timestamp()
            for key, timestamp in self._cache_timestamps.items():
                age_minutes = int((current_time - timestamp) / 60)
                stats['cache_ages'][key] = f"{age_minutes} minutes"
            
            # Collect background task statuses for monitoring
            stats['background_task_statuses'] = {}
            for task_name, task_info in self._background_tasks.items():
                stats['background_task_statuses'][task_name] = task_info.get('status', 'unknown')
            
            return stats

    def clear_expired_cache(self):
        """Clear expired cache entries"""
        current_time = datetime.now().timestamp()
        expired_keys = []
        
        with self._lock:
            # Check each cached item for expiration
            for key, timestamp in self._cache_timestamps.items():
                age = current_time - timestamp
                # Determine expiry time based on cache type
                if key.startswith('api_'):
                    expiry_time = self.API_CACHE_DURATION
                elif key.startswith('dashboard_'):
                    expiry_time = self.API_CACHE_DURATION
                else:
                    expiry_time = self.HISTORICAL_CACHE_DURATION
                
                # Mark expired items for removal
                if age > expiry_time:
                    expired_keys.append(key)
            
            # Remove expired entries atomically
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
            # Reset all cache structures
            self._memory_cache.clear()
            self._cache_timestamps.clear()
            self._historical_data = None
            self._historical_loaded = False
            self._background_tasks.clear()
        print("[Cache] All caches cleared")

    def warm_up_cache(self):
        """Minimal warm-up - cache builds on-demand via /api/cache-builder"""
        print("[Cache] Cache system initialized (no startup preload)")
        # Don't load anything on startup - prevents blocking Render deployment
        # Cache will be built by:
        # 1. First page load (loads API data only)
        # 2. UptimeRobot calling /api/cache-builder (gradually loads historical data)

# Global cache instance for application-wide use
cache_manager = CacheManager()