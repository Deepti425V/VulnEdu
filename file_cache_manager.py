# file_cache_manager.py
import json
import gzip
import os
import time
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional

class FileCacheManager:
    def __init__(self, cache_dir="./data/file_cache"):
        # Create cache directory if it doesn't exist
        self.cache_dir = cache_dir
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)
        
        # Define cache file paths with templates
        self.cache_files = {
            'trends_30_days': os.path.join(cache_dir, 'cve_trends_30_days.json.gz'),
            'historical_year': os.path.join(cache_dir, 'historical_year_{year}.json.gz'),
            'timeline': os.path.join(cache_dir, 'vulnerability_timeline_{years}.json.gz')
        }
        
        # Cache expiration times (in seconds)
        self.expiration_times = {
            'trends_30_days': 6 * 60 * 60,  # 6 hours
            'historical_year': 7 * 24 * 60 * 60,  # 7 days
            'timeline': 24 * 60 * 60  # 24 hours
        }
        
        # Thread lock for thread safety
        self._lock = threading.Lock()
        self._stats = {'hits': 0, 'misses': 0, 'saves': 0, 'errors': 0}
    
    def get_cache_path(self, cache_type, **kwargs):
        """Get full path to cache file with parameter substitution"""
        base_path = self.cache_files.get(cache_type)
        if not base_path:
            return None
        return base_path.format(**kwargs) if kwargs else base_path
    
    def is_cache_valid(self, file_path):
        """Check if cache file exists and is not expired"""
        if not os.path.exists(file_path):
            return False
        
        # Get file modification time
        mod_time = os.path.getmtime(file_path)
        current_time = time.time()
        
        # Get cache type from path
        cache_type = None
        for key, pattern in self.cache_files.items():
            if key in file_path:
                cache_type = key
                break
        
        # Get appropriate expiration time
        expiration_time = self.expiration_times.get(cache_type, 24 * 60 * 60)
        
        # Check if cache is still valid
        return (current_time - mod_time) < expiration_time
    
    def load_from_cache(self, cache_type, **kwargs):
        """Load data from cache file if it exists and is valid"""
        with self._lock:
            file_path = self.get_cache_path(cache_type, **kwargs)
            
            if not file_path or not self.is_cache_valid(file_path):
                self._stats['misses'] += 1
                print(f"[FileCache] MISS: {file_path}")
                return None
            
            try:
                with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                    data = json.loads(f.read())
                
                self._stats['hits'] += 1
                print(f"[FileCache] HIT: {file_path}")
                return data
            
            except Exception as e:
                self._stats['errors'] += 1
                print(f"[FileCache] ERROR loading from {file_path}: {str(e)}")
                return None
    
    def save_to_cache(self, data, cache_type, **kwargs):
        """Save data to cache file with compression"""
        with self._lock:
            file_path = self.get_cache_path(cache_type, **kwargs)
            if not file_path:
                return False
            
            try:
                # Create parent directory if needed
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                
                # Convert data to JSON and compress
                json_str = json.dumps(data)
                with gzip.open(file_path, 'wt', encoding='utf-8') as f:
                    f.write(json_str)
                
                self._stats['saves'] += 1
                file_size = os.path.getsize(file_path) / 1024  # KB
                print(f"[FileCache] SAVED: {file_path} ({file_size:.1f} KB)")
                return True
            
            except Exception as e:
                self._stats['errors'] += 1
                print(f"[FileCache] ERROR saving to {file_path}: {str(e)}")
                return False
    
    def get_cache_stats(self):
        """Get cache statistics"""
        with self._lock:
            stats = self._stats.copy()
            stats['files'] = []
            total_size = 0
            
            # Get info about all cache files
            for pattern in self.cache_files.values():
                base_dir = os.path.dirname(pattern)
                if os.path.exists(base_dir):
                    for file in os.listdir(base_dir):
                        if file.endswith('.json.gz'):
                            file_path = os.path.join(base_dir, file)
                            size = os.path.getsize(file_path) / 1024  # KB
                            total_size += size
                            stats['files'].append({
                                'path': file_path,
                                'size': f"{size:.1f} KB",
                            })
            
            stats['total_size'] = f"{total_size:.1f} KB"
            return stats

# Create global instance
file_cache_manager = FileCacheManager()