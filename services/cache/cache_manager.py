import threading
import gzip
import pickle
import os
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
import config

class CacheManager:
    """Lightweight caching system with GZIP compression for 512MB RAM + DISK PERSISTENCE"""
    
    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self.historical_loaded = False
        self.lock = threading.Lock()
        
        # Cache configuration
        self.cache_duration = config.CACHE_DURATION
        self.enable_gzip = config.ENABLE_GZIP_CACHE
        
        # Disk cache directory
        self.disk_cache_dir = os.path.join(config.CACHE_DIR, 'memory_cache')
        os.makedirs(self.disk_cache_dir, exist_ok=True)
        
        print(f"[Cache] Initialized with GZIP={'enabled' if self.enable_gzip else 'disabled'}, duration={self.cache_duration}")
        
        # Load vendor risk from disk if available
        self._load_vendor_risk_from_disk()
    
    def _load_vendor_risk_from_disk(self):
        """Load vendor risk from disk cache on startup"""
        vendor_cache_file = os.path.join(self.disk_cache_dir, 'vendor_risk.pkl.gz')
        
        if os.path.exists(vendor_cache_file):
            try:
                # Check if file is less than 24 hours old
                file_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(vendor_cache_file))
                if file_age < timedelta(hours=24):
                    with open(vendor_cache_file, 'rb') as f:
                        compressed_data = f.read()
                        decompressed = gzip.decompress(compressed_data)
                        vendor_data = pickle.loads(decompressed)
                    
                    # Store in memory cache
                    self._cache['vendor_risk'] = {
                        'data': compressed_data,
                        'timestamp': datetime.fromtimestamp(os.path.getmtime(vendor_cache_file), tz=timezone.utc),
                        'compressed': True
                    }
                    
                    age_hours = int(file_age.total_seconds() / 3600)
                    print(f"[Cache] ✓ Loaded vendor risk from disk (age: {age_hours}h)")
                else:
                    print(f"[Cache] Disk cache too old ({file_age}), will recalculate")
                    os.remove(vendor_cache_file)
            except Exception as e:
                print(f"[Cache] Error loading vendor risk from disk: {e}")
    
    def set(self, key: str, data: Any) -> bool:
        """Store data in cache with optional GZIP compression"""
        try:
            with self.lock:
                # Serialize data
                serialized = pickle.dumps(data)
                
                # Compress if enabled
                if self.enable_gzip:
                    compressed = gzip.compress(serialized, compresslevel=6)
                    original_size = len(serialized)
                    compressed_size = len(compressed)
                    compression_ratio = (1 - compressed_size / original_size) * 100
                    print(f"[Cache] Compressed {key}: {original_size:,} -> {compressed_size:,} bytes ({compression_ratio:.1f}% reduction)")
                    data_to_store = compressed
                else:
                    data_to_store = serialized
                
                # Store with timestamp
                self._cache[key] = {
                    'data': data_to_store,
                    'timestamp': datetime.now(timezone.utc),
                    'compressed': self.enable_gzip
                }
                
                # Save vendor risk to disk for persistence across restarts
                if key == 'vendor_risk':
                    self._save_vendor_risk_to_disk(data_to_store)
                
                return True
        except Exception as e:
            print(f"[Cache] Error storing {key}: {e}")
            return False
    
    def _save_vendor_risk_to_disk(self, compressed_data):
        """Save vendor risk to disk for persistence"""
        try:
            vendor_cache_file = os.path.join(self.disk_cache_dir, 'vendor_risk.pkl.gz')
            with open(vendor_cache_file, 'wb') as f:
                f.write(compressed_data)
            print(f"[Cache] ✓ Saved vendor risk to disk for persistence")
        except Exception as e:
            print(f"[Cache] Warning: Could not save vendor risk to disk: {e}")
    
    def get(self, key: str) -> Optional[Any]:
        """Retrieve data from cache"""
        with self.lock:
            if key not in self._cache:
                return None
            
            try:
                cache_entry = self._cache[key]
                
                # Check if cache is expired
                cache_age = datetime.now(timezone.utc) - cache_entry['timestamp']
                if cache_age > self.cache_duration:
                    print(f"[Cache] {key} expired (age: {cache_age})")
                    del self._cache[key]
                    return None
                
                # Decompress if needed
                data_bytes = cache_entry['data']
                if cache_entry['compressed']:
                    decompressed = gzip.decompress(data_bytes)
                    data = pickle.loads(decompressed)
                else:
                    data = pickle.loads(data_bytes)
                
                age_minutes = int(cache_age.total_seconds() / 60)
                print(f"[Cache] ✓ Hit for {key} (age: {age_minutes}min)")
                return data
                
            except Exception as e:
                print(f"[Cache] Error retrieving {key}: {e}")
                if key in self._cache:
                    del self._cache[key]
                return None
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            total_size = 0
            for entry in self._cache.values():
                total_size += len(entry['data'])
            
            stats = {
                'cached_entries': len(self._cache),
                'total_size_mb': round(total_size / (1024 * 1024), 2),
                'cache_duration_hours': self.cache_duration.total_seconds() / 3600,
                'cache_keys': list(self._cache.keys())
            }
            
            return stats
    
    def clear_cache(self):
        """Clear all cached data"""
        with self.lock:
            self._cache.clear()
            self.historical_loaded = False
            print("[Cache] All caches cleared")

# Global cache instance
cache_manager = CacheManager()
