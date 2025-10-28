"""Memory monitoring and management utilities for Render deployment"""

import psutil
import os
import gc
import threading
import time
from typing import Dict, Tuple, Optional
import config

class MemoryMonitor:
    """Monitor and manage memory usage for Render's 512MB limit"""
    
    def __init__(self, max_memory_mb: int = None):
        self.max_memory_mb = max_memory_mb or config.MAX_MEMORY_USAGE_MB
        self.warning_threshold = 0.8  # 80% of max
        self.critical_threshold = 0.9  # 90% of max
        self.last_cleanup = time.time()
        self.cleanup_interval = 60  # Minimum seconds between cleanups
        
        print(f"[MemoryMonitor] Initialized with {self.max_memory_mb}MB limit")
    
    def get_memory_info(self) -> Dict[str, float]:
        """Get current memory usage information"""
        try:
            process = psutil.Process(os.getpid())
            mem_info = process.memory_info()
            
            # Get system memory info
            vm = psutil.virtual_memory()
            
            return {
                'rss_mb': mem_info.rss / 1024 / 1024,
                'vms_mb': mem_info.vms / 1024 / 1024,
                'percent_of_limit': (mem_info.rss / 1024 / 1024 / self.max_memory_mb) * 100,
                'system_percent': vm.percent,
                'available_mb': vm.available / 1024 / 1024,
                'total_mb': vm.total / 1024 / 1024
            }
        except Exception as e:
            print(f"[MemoryMonitor] Error getting memory info: {e}")
            return {
                'rss_mb': 0,
                'vms_mb': 0,
                'percent_of_limit': 0,
                'system_percent': 0,
                'available_mb': 0,
                'total_mb': 0
            }
    
    def check_memory_status(self) -> Tuple[str, Dict[str, float]]:
        """Check memory status and return status level and info"""
        info = self.get_memory_info()
        percent = info['percent_of_limit']
        
        if percent >= self.critical_threshold * 100:
            return 'CRITICAL', info
        elif percent >= self.warning_threshold * 100:
            return 'WARNING', info
        else:
            return 'OK', info
    
    def perform_cleanup(self, level: str = 'standard') -> bool:
        """Perform memory cleanup based on level"""
        
        # Check if enough time has passed since last cleanup
        if time.time() - self.last_cleanup < self.cleanup_interval:
            return False
        
        print(f"[MemoryMonitor] Performing {level} cleanup...")
        self.last_cleanup = time.time()
        
        # Get before stats
        before = self.get_memory_info()
        
        if level == 'emergency':
            # Emergency cleanup - clear everything possible
            self._emergency_cleanup()
        elif level == 'aggressive':
            # Aggressive cleanup - clear most caches
            self._aggressive_cleanup()
        else:
            # Standard cleanup - basic garbage collection
            self._standard_cleanup()
        
        # Get after stats
        after = self.get_memory_info()
        
        freed_mb = before['rss_mb'] - after['rss_mb']
        print(f"[MemoryMonitor] Cleanup completed. Freed: {freed_mb:.2f}MB")
        print(f"[MemoryMonitor] Memory: {after['rss_mb']:.2f}MB / {self.max_memory_mb}MB ({after['percent_of_limit']:.1f}%)")
        
        return freed_mb > 0
    
    def _standard_cleanup(self):
        """Standard garbage collection"""
        gc.collect()
    
    def _aggressive_cleanup(self):
        """Aggressive cache clearing and garbage collection"""
        # Import here to avoid circular dependency
        from services.cache.cache_manager import cache_manager
        
        # Clear historical data from cache
        cache_manager._historical_data.clear()
        
        # Multiple GC passes
        for _ in range(2):
            gc.collect()
    
    def _emergency_cleanup(self):
        """Emergency cleanup - clear all possible memory"""
        # Import here to avoid circular dependency
        from services.cache.cache_manager import cache_manager
        
        # Clear all caches
        cache_manager.clear_cache()
        
        # Clear any module-level caches
        import sys
        sys.modules.clear()
        
        # Force multiple aggressive GC cycles
        for _ in range(3):
            gc.collect(2)  # Collect oldest generation
    
    def auto_manage_memory(self):
        """Automatically manage memory based on usage"""
        status, info = self.check_memory_status()
        
        if status == 'CRITICAL':
            print(f"[MemoryMonitor] CRITICAL: Memory at {info['rss_mb']:.2f}MB ({info['percent_of_limit']:.1f}%)")
            self.perform_cleanup('emergency')
        elif status == 'WARNING':
            print(f"[MemoryMonitor] WARNING: Memory at {info['rss_mb']:.2f}MB ({info['percent_of_limit']:.1f}%)")
            self.perform_cleanup('aggressive')
        
        return status, info
    
    def start_monitoring(self, interval: int = 30):
        """Start background memory monitoring"""
        def monitor():
            while True:
                time.sleep(interval)
                self.auto_manage_memory()
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        print(f"[MemoryMonitor] Background monitoring started (interval: {interval}s)")


class MemoryContext:
    """Context manager for memory-intensive operations"""
    
    def __init__(self, operation_name: str, cleanup_after: bool = True):
        self.operation_name = operation_name
        self.cleanup_after = cleanup_after
        self.monitor = MemoryMonitor()
        self.start_memory = None
    
    def __enter__(self):
        self.start_memory = self.monitor.get_memory_info()
        print(f"[Memory] Starting '{self.operation_name}' - Memory: {self.start_memory['rss_mb']:.2f}MB")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        end_memory = self.monitor.get_memory_info()
        memory_delta = end_memory['rss_mb'] - self.start_memory['rss_mb']
        
        print(f"[Memory] Completed '{self.operation_name}'")
        print(f"[Memory] Memory delta: {memory_delta:+.2f}MB (now: {end_memory['rss_mb']:.2f}MB)")
        
        if self.cleanup_after:
            gc.collect()
        
        # Check if we need emergency cleanup
        if end_memory['percent_of_limit'] > 90:
            print(f"[Memory] High memory after operation, performing cleanup...")
            self.monitor.perform_cleanup('aggressive')


def check_memory_available(required_mb: int = 100) -> bool:
    """Check if enough memory is available for an operation"""
    try:
        vm = psutil.virtual_memory()
        available_mb = vm.available / 1024 / 1024
        
        if available_mb < required_mb:
            print(f"[Memory] Insufficient memory: {available_mb:.2f}MB available, {required_mb}MB required")
            return False
        
        return True
    except Exception as e:
        print(f"[Memory] Error checking available memory: {e}")
        return False


def get_memory_usage_string() -> str:
    """Get a formatted string of current memory usage"""
    try:
        process = psutil.Process(os.getpid())
        mem_mb = process.memory_info().rss / 1024 / 1024
        max_mb = config.MAX_MEMORY_USAGE_MB
        percent = (mem_mb / max_mb) * 100
        
        # Color code based on usage
        if percent > 90:
            status = "CRITICAL"
        elif percent > 80:
            status = "WARNING"
        elif percent > 70:
            status = "CAUTION"
        else:
            status = "OK"
        
        return f"Memory: {mem_mb:.1f}/{max_mb}MB ({percent:.1f}%) [{status}]"
    except:
        return "Memory: Unknown"


# Global monitor instance
memory_monitor = MemoryMonitor()

# Start background monitoring on import
memory_monitor.start_monitoring()