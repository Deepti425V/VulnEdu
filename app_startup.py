# app_startup.py
import os
import threading
import time
from datetime import datetime

# Global flag for initialization status
app_initialized = False
initialization_error = None

def initialize_app(use_file_cache=True):
    """Initialize application with optional file cache usage"""
    global app_initialized, initialization_error
    
    try:
        print(f"[App] Initializing at {datetime.now().isoformat()}")
        
        if use_file_cache:
            # Import file cache manager
            from file_cache_manager import file_cache_manager
            
            # Check if cache directory exists and has files
            cache_dir = file_cache_manager.cache_dir
            if os.path.exists(cache_dir):
                cache_files = [f for f in os.listdir(cache_dir) if f.endswith('.json.gz')]
                if cache_files:
                    print(f"[App] Found {len(cache_files)} cache files in {cache_dir}")
                else:
                    print(f"[App] Cache directory exists but no cache files found")
            else:
                print(f"[App] Cache directory {cache_dir} not found")
                os.makedirs(cache_dir, exist_ok=True)
            
            # Start with minimal data loading - just the 30-day trends
            from services.analysis.trend_analyzer import get_cve_trends_last_30_days
            
            print("[App] Loading 30-day trends (minimal data for startup)")
            trends = get_cve_trends_last_30_days()
            
            print(f"[App] Initial data loaded: {trends['total_cves']} CVEs")
            
            # Start background thread to preload timeline data
            if cache_files:
                thread = threading.Thread(
                    target=_preload_timeline_cache,
                    daemon=True
                )
                thread.start()
                print("[App] Started background thread to preload timeline")
        else:
            print("[App] File cache usage disabled")
        
        app_initialized = True
        print("[App] Initialization complete")
        return True
        
    except Exception as e:
        initialization_error = str(e)
        print(f"[App] ERROR during initialization: {str(e)}")
        app_initialized = False
        return False

def _preload_timeline_cache():
    """Background task to preload 1-year timeline in cache"""
    try:
        print("[Background] Starting preload of 1-year timeline...")
        time.sleep(5)  # Wait for app to stabilize
        
        from services.analysis.trend_analyzer import get_vulnerabilities_over_time_last_n_years
        
        # Load 1-year timeline to ensure it's in cache
        timeline = get_vulnerabilities_over_time_last_n_years(years=1)
        print(f"[Background] Preloaded 1-year timeline: {timeline['total_cves']} CVEs")
        
    except Exception as e:
        print(f"[Background] Error preloading timeline: {str(e)}")

def get_app_status():
    """Get application initialization status"""
    return {
        'initialized': app_initialized,
        'error': initialization_error,
        'timestamp': datetime.now().isoformat()
    }