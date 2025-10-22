import os
import json
import threading
from typing import Dict, List, Any
from datetime import datetime, timezone, timedelta
from services.analysis.trend_analyzer import get_cve_trends_last_30_days
from services.data.api_client import api_client
from services.data.data_source_config import data_source_config
from services.cache.cache_manager import cache_manager
import config

class DataOrchestrator:
    """Memory-optimized orchestrator with STAGED LOADING for 512MB RAM"""
    
    def __init__(self):
        data_source_config.log_data_source_status()
        self._last_refresh_time = None
        self._full_data_loaded = False
        self._loading_progress = {
            'stage': 'idle',
            'progress': 0,
            'message': 'Not started',
            'started_at': None,
            'completed_at': None,
            'error': None
        }
        self._loading_lock = threading.Lock()
        print("[Orchestrator] Initialized with STAGED LOADING for 512MB")
    
    def get_loading_progress(self):
        """Get current loading progress for progress tracker"""
        with self._loading_lock:
            return self._loading_progress.copy()
    
    def get_dashboard_data(self, year=None, month=None, day=None, severity_filter=None, 
                          timeline_years=1, load_historical=False, lite_mode=True):
        """Get dashboard data - LITE MODE for first load"""
        print(f"[Orchestrator] Loading dashboard (lite_mode={lite_mode}): year={year}, month={month}, severity={severity_filter}")
        
        try:
            cache_key = f"dashboard_{year}_{month}_{day}_{severity_filter}_{timeline_years}"
            cached_data = cache_manager.get(cache_key)
            if cached_data:
                print(f"[Orchestrator] ✓ Returning CACHED dashboard data")
                return cached_data
            
            print("[Orchestrator] Cache MISS - Loading data...")
            
            if lite_mode and not self._full_data_loaded:
                cve_trends = self._get_lite_cve_trends()
            else:
                cve_trends = self._get_cve_trends_cached()
            
            if lite_mode and not self._full_data_loaded:
                vulnerabilities_timeline = self._get_empty_timeline()
            else:
                vulnerabilities_timeline = self._get_timeline_cached(timeline_years)
            
            if lite_mode and not self._full_data_loaded:
                filtered_cves = self._get_lite_filtered_cves()
            else:
                filtered_cves = self._get_filtered_cves_cached(year=year, month=month, day=day)
            
            if severity_filter:
                from utils.filters import FilterService
                filter_service = FilterService()
                filtered_cves = filter_service.filter_by_severity(filtered_cves, severity_filter)
            
            from collections import Counter
            severity_counts = Counter()
            for cve in filtered_cves:
                severity = cve.get('Severity', 'UNKNOWN').upper()
                if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    severity_counts[severity] += 1
                else:
                    severity_counts['UNKNOWN'] += 1
            
            severity_metrics = {
                'CRITICAL': severity_counts.get('CRITICAL', 0),
                'HIGH': severity_counts.get('HIGH', 0),
                'MEDIUM': severity_counts.get('MEDIUM', 0),
                'LOW': severity_counts.get('LOW', 0),
                'UNKNOWN': severity_counts.get('UNKNOWN', 0),
                'total_cves': len(filtered_cves)
            }
            
            total = len(filtered_cves)
            if total > 0:
                severity_percentages = {}
                for key in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                    percentage = round((severity_counts.get(key, 0) * 100 / total))
                    severity_percentages[key] = f"{percentage}%"
            else:
                severity_percentages = {k: "0%" for k in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']}
            
            if lite_mode and not self._full_data_loaded:
                vendor_risk, weighted_vendor_risk = self._get_empty_vendor_risk(), {'indices': [], 'labels': [], 'values': []}
            else:
                vendor_risk, weighted_vendor_risk = self._get_vendor_risk_cached()
            
            note_text = self._generate_note_text(year, month, day, severity_filter, load_historical, timeline_years)
            if lite_mode and not self._full_data_loaded:
                note_text += " (Full data loading in background...)"
            
            dashboard_data = {
                'metrics': severity_metrics,
                'total_cves': len(filtered_cves),
                'severity_percentage': severity_percentages,
                'timeline_data_days': cve_trends,
                'timeline_data_years': vulnerabilities_timeline,
                'cwe_radar': vendor_risk.get('top_10_cwes', {'indices': [], 'labels': [], 'values': []}),
                'cwe_radar_all': vendor_risk,
                'cwe_radar_weighted': weighted_vendor_risk,
                'cwe_radar_descriptions': {},
                'latest_cves': filtered_cves,
                'available_years': list(range(datetime.now().year, 2009, -1)),
                'available_months': list(range(1, 13)),
                'note_text': note_text,
                'historical_loaded': True,
                'lite_mode': lite_mode and not self._full_data_loaded
            }
            
            cache_manager.set(cache_key, dashboard_data)
            
            return dashboard_data
            
        except Exception as e:
            print(f"[Orchestrator] Error: {e}")
            import traceback
            traceback.print_exc()
            raise e
    
    def _get_lite_cve_trends(self):
        """Get LITE CVE trends - only 200 CVEs"""
        cached = cache_manager.get("cve_trends_lite")
        if cached:
            return cached
        
        cves = api_client.get_cves_last_30_days(batch_size=200, offset=0)
        
        from collections import defaultdict
        daily_counts = defaultdict(int)
        today = datetime.now(timezone.utc).date()
        
        for i in range(30):
            day = today - timedelta(days=29-i)
            daily_counts[day.strftime('%Y-%m-%d')] = 0
        
        for cve in cves:
            pub_date = cve.get('Published', '')
            if pub_date:
                try:
                    if 'T' in pub_date:
                        dt = datetime.fromisoformat(pub_date.replace('Z', '+00:00'))
                    else:
                        dt = datetime.strptime(pub_date[:10], '%Y-%m-%d')
                    date_key = dt.date().strftime('%Y-%m-%d')
                    if date_key in daily_counts:
                        daily_counts[date_key] += 1
                except:
                    continue
        
        sorted_dates = sorted(daily_counts.keys())
        result = {
            'labels': sorted_dates,
            'values': [daily_counts[date] for date in sorted_dates],
            'total_cves': len(cves)
        }
        
        cache_manager.set("cve_trends_lite", result)
        return result
    
    def _get_lite_filtered_cves(self):
        """Get LITE filtered CVEs - only 200"""
        cached = cache_manager.get("filtered_cves_lite")
        if cached:
            return cached
        
        cves = api_client.get_cves_last_30_days(batch_size=200, offset=0)
        cache_manager.set("filtered_cves_lite", cves)
        return cves
    
    def _get_empty_timeline(self):
        """Return empty timeline"""
        return {
            'labels': [],
            'values': [],
            'total_cves': 0,
            'months_covered': 0,
            'raw_data': {}
        }
    
    def warm_cache_staged(self):
        """STAGED LOADING - Load data in 3 stages to stay under 512MB"""
        print("[Orchestrator] ===== STAGED CACHE WARMING STARTED =====")
        
        with self._loading_lock:
            self._loading_progress = {
                'stage': 'started',
                'progress': 0,
                'message': 'Starting staged data loading...',
                'started_at': datetime.now().isoformat(),
                'completed_at': None,
                'error': None
            }
        
        try:
            # STAGE 1: Load ALL CVEs (4112 CVEs)
            self._update_progress('stage1', 10, 'Stage 1/3: Loading all 4112 CVEs...')
            print("[Orchestrator] STAGE 1: Loading CVE trends (ALL CVEs)...")
            from services.analysis.trend_analyzer import get_cve_trends_last_30_days
            cve_trends = get_cve_trends_last_30_days()
            cache_manager.set("cve_trends_30days", cve_trends)
            print(f"[Orchestrator] ✓ Stage 1 complete: {cve_trends['total_cves']} CVEs loaded")
            self._update_progress('stage1', 40, f'Stage 1/3: {cve_trends["total_cves"]} CVEs loaded')
            
            # STAGE 2: Load 3-month timeline (lighter than 12 months)
            self._update_progress('stage2', 50, 'Stage 2/3: Loading 3-month timeline...')
            print("[Orchestrator] STAGE 2: Loading 3-month timeline...")
            from services.analysis.trend_analyzer import get_vulnerabilities_over_time_last_n_months
            timeline = get_vulnerabilities_over_time_last_n_months(3)
            cache_manager.set("timeline_3months", timeline)
            print(f"[Orchestrator] ✓ Stage 2 complete: Timeline with {timeline['total_cves']} CVEs")
            self._update_progress('stage2', 70, f'Stage 2/3: Timeline loaded ({timeline["total_cves"]} CVEs)')
            
            # STAGE 3: Skip vendor risk to save memory
            self._update_progress('stage3', 90, 'Stage 3/3: Finalizing...')
            print("[Orchestrator] STAGE 3: Skipping vendor risk to save memory")
            
            # Mark as complete
            self._full_data_loaded = True
            stats = cache_manager.get_cache_stats()
            
            self._update_progress('completed', 100, f'✓ All data loaded! {cve_trends["total_cves"]} CVEs cached')
            
            with self._loading_lock:
                self._loading_progress['completed_at'] = datetime.now().isoformat()
            
            print("[Orchestrator] ===== STAGED CACHE WARMING COMPLETED =====")
            print(f"  - CVE Trends: {cve_trends['total_cves']} CVEs")
            print(f"  - Timeline: {timeline['total_cves']} CVEs (3 months)")
            print(f"  - Cache size: {stats['total_size_mb']:.1f} MB")
            
            return {
                'success': True,
                'message': 'Staged cache warming completed',
                'cve_trends_total': cve_trends['total_cves'],
                'timeline_total': timeline['total_cves'],
                'stats': stats
            }
            
        except Exception as e:
            error_msg = f"Error during staged loading: {str(e)}"
            print(f"[Orchestrator] ❌ {error_msg}")
            import traceback
            traceback.print_exc()
            
            with self._loading_lock:
                self._loading_progress['stage'] = 'error'
                self._loading_progress['error'] = error_msg
                self._loading_progress['completed_at'] = datetime.now().isoformat()
            
            return {
                'success': False,
                'error': error_msg,
                'traceback': traceback.format_exc()
            }
    
    def _update_progress(self, stage, progress, message):
        """Update loading progress"""
        with self._loading_lock:
            self._loading_progress['stage'] = stage
            self._loading_progress['progress'] = progress
            self._loading_progress['message'] = message
        print(f"[Progress] {progress}% - {message}")
    
    def _get_cve_trends_cached(self):
        """Get full CVE trends"""
        cached = cache_manager.get("cve_trends_30days")
        if cached:
            return cached
        
        trends = get_cve_trends_last_30_days()
        cache_manager.set("cve_trends_30days", trends)
        return trends
    
    def _get_timeline_cached(self, years=1):
        """Get timeline - use 3-month cached version"""
        cached = cache_manager.get("timeline_3months")
        if cached:
            return cached
        return self._get_empty_timeline()
    
    def _get_filtered_cves_cached(self, year=None, month=None, day=None) -> List[Dict[str, Any]]:
        """Get full filtered CVEs"""
        cache_key = f"filtered_cves_{year}_{month}_{day}"
        cached = cache_manager.get(cache_key)
        if cached:
            return cached
        
        if not year:
            all_cves = []
            offset = 0
            batch_size = config.API_BATCH_SIZE
            max_iterations = 15
            iteration = 0
            
            while iteration < max_iterations:
                iteration += 1
                batch = api_client.get_cves_last_30_days(batch_size=batch_size, offset=offset)
                if not batch:
                    break
                all_cves.extend(batch)
                if len(batch) < batch_size:
                    break
                offset += batch_size
            
            cache_manager.set(cache_key, all_cves)
            return all_cves
        else:
            cves = api_client.get_cves_for_date_range(year=year, month=month, day=day, batch_size=config.API_BATCH_SIZE)
            cache_manager.set(cache_key, cves)
            return cves
    
    def get_filtered_cves(self, year=None, month=None, day=None) -> List[Dict[str, Any]]:
        return self._get_filtered_cves_cached(year=year, month=month, day=day)
    
    def _get_vendor_risk_cached(self):
        """Get vendor risk"""
        cached = cache_manager.get("vendor_risk")
        if cached:
            return cached
        
        empty_risk = self._get_empty_vendor_risk()
        return (empty_risk, {'indices': [], 'labels': [], 'values': []})
    
    def get_cve_detail(self, cve_id: str) -> Dict[str, Any]:
        return api_client.get_cve_detail(cve_id)
    
    def clear_cache(self):
        api_client.clear_cache()
        cache_manager.clear_cache()
        self._full_data_loaded = False
    
    def get_data_source_status(self) -> Dict[str, Any]:
        return data_source_config.get_status()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        return cache_manager.get_cache_stats()
    
    def _get_empty_vendor_risk(self):
        return {
            'top_5_cwes': {'indices': [], 'labels': [], 'values': []},
            'top_10_cwes': {'indices': [], 'labels': [], 'values': []},
            'all_cwes': {'indices': [], 'labels': [], 'values': []},
            'severity_matrix': {},
            'cwe_30_day_counts': {},
            'total_cves_analyzed': 0,
            'years_analyzed': []
        }
    
    def _generate_note_text(self, year, month, day, severity_filter, load_historical, timeline_years):
        if year and month and day:
            return f"Cards & Pie Chart: {year}-{month:02d}-{day:02d}"
        elif year and month:
            return f"Cards & Pie Chart: {year}-{month:02d}"
        elif year:
            return f"Cards & Pie Chart: {year} data"
        elif severity_filter:
            return f"Filtered by: {severity_filter.lower()} severity"
        else:
            return f"Last 30 days of CVE data"

data_orchestrator = DataOrchestrator()
