import os
import json
from typing import Dict, List, Any
from datetime import datetime, timezone, timedelta
from services.analysis.trend_analyzer import get_cve_trends_last_30_days
from services.data.api_client import api_client
from services.data.data_source_config import data_source_config
from services.cache.cache_manager import cache_manager
import config

class DataOrchestrator:
    """Memory-optimized orchestrator - LITE MODE for 512MB RAM"""
    
    def __init__(self):
        data_source_config.log_data_source_status()
        self._last_refresh_time = None
        self._full_data_loaded = False  # Track if full data is loaded
        print("[Orchestrator] Initialized with LITE MODE for first load")
    
    def get_dashboard_data(self, year=None, month=None, day=None, severity_filter=None, 
                          timeline_years=1, load_historical=False, lite_mode=True):
        """Get dashboard data - LITE MODE for first load, FULL MODE after cache"""
        print(f"[Orchestrator] Loading dashboard (lite_mode={lite_mode}): year={year}, month={month}, severity={severity_filter}")
        
        try:
            # Check cache first
            cache_key = f"dashboard_{year}_{month}_{day}_{severity_filter}_{timeline_years}"
            cached_data = cache_manager.get(cache_key)
            if cached_data:
                print(f"[Orchestrator] ✓ Returning CACHED dashboard data")
                return cached_data
            
            print("[Orchestrator] Cache MISS - Loading data...")
            
            # 1. CVE Trends - LITE: Only 200 CVEs for first load
            print("[Orchestrator] Getting CVE trends")
            if lite_mode and not self._full_data_loaded:
                cve_trends = self._get_lite_cve_trends()
            else:
                cve_trends = self._get_cve_trends_cached()
            
            # 2. Timeline - LITE: Skip on first load
            print(f"[Orchestrator] Loading timeline")
            if lite_mode and not self._full_data_loaded:
                vulnerabilities_timeline = self._get_empty_timeline()
            else:
                vulnerabilities_timeline = self._get_timeline_cached(timeline_years)
            
            # 3. Filtered CVEs - LITE: Only 200 CVEs
            print("[Orchestrator] Getting filtered CVEs")
            if lite_mode and not self._full_data_loaded:
                filtered_cves = self._get_lite_filtered_cves()
            else:
                filtered_cves = self._get_filtered_cves_cached(year=year, month=month, day=day)
            
            if severity_filter:
                from utils.filters import FilterService
                filter_service = FilterService()
                filtered_cves = filter_service.filter_by_severity(filtered_cves, severity_filter)
            
            # 4. Calculate severity counts
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
            
            # 5. Vendor Risk - LITE: Skip on first load
            print("[Orchestrator] Getting vendor risk")
            if lite_mode and not self._full_data_loaded:
                vendor_risk, weighted_vendor_risk = self._get_empty_vendor_risk(), {'indices': [], 'labels': [], 'values': []}
            else:
                vendor_risk, weighted_vendor_risk = self._get_vendor_risk_cached()
            
            note_text = self._generate_note_text(year, month, day, severity_filter, load_historical, timeline_years)
            if lite_mode and not self._full_data_loaded:
                note_text += " (Loading full data in background...)"
            
            print(f"[Orchestrator] ✓ Data loaded:")
            print(f"  - CVEs: {len(filtered_cves)}")
            print(f"  - Trends: {len(cve_trends.get('labels', []))} days")
            print(f"  - Timeline: {len(vulnerabilities_timeline.get('labels', []))} months")
            
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
            
            # Cache the result
            cache_manager.set(cache_key, dashboard_data)
            
            return dashboard_data
            
        except Exception as e:
            print(f"[Orchestrator] Error: {e}")
            import traceback
            traceback.print_exc()
            raise e
    
    def _get_lite_cve_trends(self):
        """Get LITE CVE trends - only 200 CVEs"""
        print("[Orchestrator] Loading LITE CVE trends (200 CVEs only)")
        cached = cache_manager.get("cve_trends_lite")
        if cached:
            return cached
        
        # Fetch only 200 CVEs
        cves = api_client.get_cves_last_30_days(batch_size=200, offset=0)
        
        # Process into trends
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
        print("[Orchestrator] Fetching LITE filtered CVEs (200 only)")
        cached = cache_manager.get("filtered_cves_lite")
        if cached:
            return cached
        
        cves = api_client.get_cves_last_30_days(batch_size=200, offset=0)
        cache_manager.set("filtered_cves_lite", cves)
        return cves
    
    def _get_empty_timeline(self):
        """Return empty timeline for LITE mode"""
        return {
            'labels': [],
            'values': [],
            'total_cves': 0,
            'months_covered': 0,
            'raw_data': {}
        }
    
    def warm_cache_full(self):
        """Load FULL data into cache - call this manually before presentation!"""
        print("[Orchestrator] ===== WARMING CACHE WITH FULL DATA =====")
        
        try:
            # Mark as full load
            self._full_data_loaded = True
            
            # Load full data
            dashboard_data = self.get_dashboard_data(lite_mode=False)
            
            print("[Orchestrator] ===== CACHE WARMED SUCCESSFULLY =====")
            print(f"  - Total CVEs: {dashboard_data['total_cves']}")
            print(f"  - Timeline months: {len(dashboard_data['timeline_data_years']['labels'])}")
            print(f"  - Memory usage: ~{cache_manager.get_cache_stats()['total_size_mb']:.1f}MB")
            
            return {
                'success': True,
                'message': 'Cache warmed with full data',
                'stats': cache_manager.get_cache_stats()
            }
        except Exception as e:
            print(f"[Orchestrator] Error warming cache: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': str(e)
            }
    
    def _get_cve_trends_cached(self):
        """Get full CVE trends"""
        cached = cache_manager.get("cve_trends_30days")
        if cached:
            return cached
        
        trends = get_cve_trends_last_30_days()
        cache_manager.set("cve_trends_30days", trends)
        return trends
    
    def _get_timeline_cached(self, years=1):
        """Get timeline"""
        cache_key = f"timeline_{years}years"
        cached = cache_manager.get(cache_key)
        if cached:
            return cached
        
        try:
            from services.analysis.trend_analyzer import get_vulnerabilities_over_time_last_n_years
            timeline = get_vulnerabilities_over_time_last_n_years(years)
            cache_manager.set(cache_key, timeline)
            return timeline
        except Exception as e:
            print(f"[Orchestrator] Error getting timeline: {e}")
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
        """Public method"""
        return self._get_filtered_cves_cached(year=year, month=month, day=day)
    
    def _get_vendor_risk_cached(self):
        """Get vendor risk"""
        cached = cache_manager.get("vendor_risk")
        if cached:
            return cached
        
        try:
            from services.analysis.cwe import get_vendor_risk_analysis, get_weighted_cwe_analysis
            vendor_risk = get_vendor_risk_analysis()
            weighted_vendor_risk = get_weighted_cwe_analysis()
            
            result = (vendor_risk, weighted_vendor_risk)
            cache_manager.set("vendor_risk", result)
            return result
        except Exception as e:
            print(f"[Orchestrator] Error: {e}")
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
