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
    """Memory-optimized orchestrator with GZIP CACHE and AUTO-REFRESH"""
    
    def __init__(self):
        data_source_config.log_data_source_status()
        self._last_refresh_time = None
        print("[Orchestrator] Initialized with LAZY LOADING and GZIP CACHE")
    
    def get_dashboard_data(self, year=None, month=None, day=None, severity_filter=None, 
                          timeline_years=1, load_historical=False):
        """Get dashboard data - LAZY LOAD with GZIP CACHE"""
        print(f"[Orchestrator] Loading dashboard data with filters: year={year}, month={month}, day={day}, severity={severity_filter}, timeline_years={timeline_years}")
        
        try:
            # Check if auto-refresh is needed
            self._check_auto_refresh()
            
            # Try to get from cache first
            cache_key = f"dashboard_{year}_{month}_{day}_{severity_filter}_{timeline_years}"
            cached_data = cache_manager.get(cache_key)
            if cached_data:
                print(f"[Orchestrator] ✓ Returning CACHED dashboard data")
                return cached_data
            
            print("[Orchestrator] Cache MISS - Loading fresh data...")
            
            # 1. CVE Trends (Last 30 days) - FROM CACHE OR API
            print("[Orchestrator] Getting CVE trends (last 30 days)")
            cve_trends = self._get_cve_trends_cached()
            
            # 2. Vulnerabilities Over Time - FROM CACHE OR HISTORICAL
            print(f"[Orchestrator] Loading timeline for {timeline_years} year(s)")
            vulnerabilities_timeline = self._get_timeline_cached(timeline_years)
            
            # 3. Filtered data for Cards and Pie Chart - FROM CACHE OR API
            print("[Orchestrator] Getting filtered data for cards and pie chart")
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
            
            # 5. Vendor Risk Analysis - FROM CACHE (WITH DISK PERSISTENCE)
            print("[Orchestrator] Getting vendor risk analysis...")
            vendor_risk, weighted_vendor_risk = self._get_vendor_risk_cached()
            
            note_text = self._generate_note_text(year, month, day, severity_filter, load_historical, timeline_years)
            
            print(f"[Orchestrator] ✓ Data loaded successfully:")
            print(f"  - Filtered CVEs (cards/pie): {len(filtered_cves)}")
            print(f"  - CVE Trends data points: {len(cve_trends.get('labels', []))}")
            print(f"  - Timeline data points: {len(vulnerabilities_timeline.get('labels', []))}")
            print(f"  - Severity counts: C={severity_metrics['CRITICAL']}, H={severity_metrics['HIGH']}, M={severity_metrics['MEDIUM']}, L={severity_metrics['LOW']}")
            
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
                'historical_loaded': True
            }
            
            # Cache the result
            cache_manager.set(cache_key, dashboard_data)
            print(f"[Orchestrator] ✓ Dashboard data CACHED for 1 hour")
            
            return dashboard_data
            
        except Exception as e:
            print(f"[Orchestrator] Error in get_dashboard_data: {e}")
            import traceback
            traceback.print_exc()
            raise e
    
    def _check_auto_refresh(self):
        """Check if auto-refresh is needed (every 1 hour)"""
        if self._last_refresh_time is None:
            self._last_refresh_time = datetime.now(timezone.utc)
            return
        
        time_since_refresh = datetime.now(timezone.utc) - self._last_refresh_time
        refresh_interval = timedelta(minutes=config.AUTO_REFRESH_INTERVAL_MINUTES)
        
        if time_since_refresh >= refresh_interval:
            print(f"[Orchestrator] Auto-refresh triggered (last refresh: {int(time_since_refresh.total_seconds()/60)} minutes ago)")
            self.clear_cache()
            self._last_refresh_time = datetime.now(timezone.utc)
    
    def _get_cve_trends_cached(self):
        """Get CVE trends with cache"""
        cached = cache_manager.get("cve_trends_30days")
        if cached:
            return cached
        
        print("[Orchestrator] Loading CVE trends (not cached)")
        trends = get_cve_trends_last_30_days()
        cache_manager.set("cve_trends_30days", trends)
        return trends
    
    def _get_timeline_cached(self, years=1):
        """Get timeline with cache"""
        cache_key = f"timeline_{years}years"
        cached = cache_manager.get(cache_key)
        if cached:
            return cached
        
        print(f"[Orchestrator] Loading timeline for {years} year(s) (not cached)")
        try:
            from services.analysis.trend_analyzer import get_vulnerabilities_over_time_last_n_years
            timeline = get_vulnerabilities_over_time_last_n_years(years)
            cache_manager.set(cache_key, timeline)
            return timeline
        except Exception as e:
            print(f"[Orchestrator] Error getting timeline: {e}")
            return {'labels': [], 'values': [], 'total_cves': 0, 'months_covered': 0, 'raw_data': {}}
    
    def _get_filtered_cves_cached(self, year=None, month=None, day=None) -> List[Dict[str, Any]]:
        """Get filtered CVEs with cache - FETCH ALL IN BATCHES OF 400"""
        cache_key = f"filtered_cves_{year}_{month}_{day}"
        cached = cache_manager.get(cache_key)
        if cached:
            return cached
        
        print(f"[Orchestrator] Fetching filtered CVEs (not cached): year={year}, month={month}, day={day}")
        
        if not year:
            print(f"[Orchestrator] Fetching ALL last 30 days data (batches of {config.API_BATCH_SIZE})")
            all_cves = []
            offset = 0
            batch_size = config.API_BATCH_SIZE
            max_iterations = 15  # 15 * 400 = 6000 max
            iteration = 0
            
            while iteration < max_iterations:
                iteration += 1
                print(f"[Orchestrator] → Batch {iteration}/{max_iterations} (offset={offset})")
                
                batch = api_client.get_cves_last_30_days(batch_size=batch_size, offset=offset)
                
                if not batch:
                    print(f"[Orchestrator] No more data at offset {offset}")
                    break
                
                all_cves.extend(batch)
                print(f"[Orchestrator] Total loaded: {len(all_cves)} CVEs")
                
                # If we got less than batch_size, we've reached the end
                if len(batch) < batch_size:
                    print(f"[Orchestrator] Got {len(batch)} < {batch_size}, end of data")
                    break
                
                offset += batch_size
            
            print(f"[Orchestrator] ✓ Fetched {len(all_cves)} CVEs total in {iteration} batches")
            cache_manager.set(cache_key, all_cves)
            return all_cves
        else:
            print(f"[Orchestrator] Fetching {year}-{month or 'all'} from API")
            cves = api_client.get_cves_for_date_range(year=year, month=month, day=day, batch_size=config.API_BATCH_SIZE)
            cache_manager.set(cache_key, cves)
            return cves
    
    def get_filtered_cves(self, year=None, month=None, day=None) -> List[Dict[str, Any]]:
        """Get filtered CVEs - PUBLIC METHOD for routes"""
        return self._get_filtered_cves_cached(year=year, month=month, day=day)
    
    def _get_vendor_risk_cached(self):
        """Get vendor risk with cache (WITH DISK PERSISTENCE)"""
        cached = cache_manager.get("vendor_risk")
        if cached:
            print("[Orchestrator] ✓ Using CACHED vendor risk analysis")
            return cached
        
        print("[Orchestrator] Calculating vendor risk analysis (not cached)...")
        try:
            from services.analysis.cwe import get_vendor_risk_analysis, get_weighted_cwe_analysis
            vendor_risk = get_vendor_risk_analysis()
            weighted_vendor_risk = get_weighted_cwe_analysis()
            
            result = (vendor_risk, weighted_vendor_risk)
            cache_manager.set("vendor_risk", result)
            print("[Orchestrator] ✓ Vendor risk analysis CACHED (saved to disk)")
            return result
            
        except Exception as e:
            print(f"[Orchestrator] Error calculating vendor risk: {e}")
            empty_risk = self._get_empty_vendor_risk()
            return (empty_risk, {'indices': [], 'labels': [], 'values': []})
    
    def get_cve_detail(self, cve_id: str) -> Dict[str, Any]:
        return api_client.get_cve_detail(cve_id)
    
    def clear_cache(self):
        """Clear all caches"""
        api_client.clear_cache()
        cache_manager.clear_cache()
        print("[Orchestrator] All caches cleared")
    
    def get_data_source_status(self) -> Dict[str, Any]:
        return data_source_config.get_status()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
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
            note_text = f"Cards & Pie Chart: {year}-{month:02d}-{day:02d} | Trends: Last 30 days"
        elif year and month:
            note_text = f"Cards & Pie Chart: {year}-{month:02d} | Trends: Last 30 days"
        elif year:
            note_text = f"Cards & Pie Chart: {year} data | Trends: Last 30 days"
        elif severity_filter:
            note_text = f"Cards & Pie Chart: {severity_filter.lower()} severity | Trends: Last 30 days"
        else:
            note_text = f"Showing last 30 days of CVE data"
        
        return note_text

data_orchestrator = DataOrchestrator()
