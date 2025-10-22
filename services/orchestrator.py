import os
import json
from typing import Dict, List, Any
from datetime import datetime, timezone, timedelta
from services.analysis.trend_analyzer import get_cve_trends_last_30_days
from services.data.api_client import api_client
from services.data.data_source_config import data_source_config
import config

class DataOrchestrator:
    """Memory-optimized orchestrator - loads only what's needed"""
    
    def __init__(self):
        data_source_config.log_data_source_status()
        self._vendor_risk_cache = None
        self._vendor_risk_cache_time = None
        self._vendor_risk_loaded = False
    
    def get_dashboard_data(self, year=None, month=None, day=None, severity_filter=None, timeline_years=1, load_historical=False):
        """Get dashboard data - MEMORY OPTIMIZED"""
        
        print(f"[Orchestrator] Loading dashboard data with filters: year={year}, month={month}, day={day}, severity={severity_filter}, timeline_years={timeline_years}")
        
        try:
            # 1. CVE Trends (Last 30 days) - ALWAYS FROM API
            print("[Orchestrator] Getting CVE trends (last 30 days)")
            cve_trends = get_cve_trends_last_30_days()
            
            # 2. Vulnerabilities Over Time - LOAD FROM HISTORICAL FILES
            print(f"[Orchestrator] Loading timeline for {timeline_years} year(s)")
            vulnerabilities_timeline = self._get_timeline_historical(timeline_years)
            
            # 3. Filtered data for Cards and Pie Chart
            print("[Orchestrator] Getting filtered data for cards and pie chart")
            filtered_cves = self.get_filtered_cves(year=year, month=month, day=day)
            
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
            
            # 5. Vendor Risk Analysis - LAZY LOAD with 24h cache
            vendor_risk, weighted_vendor_risk = self._get_vendor_risk_cached()
            
            note_text = self._generate_note_text(year, month, day, severity_filter, load_historical, timeline_years)
            
            print(f"[Orchestrator] Data loaded successfully:")
            print(f" - Filtered CVEs (cards/pie): {len(filtered_cves)}")
            print(f" - CVE Trends data points: {len(cve_trends.get('labels', []))}")
            print(f" - Timeline data points: {len(vulnerabilities_timeline.get('labels', []))}")
            print(f" - Severity counts: C={severity_metrics['CRITICAL']}, H={severity_metrics['HIGH']}, M={severity_metrics['MEDIUM']}, L={severity_metrics['LOW']}")
            
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
            
            return dashboard_data
            
        except Exception as e:
            print(f"[Orchestrator] Error in get_dashboard_data: {e}")
            import traceback
            traceback.print_exc()
            raise e
    
    def _get_vendor_risk_cached(self):
        """Get vendor risk with 24h cache - SAVES TO DATABASE"""
        
        # Try to load from database first
        if not self._vendor_risk_loaded:
            from database import db_manager
            if db_manager.use_database:
                cached_data = db_manager.get_vendor_risk_cache()
                if cached_data:
                    cache_age = datetime.now(timezone.utc) - cached_data['updated_at'].replace(tzinfo=timezone.utc)
                    if cache_age.total_seconds() < 86400:  # 24 hours
                        print(f"[Orchestrator] Using database cached vendor risk (age: {int(cache_age.total_seconds()/3600)}h)")
                        self._vendor_risk_cache = (cached_data['vendor_risk'], cached_data['weighted_risk'])
                        self._vendor_risk_cache_time = cached_data['updated_at']
                        self._vendor_risk_loaded = True
                        return self._vendor_risk_cache
        
        # Check in-memory cache
        if self._vendor_risk_cache and self._vendor_risk_cache_time:
            cache_age = datetime.now(timezone.utc) - self._vendor_risk_cache_time.replace(tzinfo=timezone.utc)
            if cache_age.total_seconds() < 86400:
                print(f"[Orchestrator] Using in-memory vendor risk cache (age: {int(cache_age.total_seconds()/3600)}h)")
                return self._vendor_risk_cache
        
        # Calculate fresh
        print("[Orchestrator] Calculating fresh vendor risk analysis (last 2 years)...")
        try:
            from services.analysis.cwe import get_vendor_risk_analysis, get_weighted_cwe_analysis
            
            vendor_risk = get_vendor_risk_analysis()
            weighted_vendor_risk = get_weighted_cwe_analysis()
            
            self._vendor_risk_cache = (vendor_risk, weighted_vendor_risk)
            self._vendor_risk_cache_time = datetime.now(timezone.utc)
            self._vendor_risk_loaded = True
            
            # Save to database
            from database import db_manager
            if db_manager.use_database:
                db_manager.save_vendor_risk_cache(vendor_risk, weighted_vendor_risk)
                print("[Orchestrator] Vendor risk saved to database cache")
            
            return self._vendor_risk_cache
            
        except Exception as e:
            print(f"[Orchestrator] Error calculating vendor risk: {e}")
            import traceback
            traceback.print_exc()
            empty_risk = self._get_empty_vendor_risk()
            return (empty_risk, {'indices': [], 'labels': [], 'values': []})
    
    def _get_timeline_historical(self, years=1) -> Dict[str, Any]:
        """Load timeline data from HISTORICAL FILES"""
        try:
            from services.analysis.trend_analyzer import get_vulnerabilities_over_time_last_n_years
            return get_vulnerabilities_over_time_last_n_years(years)
        except Exception as e:
            print(f"[Orchestrator] Error getting timeline: {e}")
            import traceback
            traceback.print_exc()
            return {'labels': [], 'values': [], 'total_cves': 0, 'months_covered': 0, 'raw_data': {}}
    
    def get_filtered_cves(self, year=None, month=None, day=None) -> List[Dict[str, Any]]:
        """Get filtered CVEs"""
        print(f"[Orchestrator] Getting filtered CVEs: year={year}, month={month}, day={day}")
        
        if not year:
            print(f"[Orchestrator] Using API data (last 30 days)")
            cves = api_client.get_cves_last_30_days()
            print(f"[Orchestrator] API returned {len(cves)} CVEs")
            return cves
        else:
            print(f"[Orchestrator] User requested {year}-{month or 'all'}, fetching from API")
            return api_client.get_cves_for_date_range(year=year, month=month, day=day)
    
    def get_cve_detail(self, cve_id: str) -> Dict[str, Any]:
        return api_client.get_cve_detail(cve_id)
    
    def clear_cache(self):
        api_client.clear_cache()
        self._vendor_risk_cache = None
        self._vendor_risk_cache_time = None
        self._vendor_risk_loaded = False
    
    def get_data_source_status(self) -> Dict[str, Any]:
        return data_source_config.get_status()
    
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