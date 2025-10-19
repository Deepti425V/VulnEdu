# Operating system interface for file and cache operations
import os
# JSON processing for cache file operations (imported but not directly used)
import json
# Type annotations for complex data structures and function returns
from typing import Dict, List, Any
# Date and time operations for temporal filtering and processing
from datetime import datetime, timezone, timedelta
# Trend analysis service for temporal vulnerability patterns
from services.analysis.trend_analyzer import get_cve_trends_last_30_days
# Severity analysis service for vulnerability classification metrics
from services.analysis.severity_analyzer import get_severity_card_counts, get_severity_percentages
# Updated import to use the new modular structure for CWE analysis
from services.analysis.cwe_processor import get_vendor_risk_analysis, get_weighted_cwe_analysis
# Real-time API client for current vulnerability data
from services.data.api_client import api_client
# Cache management service for performance optimization
from services.cache.cache_manager import cache_manager
# Dynamic data source configuration for intelligent routing
from services.data.data_source_config import data_source_config
# Application configuration for system settings
import config

class DataOrchestrator:
    """Clean orchestrator using separate visualization modules with caching and dynamic data sources"""
    
    def __init__(self):
        # Log data source configuration on startup for operational visibility
        data_source_config.log_data_source_status()
    
    def get_dashboard_data(self, year=None, month=None, day=None, severity_filter=None, timeline_years=1):
        """Get all dashboard data with separate data sources for different components"""
        print(f"[Orchestrator] Loading dashboard data with filters: year={year}, month={month}, day={day}, severity={severity_filter}, timeline_years={timeline_years}")
        
        try:
            # 1. CVE Trends (Last 30 days) – ALWAYS unfiltered, last 30 days only
            print("[Orchestrator] Getting CVE trends (last 30 days) - unfiltered")
            cve_trends = self._get_always_30_day_trends()
            
            # 2. Vulnerabilities Over Time – Dynamic years based on user selection
            print(f"[Orchestrator] Getting vulnerabilities over time (last {timeline_years} years) - unfiltered")
            vulnerabilities_timeline = self._get_timeline(timeline_years)
            
            # 3. Filtered data for Cards and Pie Chart ONLY
            print("[Orchestrator] Getting filtered data for cards and pie chart")
            filtered_cves = self.get_filtered_cves(year=year, month=month, day=day)
            
            # Apply severity filter if specified as additional layer
            if severity_filter:
                from utils.filters import FilterService
                filter_service = FilterService()
                filtered_cves = filter_service.filter_by_severity(filtered_cves, severity_filter)
            
            # 4. Calculate severity counts from filtered data (for cards and pie chart)
            from collections import Counter
            severity_counts = Counter()
            for cve in filtered_cves:
                severity = cve.get('Severity', 'UNKNOWN').upper()
                if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    severity_counts[severity] += 1
                else:
                    severity_counts['UNKNOWN'] += 1
            
            # Create comprehensive severity data structure
            severity_metrics = {
                'CRITICAL': severity_counts.get('CRITICAL', 0),
                'HIGH': severity_counts.get('HIGH', 0),
                'MEDIUM': severity_counts.get('MEDIUM', 0),
                'LOW': severity_counts.get('LOW', 0),
                'UNKNOWN': severity_counts.get('UNKNOWN', 0),
                'total_cves': len(filtered_cves)
            }
            
            # Calculate percentages for pie chart visualization
            total = len(filtered_cves)
            if total > 0:
                severity_percentages = {}
                for key in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
                    percentage = round((severity_counts.get(key, 0) * 100 / total))
                    severity_percentages[key] = f"{percentage}%"
            else:
                severity_percentages = {k: "0%" for k in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']}
            
            # 5. Vendor Risk Analysis - use full historical data (unchanged)
            try:
                vendor_risk = get_vendor_risk_analysis()
                weighted_vendor_risk = get_weighted_cwe_analysis()
            except Exception as e:
                print(f"[Orchestrator] Error loading vendor risk analysis: {e}")
                # Provide empty data structure to maintain dashboard functionality
                vendor_risk = {
                    'top_5_cwes': {'indices': [], 'labels': [], 'values': []},
                    'top_10_cwes': {'indices': [], 'labels': [], 'values': []},
                    'all_cwes': {'indices': [], 'labels': [], 'values': []},
                    'severity_matrix': {},
                    'cwe_30_day_counts': {},
                    'total_cves_analyzed': 0,
                    'years_analyzed': []
                }
                weighted_vendor_risk = {'indices': [], 'labels': [], 'values': []}
            
            # Generate proper note text with data source info for transparency
            cutoff_info, explanation = data_source_config.get_data_source_cutoff()
            if year and month and day:
                note_text = f"Cards & Pie Chart: {year}-{month:02d}-{day:02d} | Trends: Last 30 days | Timeline: Last {timeline_years} year(s)"
            elif year and month:
                note_text = f"Cards & Pie Chart: {year}-{month:02d} | Trends: Last 30 days | Timeline: Last {timeline_years} year(s)"
            elif year:
                note_text = f"Cards & Pie Chart: {year} data | Trends: Last 30 days | Timeline: Last {timeline_years} year(s)"
            elif severity_filter:
                note_text = f"Cards & Pie Chart: {severity_filter.lower()} severity | Trends: Last 30 days | Timeline: Last {timeline_years} year(s)"
            else:
                note_text = f"Cards & Pie Chart: Last 30 days | Trends: Last 30 days | Timeline: Last {timeline_years} year(s)"
            
            # Add data source information for operational transparency
            note_text += f" | {explanation}"
            
            # Log comprehensive operation summary
            print(f"[Orchestrator] Data loaded successfully:")
            print(f"  Filtered CVEs (cards/pie): {len(filtered_cves)}")
            print(f"  CVE Trends data points: {len(cve_trends.get('labels', []))}")
            print(f"  Timeline data points: {len(vulnerabilities_timeline.get('labels', []))}")
            print(f"  Severity counts: C={severity_metrics['CRITICAL']}, H={severity_metrics['HIGH']}, M={severity_metrics['MEDIUM']}, L={severity_metrics['LOW']}")
            
            # Construct comprehensive dashboard data structure
            dashboard_data = {
                # Current metrics from filtered data (for cards and pie chart)
                'metrics': severity_metrics,
                'total_cves': len(filtered_cves),
                'severity_percentage': severity_percentages,
                
                # Chart data – SEPARATED by purpose for clarity
                'timeline_data_days': cve_trends,  # Always last 30 days
                'timeline_data_years': vulnerabilities_timeline,  # Dynamic years
                'cwe_radar': vendor_risk.get('top_10_cwes', {'indices': [], 'labels': [], 'values': []}),
                'cwe_radar_all': vendor_risk,
                'cwe_radar_weighted': weighted_vendor_risk,
                'cwe_radar_descriptions': self._get_cwe_descriptions(),
                
                # Raw data for other pages
                'latest_cves': filtered_cves,
                'available_years': list(range(datetime.now().year, 2009, -1)),
                'available_months': list(range(1, 13)),
                
                # Status info for transparency
                'note_text': note_text
            }
            
            print(f"[Orchestrator] Dashboard data structure created successfully")
            return dashboard_data
            
        except Exception as e:
            print(f"[Orchestrator] Error in get_dashboard_data: {e}")
            import traceback
            traceback.print_exc()
            raise e
    
    def _get_always_30_day_trends(self) -> Dict[str, Any]:
        """Always get last 30 days trends from API – unfiltered"""
        try:
            return get_cve_trends_last_30_days()
        except Exception as e:
            print(f"[Orchestrator] Error getting 30-day trends: {e}")
            # Return empty structure to maintain dashboard functionality
            return {
                'labels': [],
                'values': [],
                'total_cves': 0,
                'date_range': {'start': '', 'end': ''}
            }
    
    def _get_timeline(self, years=1) -> Dict[str, Any]:
        """Get timeline for specified number of years from historical data - unfiltered"""
        try:
            from services.analysis.trend_analyzer import get_vulnerabilities_over_time_last_n_years
            return get_vulnerabilities_over_time_last_n_years(years)
        except Exception as e:
            print(f"[Orchestrator] Error getting timeline: {e}")
            # Return empty structure to maintain dashboard functionality
            return {
                'labels': [],
                'values': [],
                'total_cves': 0,
                'months_covered': 0,
                'raw_data': {}
            }
    
    def get_filtered_cves(self, year=None, month=None, day=None) -> List[Dict[str, Any]]:
        """Get filtered CVE data using dynamic data source selection – ENHANCED DEBUG"""
        print(f"[Orchestrator] Getting filtered CVEs: year={year}, month={month}, day={day}")
        
        cutoff_info, explanation = data_source_config.get_data_source_cutoff()
        
        if not year:
            # No year filter - use API data for current/recent months
            print(f"[Orchestrator] Using API data for recent data")
            cves = api_client.get_cves_last_30_days()
            print(f"[Orchestrator] API returned {len(cves)} CVEs")
            return cves
        
        # Determine data source based on dynamic cutoff
        if data_source_config.should_use_historical(year, month):
            # Use historical data
            print(f"[Orchestrator] Using historical data for {year}-{month or 'all'}")
            try:
                from services.analysis.trend_analyzer import get_filtered_historical_cves
                cves = get_filtered_historical_cves(year, month, day)
                
                # DEBUG: Check what we actually got
                print(f"[Orchestrator] Historical data returned {len(cves)} CVEs")
                if cves:
                    # Show sample dates to verify filtering
                    sample_dates = []
                    for i, cve in enumerate(cves[:5]):  # Check first 5
                        pub_date = cve.get('Published', 'No date')
                        sample_dates.append(f"{cve.get('ID', 'Unknown')}: {pub_date}")
                    print(f"[Orchestrator] Sample CVE dates: {sample_dates}")
                
                return cves
            except Exception as e:
                print(f"[Orchestrator] Error loading historical data: {e}")
                import traceback
                traceback.print_exc()
                return []
        else:
            # Use API data
            print(f"[Orchestrator] Using API data for {year}-{month or 'current'}")
            cves = api_client.get_cves_last_30_days()
            
            # Apply date filters for API data
            if year or month or day:
                filtered_cves = []
                for cve in cves:
                    pub_date = cve.get('Published', '')
                    if pub_date:
                        try:
                            # Handle different date formats from API
                            if 'T' in pub_date:
                                dt = datetime.fromisoformat(pub_date.replace('Z', '+00:00'))
                            else:
                                dt = datetime.strptime(pub_date[:10], '%Y-%m-%d')
                            
                            # Check filters against parsed date
                            if year and dt.year != year:
                                continue
                            if month and dt.month != month:
                                continue
                            if day and dt.day != day:
                                continue
                            
                            filtered_cves.append(cve)
                        except:
                            continue
                cves = filtered_cves
            
            print(f"[Orchestrator] API data filtered to {len(cves)} CVEs")
            return cves
    
    def get_cve_detail(self, cve_id: str) -> Dict[str, Any]:
        """Get detailed CVE information using dynamic data sources"""
        if not cve_id or not cve_id.startswith("CVE"):
            return self._get_not_found_cve(cve_id)
        
        # Search in recent API data first for current vulnerabilities
        try:
            recent_cves = api_client.get_cves_last_30_days()
            for cve in recent_cves:
                if cve.get('ID') == cve_id:
                    print(f"[Orchestrator] Found CVE {cve_id} in API data")
                    return cve
        except:
            pass
        
        # Search in historical data systematically
        try:
            from services.data.data_processor import historical_loader
            available_files = data_source_config.get_available_historical_files()
            
            # Search through available historical files
            for year, filepath in available_files.items():
                year_data = historical_loader.get_year_data(year)
                for cve in year_data:
                    if cve.get('ID') == cve_id:
                        print(f"[Orchestrator] Found CVE {cve_id} in historical data ({year})")
                        return cve
        except Exception as e:
            print(f"[Orchestrator] Error searching historical data: {e}")
        
        print(f"[Orchestrator] CVE {cve_id} not found in any data source")
        return self._get_not_found_cve(cve_id)
    
    def _get_cwe_descriptions(self) -> Dict[str, str]:
        """Get CWE descriptions for tooltips and user education"""
        return {
            "CWE-79": "Cross-Site Scripting (XSS) – allows script/code injection into web pages viewed by others.",
            "CWE-89": "SQL Injection – improper input handling lets attackers run malicious database queries.",
            "CWE-20": "Improper Input Validation – fails to properly check user input data.",
            "CWE-22": "Path Traversal – file access outside allowed directories.",
            "CWE-119": "Buffer Overflow – code writes past memory buffer limits.",
            "CWE-78": "OS Command Injection – attacker can execute operating system commands.",
            "CWE-287": "Improper Authentication.",
            "CWE-200": "Information Exposure.",
            "CWE-352": "Cross-Site Request Forgery.",
            "CWE-862": "Missing Authorization.",
            "CWE-74": "Improper Neutralization of Special Elements."
        }
    
    def _get_not_found_cve(self, cve_id: str) -> Dict[str, Any]:
        """Return placeholder for CVEs not found in available data"""
        return {
            'ID': cve_id,
            'Description': f'CVE {cve_id} not found in current dataset. This may be an older CVE or not yet available in our feed.',
            'Severity': 'UNKNOWN',
            'CWE': None,
            'Published': '',
            'lastModified': '',
            'References': [f'https://nvd.nist.gov/vuln/detail/{cve_id}'],  # Provide external reference
            'Products': [],
            'CVSS_Score': None,
            'metrics': {}
        }
    
    def clear_cache(self):
        """Clear all caches for complete data refresh"""
        cache_manager.clear_cache()
        # Also clear the data source config cache
        data_source_config._cutoff_cache = None
        data_source_config._cache_date = None
        
        # Remove specific cache files
        cache_file = os.path.join(config.CACHE_DIR, "recent_api_cache.json")
        if os.path.exists(cache_file):
            os.remove(cache_file)
        
        print("[Orchestrator] All caches cleared, including data source config cache")
    
    def get_data_source_status(self) -> Dict[str, Any]:
        """Get current data source status for debugging and monitoring"""
        cutoff_info, explanation = data_source_config.get_data_source_cutoff()
        available_files = data_source_config.get_available_historical_files()
        
        return {
            'cutoff_info': cutoff_info,
            'explanation': explanation,
            'available_historical_files': len(available_files),
            'historical_years': list(available_files.keys()),
            'current_date': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        }

# Global orchestrator instance for application-wide coordination
data_orchestrator = DataOrchestrator()