from flask import Flask, render_template, request, url_for, redirect, jsonify
from services.fetch_CVE import get_all_cves, reset_circuit_breaker
from services.nvd_api import get_cve_detail
from services.cwe_data import get_cwe_dict, get_single_cwe, warm_cwe_cache
from services.cwe_map import CWE_TITLES, cwe_title
from collections import Counter, defaultdict
import math
import random
from datetime import datetime, timedelta, timezone
from calendar import monthrange
import os
from threading import Thread, Lock
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
import functools

app = Flask(__name__)

# Reset circuit breaker on startup
try:
    reset_circuit_breaker()
    print("[Startup] Circuit breaker reset")
except:
    print("[Startup] Could not reset circuit breaker")

# Enhanced global cache - REAL DATA ONLY
class CircuitBreaker:
    def __init__(self, failure_threshold=3, timeout=300):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'

    def call(self, func, *args, **kwargs):
        if self.state == 'OPEN':
            if time.time() - self.last_failure_time > self.timeout:
                self.state = 'HALF_OPEN'
            else:
                raise Exception("Circuit breaker is OPEN - API calls temporarily disabled")

        try:
            result = func(*args, **kwargs)
            if self.state == 'HALF_OPEN':
                self.state = 'CLOSED'
                self.failure_count = 0
            return result
        except Exception as e:
            self.failure_count += 1
            if self.failure_count >= self.failure_threshold:
                self.state = 'OPEN'
                self.last_failure_time = time.time()
            raise e

# Global cache - REAL DATA ONLY
timeline_cache = {
    'data': None,
    'last_updated': None,
    'lock': Lock(),
    'circuit_breaker': CircuitBreaker()
}

TIMELINE_CACHE_HOURS = 3  # Reduced cache time for more frequent real data updates

# Thread pool for background tasks
executor = ThreadPoolExecutor(max_workers=2)

_warmed_up = False

def cache_with_timeout(timeout_seconds=1800):  # 30 minutes
    """Decorator for caching function results with timeout"""
    def decorator(func):
        cache = {}
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            key = str(args) + str(kwargs)
            now = time.time()
            if key in cache:
                data, timestamp = cache[key]
                if now - timestamp < timeout_seconds:
                    return data
            result = func(*args, **kwargs)
            cache[key] = (result, now)
            return result
        return wrapper
    return decorator

def get_cached_timeline_data():
    """Get timeline data - REAL DATA ONLY"""
    global timeline_cache
    
    with timeline_cache['lock']:
        now = datetime.now(timezone.utc)
        
        # Check if we have valid cached data
        if (timeline_cache['data'] is not None and 
            timeline_cache['last_updated'] is not None and
            (now - timeline_cache['last_updated']).total_seconds() < TIMELINE_CACHE_HOURS * 3600):
            print("[Timeline] Using cached timeline data")
            return timeline_cache['data']
        
        # Generate new timeline data from REAL CVEs only
        try:
            print("[Timeline] Generating fresh timeline data from real CVEs...")
            timeline_data = timeline_cache['circuit_breaker'].call(generate_timeline_data)
            timeline_cache['data'] = timeline_data
            timeline_cache['last_updated'] = now
            return timeline_data
        except Exception as e:
            print(f"[Timeline] Failed to generate timeline data: {e}")
            # Return empty data rather than fake data
            now = datetime.now(timezone.utc)
            months = []
            base_month = now.replace(day=1)
            
            for i in reversed(range(36)):
                dt = (base_month - timedelta(days=31 * i)).replace(day=1)
                months.append((dt.year, dt.month))
            
            month_labels = [f"{y}-{m:02d}" for y, m in months]
            
            return {
                'labels': month_labels,
                'values': [0] * len(month_labels)  # Return zeros instead of fake data
            }

def generate_timeline_data():
    """Generate timeline data from REAL CVEs only"""
    try:
        print("[Timeline] Fetching real CVEs for timeline generation...")
        # Fetch more days to get better historical coverage
        recent_cves = get_all_cves(force_refresh=False, timeout=30, days=90)
        
        if not recent_cves:
            print("[Timeline] No real CVEs available for timeline")
            raise Exception("No real CVE data available")
        
        print(f"[Timeline] Processing {len(recent_cves)} real CVEs for timeline")
        
        now = datetime.now(timezone.utc)
        months = []
        base_month = now.replace(day=1)
        
        # Generate 36 months of labels
        for i in reversed(range(36)):
            dt = (base_month - timedelta(days=31 * i)).replace(day=1)
            months.append((dt.year, dt.month))
        
        month_labels = [f"{y}-{m:02d}" for y, m in months]
        month_counts = {k: 0 for k in month_labels}
        
        # Count REAL CVEs by month
        for cve in recent_cves:
            published_str = cve.get('Published', '')
            if published_str and len(published_str) >= 7:
                month_key = published_str[:7]  # YYYY-MM format
                if month_key in month_counts:
                    month_counts[month_key] += 1
        
        # Only use months that have real data
        result_data = {
            'labels': list(month_counts.keys()),
            'values': list(month_counts.values())
        }
        
        total_cves = sum(result_data['values'])
        print(f"[Timeline] Generated timeline with {total_cves} total real CVEs across {len([v for v in result_data['values'] if v > 0])} months with data")
        
        return result_data
        
    except Exception as e:
        print(f"[Timeline] Error generating timeline data: {e}")
        raise e

def refresh_timeline_cache_background():
    """Background refresh that doesn't block main thread"""
    def refresh_task():
        try:
            get_cached_timeline_data()
        except Exception as e:
            print(f"Background timeline refresh failed: {e}")
    
    executor.submit(refresh_task)

def warm_dashboard_cache_if_needed():
    """Warm cache without blocking if it fails"""
    global _warmed_up
    if not _warmed_up:
        _warmed_up = True
        def _warm():
            try:
                executor.submit(lambda: get_all_cves(days=30, force_refresh=False, timeout=20))
                executor.submit(refresh_timeline_cache_background)
                executor.submit(warm_cwe_cache)
            except Exception as e:
                print(f"Cache warming failed: {e}")
        
        Thread(target=_warm, daemon=True).start()

def calculate_severity_metrics(cves):
    """Calculate severity metrics with error handling"""
    counts = Counter()
    for cve in cves:
        sev = cve.get('Severity', '').upper()
        if sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            counts[sev] += 1
    
    return {level: counts.get(level, 0) for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']}

def parse_published_date(cve):
    """Parse published date with error handling"""
    published_str = cve.get('Published')
    if not published_str:
        return None
    
    try:
        return datetime.fromisoformat(published_str.replace('Z', '+00:00'))
    except Exception:
        try:
            return datetime.strptime(published_str[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except Exception:
            return None

def get_all_years():
    """Get available years for filtering"""
    current_year = datetime.now(timezone.utc).year
    return list(range(current_year, 1998, -1))

def get_cwe_severity_chart_data(cves, selected_cwe_list):
    """Generate CWE severity chart data"""
    cwe_severity = defaultdict(lambda: defaultdict(int))
    
    for cve in cves:
        cwe = cve.get('CWE')
        if cwe in selected_cwe_list:
            severity = cve.get('Severity', 'UNKNOWN').upper()
            if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                cwe_severity[cwe][severity] += 1
    
    data = {
        'labels': [cwe_title(cwe) for cwe in selected_cwe_list],
        'indices': selected_cwe_list,
        'data': {
            'CRITICAL': [cwe_severity[cwe].get('CRITICAL', 0) for cwe in selected_cwe_list],
            'HIGH': [cwe_severity[cwe].get('HIGH', 0) for cwe in selected_cwe_list],
            'MEDIUM': [cwe_severity[cwe].get('MEDIUM', 0) for cwe in selected_cwe_list],
            'LOW': [cwe_severity[cwe].get('LOW', 0) for cwe in selected_cwe_list],
        }
    }
    
    return data

def get_cwe_radar_data_full(cves):
    """Generate CWE radar chart data"""
    cwe_counts = defaultdict(int)
    
    for cve in cves:
        cwe = cve.get('CWE')
        if cwe:
            cwe_counts[cwe] += 1
    
    sorted_cwes = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)
    
    codes = [code for code, _ in sorted_cwes]
    names = [CWE_TITLES.get(code, code) for code, _ in sorted_cwes]
    values = [count for _, count in sorted_cwes]
    
    top5_codes = codes[:5]
    top5_names = names[:5]
    top5_values = values[:5]
    
    top10_codes = codes[:10]
    top10_names = names[:10]
    top10_values = values[:10]
    
    return {
        'all': {'indices': codes, 'labels': names, 'values': values},
        'top5': {'indices': top5_codes, 'labels': top5_names, 'values': top5_values},
        'top10': {'indices': top10_codes, 'labels': top10_names, 'values': top10_values},
    }

def get_cwe_radar_weighted(cves):
    """Generate weighted CWE radar data"""
    cwe_severity = defaultdict(lambda: defaultdict(int))
    
    for cve in cves:
        cwe = cve.get('CWE')
        if cwe:
            severity = cve.get('Severity', 'UNKNOWN').upper()
            if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                weight = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}[severity]
                cwe_severity[cwe]['W'] = cwe_severity[cwe].get('W', 0) + weight
    
    sorted_cwes = sorted(cwe_severity.items(), key=lambda x: x[1].get('W', 0), reverse=True)
    
    codes = [code for code, _ in sorted_cwes]
    names = [CWE_TITLES.get(code, code) for code, _ in sorted_cwes]
    values = [obj.get('W', 0) for _, obj in sorted_cwes]
    
    return {'indices': codes, 'labels': names, 'values': values}

def get_cwe_radar_descriptions():
    """Get CWE descriptions for radar chart"""
    return {
        "CWE-79": "Cross-Site Scripting (XSS) – allows script/code injection into web pages viewed by others.",
        "CWE-89": "SQL Injection – improper input handling lets attackers run malicious database queries.",
        "CWE-20": "Improper Input Validation – fails to properly check user input data.",
        "CWE-22": "Path Traversal – file access outside allowed directories.",
        "CWE-119": "Buffer Overflow – code writes past memory buffer limits.",
        "CWE-78": "OS Command Injection – attacker can execute operating system commands.",
        "CWE-287": "Improper Authentication.",
        "CWE-200": "Information Exposure.",
    }

@cache_with_timeout(600)  # 10 minute cache
def get_cve_trends_30_days():
    """Get CVE trends for last 30 days with REAL data only"""
    try:
        today = datetime.now(timezone.utc).date()
        start_date = today - timedelta(days=29)  # 29 days ago + today = 30 days total
        
        print(f"[CVE Trends] Getting REAL data from {start_date} to {today}")
        
        # Get real CVE data
        cves = get_all_cves(days=30, force_refresh=False, timeout=25)
        
        if not cves:
            print("[CVE Trends] No real CVE data available")
            # Return empty data structure instead of fake data
            dates = [start_date + timedelta(days=i) for i in range(30)]
            return {
                'labels': [d.strftime('%Y-%m-%d') for d in dates],
                'values': [0] * 30
            }

        # Create date buckets for all 30 days
        date_counts = {}
        for i in range(30):
            date_key = start_date + timedelta(days=i)
            date_counts[date_key] = 0
        
        # Count CVEs by their published date
        for cve in cves:
            dt = parse_published_date(cve)
            if dt:
                dt_date = dt.date()
                # Only count CVEs that fall within our 30-day window
                if start_date <= dt_date <= today:
                    date_counts[dt_date] += 1
        
        # Sort dates and return the data
        sorted_dates = sorted(date_counts.keys())
        
        total_cves = sum(date_counts.values())
        print(f"[CVE Trends] Processed {total_cves} real CVEs across 30 days")
        
        return {
            'labels': [d.strftime('%Y-%m-%d') for d in sorted_dates],
            'values': [date_counts[d] for d in sorted_dates]
        }
        
    except Exception as e:
        print(f"Error getting CVE trends: {e}")
        # Return empty data rather than fake data
        today = datetime.now(timezone.utc).date()
        start_date = today - timedelta(days=29)
        dates = [start_date + timedelta(days=i) for i in range(30)]
        
        return {
            'labels': [d.strftime('%Y-%m-%d') for d in dates],
            'values': [0] * 30
        }

# Health check endpoint for Render
@app.route("/health")
def health_check():
    """Health check endpoint to prevent app from sleeping"""
    try:
        reset_circuit_breaker()
    except:
        pass
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

@app.route("/api/cwe/<cwe_id>")
def api_get_cwe(cwe_id):
    """API endpoint for CWE data"""
    try:
        cwe_data = get_single_cwe(cwe_id)
        return jsonify({
            'success': True,
            'data': cwe_data
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route("/references")
def references():
    """References and Resources page"""
    return render_template("references.html")

@app.route("/", methods=["GET"])
def index():
    """Main dashboard with REAL DATA ONLY"""
    try:
        # Start cache warming but don't wait for it
        warm_dashboard_cache_if_needed()
        
        year = request.args.get('year', type=int)
        month = request.args.get('month', type=int)
        severity_filter = request.args.get('severity')
        search_query = request.args.get('q')
        
        # Get CVEs - REAL DATA ONLY
        try:
            print(f"[Dashboard] Fetching real CVEs for year={year}, month={month}")
            all_cves = get_all_cves(year=year, month=month, force_refresh=False, timeout=20, days=30)
            
            if not all_cves:
                print("[Dashboard] No real CVE data available")
                # Return minimal dashboard with empty data instead of crashing
                return render_template(
                    "index.html",
                    year_filter=year,
                    month_filter=month,
                    severity_filter=severity_filter,
                    search_query=search_query,
                    metrics={'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
                    available_years=get_all_years(),
                    available_months=list(range(1, 13)),
                    timeline_data_days={'labels': [], 'values': []},
                    timeline_data_years={'labels': [], 'values': []},
                    severity_stats={'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
                    severity_percentage={'CRITICAL': '0', 'HIGH': '0', 'MEDIUM': '0', 'LOW': '0'},
                    cwe_radar={'indices': [], 'labels': [], 'values': []},
                    cwe_radar_all={'all': {'indices': [], 'labels': [], 'values': []}, 'top5': {'indices': [], 'labels': [], 'values': []}, 'top10': {'indices': [], 'labels': [], 'values': []}},
                    cwe_radar_weighted={'indices': [], 'labels': [], 'values': []},
                    cwe_radar_descriptions=get_cwe_radar_descriptions(),
                    note_text="No real CVE data currently available",
                    total_cves=0
                )
            
        except Exception as e:
            print(f"Error fetching CVEs: {e}")
            # Return error state instead of fake data
            return render_template("error.html", error="Unable to fetch real CVE data. Please try again later."), 500
        
        print(f"[Dashboard] Processing {len(all_cves)} real CVEs")
        
        # Process CVEs with dates
        all_cves_with_dates = []
        for cve in all_cves:
            parsed_date = parse_published_date(cve)
            if parsed_date:
                cve['_parsed_published'] = parsed_date
                all_cves_with_dates.append(cve)
        
        all_cves_with_dates.sort(key=lambda cve: cve.get('_parsed_published', datetime.min), reverse=True)
        
        # Calculate metrics from REAL data
        metrics = calculate_severity_metrics(all_cves_with_dates)
        total_cves = sum(metrics.values())
        
        print(f"[Dashboard] Calculated metrics from {total_cves} real CVEs: {metrics}")
        
        # Get timeline data - REAL DATA ONLY
        timeline_daily = get_cve_trends_30_days()
        timeline_months = get_cached_timeline_data()
        
        # Generate chart data from REAL CVEs
        cwe_radar_full = get_cwe_radar_data_full(all_cves_with_dates)
        cwe_radar_weighted = get_cwe_radar_weighted(all_cves_with_dates)
        cwe_radar_descriptions = get_cwe_radar_descriptions()
        
        # Apply filters
        display_metrics = metrics
        if severity_filter and severity_filter.upper() in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            filtered_cves = [cve for cve in all_cves_with_dates if cve.get('Severity', '').upper() == severity_filter.upper()]
            display_metrics = calculate_severity_metrics(filtered_cves)
        
        # Calculate percentages
        if total_cves == 0:
            severity_percentage = {k: "0" for k in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']}
        else:
            severity_percentage = {
                k: f"{(metrics.get(k, 0) * 100 // total_cves)}" for k in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            }
        
        # Ensure all metrics have values
        for k in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if k not in metrics:
                metrics[k] = 0
        
        # Generate note text based on actual data
        available_years = get_all_years()
        available_months = list(range(1, 13))
        note_text = None
        
        if year and month:
            days_in_month = monthrange(year, month)[1]
            note_start_date = datetime(year, month, 1).date()
            note_end_date = datetime(year, month, days_in_month).date()
            note_text = f"Showing {total_cves} real CVEs from {note_start_date.strftime('%Y-%m-%d')} to {note_end_date.strftime('%Y-%m-%d')}"
        elif year and not month:
            note_start_date = datetime(year, 1, 1).date()
            note_end_date = datetime(year, 12, 31).date()
            note_text = f"Showing {total_cves} real CVEs from {note_start_date.strftime('%Y-%m-%d')} to {note_end_date.strftime('%Y-%m-%d')}"
        else:
            # Determine actual date range from the data
            if all_cves_with_dates:
                dates = [cve['_parsed_published'].date() for cve in all_cves_with_dates if cve.get('_parsed_published')]
                if dates:
                    min_date = min(dates)
                    max_date = max(dates)
                    note_text = f"Showing {total_cves} real CVEs from {min_date.strftime('%Y-%m-%d')} to {max_date.strftime('%Y-%m-%d')}"
                else:
                    note_text = f"Showing {total_cves} real CVEs from recent data"
            else:
                note_text = "No real CVE data available for the selected period"
        
        return render_template(
            "index.html",
            year_filter=year,
            month_filter=month,
            severity_filter=severity_filter,
            search_query=search_query,
            metrics=display_metrics,
            available_years=available_years,
            available_months=available_months,
            timeline_data_days=timeline_daily,
            timeline_data_years=timeline_months,
            severity_stats=metrics,
            severity_percentage=severity_percentage,
            cwe_radar=cwe_radar_full['top10'],
            cwe_radar_all=cwe_radar_full,
            cwe_radar_weighted=cwe_radar_weighted,
            cwe_radar_descriptions=cwe_radar_descriptions,
            note_text=note_text,
            total_cves=total_cves
        )
    
    except Exception as e:
        print(f"Critical error in index route: {e}")
        return render_template("error.html", error="Service temporarily unavailable. Please try again in a few moments."), 500

@app.route("/learn")
def learn():
    """Redirect Learn landing page to 'What is a CVE?' as main topic"""
    return redirect(url_for('learn_topic', topic='what-is-cve'))

@app.route("/learn/<string:topic>")
def learn_topic(topic):
    """Learn topic pages with error handling"""
    valid_topics = [
        'what-is-cwe', 'what-is-cve', 'cvss-scores',
        'what-is-nvd-mitre', 'cve-vs-cwe-vs-cvss'
    ]
    
    if topic not in valid_topics:
        return redirect(url_for('learn_topic', topic='what-is-cve'))
    
    try:
        cves = get_all_cves(force_refresh=False, timeout=15)
        cwe_dict = get_cwe_dict()
        selected_cwes = list(CWE_TITLES.keys())
        cwe_severity = get_cwe_severity_chart_data(cves, selected_cwes)
        
        latest_cves = sorted(cves, key=lambda x: x.get('Published', ''), reverse=True)[:25]
        now = datetime.now(timezone.utc)
        
        return render_template(
            f"learn/{topic}.html",
            cwe_dict=cwe_dict,
            cwe_severity=cwe_severity,
            latest_cves=latest_cves,
            key_cwes=selected_cwes,
            key_cwe_titles=CWE_TITLES,
            now=now
        )
    
    except Exception as e:
        print(f"Error in learn_topic: {e}")
        # Return with minimal data
        return render_template(
            f"learn/{topic}.html",
            cwe_dict={},
            cwe_severity={'labels': [], 'data': {}},
            latest_cves=[],
            key_cwes=[],
            key_cwe_titles={},
            now=datetime.now(timezone.utc)
        )

@app.route("/vulnerabilities/", methods=["GET"])
def vulnerabilities():
    """Vulnerabilities listing page with REAL DATA ONLY"""
    try:
        year = request.args.get('year', type=int)
        month = request.args.get('month', type=int)
        day = request.args.get('day', type=int)
        severity_filter = request.args.get('severity')
        search_query = request.args.get('q')
        page = request.args.get('page', default=1, type=int)
        per_page = 15
        
        # Determine date filtering
        show_note = False
        note_start_date = None
        note_end_date = None
        
        if year and month and day:
            note_start_date = datetime(year, month, day).date()
            note_end_date = note_start_date
            show_note = True
        elif year and month:
            days_in_month = monthrange(year, month)[1]
            note_start_date = datetime(year, month, 1).date()
            note_end_date = datetime(year, month, days_in_month).date()
            show_note = True
        elif year and not month:
            note_start_date = datetime(year, 1, 1).date()
            note_end_date = datetime(year, 12, 31).date()
            show_note = True
        else:
            note_end_date = datetime.now(timezone.utc).date()
            note_start_date = note_end_date - timedelta(days=29)
            show_note = True
        
        # Get CVEs - REAL DATA ONLY
        try:
            print(f"[Vulnerabilities] Fetching real CVEs for year={year}, month={month}, day={day}")
            
            if year and month:
                # For specific year/month, try to get broader data and then filter
                fetch_days = 365 if year < datetime.now().year else 90
                all_cves = get_all_cves(year=year, month=month, force_refresh=False, timeout=20, days=fetch_days)
            elif year:
                # For full year
                all_cves = get_all_cves(year=year, force_refresh=False, timeout=20, days=365)
            else:
                # Current period
                all_cves = get_all_cves(force_refresh=False, timeout=15, days=30)
                
            if not all_cves:
                print("[Vulnerabilities] No real CVE data available")
                return render_template(
                    "vulnerabilities.html",
                    latest_cves=[],
                    year_filter=year,
                    month_filter=month,
                    day_filter=day,
                    severity_filter=severity_filter,
                    search_query=search_query,
                    available_years=get_all_years(),
                    available_months=list(range(1, 13)),
                    current_page=1,
                    total_pages=1,
                    page_numbers=[1],
                    total_results=0,
                    note_text="No real CVE data available for the selected period"
                )
                
        except Exception as e:
            print(f"Error fetching vulnerabilities: {e}")
            return render_template("error.html", error="Unable to fetch real vulnerability data. Please try again later."), 500
        
        # Process CVEs with dates
        all_cves_with_dates = []
        for cve in all_cves:
            parsed_date = parse_published_date(cve)
            if parsed_date is not None:
                cve['_parsed_published'] = parsed_date
                all_cves_with_dates.append(cve)
        
        all_cves_with_dates.sort(key=lambda cve: cve.get('_parsed_published', datetime.min), reverse=True)
        
        # Apply filters
        filtered_cves = all_cves_with_dates
        
        if year and month and day:
            filtered_cves = [cve for cve in filtered_cves if 
                           cve.get('_parsed_published') is not None and
                           cve['_parsed_published'].year == year and
                           cve['_parsed_published'].month == month and
                           cve['_parsed_published'].day == day]
        else:
            if severity_filter and severity_filter.upper() in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                filtered_cves = [cve for cve in filtered_cves if cve.get('Severity', '').upper() == severity_filter.upper()]
            
            if search_query:
                q_lower = search_query.lower()
                if q_lower.startswith("cwe-") and q_lower[4:].isdigit():
                    filtered_cves = [cve for cve in filtered_cves if (cve.get("CWE") or "").lower() == q_lower]
                else:
                    filtered_cves = [cve for cve in filtered_cves if q_lower in (cve.get('Description', '') + cve.get('ID', '')).lower()]
        
        # Pagination
        total_results = len(filtered_cves)
        total_pages = max(1, math.ceil(total_results / per_page))
        current_page = max(1, min(page, total_pages))
        start_index = (current_page - 1) * per_page
        end_index = start_index + per_page
        cves_page = filtered_cves[start_index:end_index]
        
        # Pagination numbers
        available_years = get_all_years()
        available_months = list(range(1, 13))
        page_numbers = []
        
        if total_pages <= 7:
            page_numbers = list(range(1, total_pages + 1))
        else:
            if current_page <= 4:
                page_numbers = list(range(1, 8))
            elif current_page >= total_pages - 3:
                page_numbers = list(range(total_pages - 6, total_pages + 1))
            else:
                page_numbers = list(range(current_page - 3, current_page + 4))
        
        # Generate note text based on actual data
        note_text = None
        if show_note and note_start_date and note_end_date:
            if note_start_date == note_end_date:
                note_text = f"Showing {total_results} real CVEs from {note_start_date.strftime('%Y-%m-%d')}"
            else:
                note_text = f"Showing {total_results} real CVEs from {note_start_date.strftime('%Y-%m-%d')} to {note_end_date.strftime('%Y-%m-%d')}"
        
        print(f"[Vulnerabilities] Displaying {len(cves_page)} CVEs out of {total_results} total")
        
        return render_template(
            "vulnerabilities.html",
            latest_cves=cves_page,
            year_filter=year,
            month_filter=month,
            day_filter=day,
            severity_filter=severity_filter,
            search_query=search_query,
            available_years=available_years,
            available_months=available_months,
            current_page=current_page,
            total_pages=total_pages,
            page_numbers=page_numbers,
            total_results=total_results,
            note_text=note_text
        )
    
    except Exception as e:
        print(f"Error in vulnerabilities route: {e}")
        return render_template("error.html", error="Unable to load vulnerabilities. Please try again."), 500

@app.route("/cve/<cve_id>")
def cve_detail(cve_id):
    """CVE detail page with improved error handling"""
    try:
        year = request.args.get('year', type=int)
        month = request.args.get('month', type=int)
        page = request.args.get('page', default=1, type=int)
        severity = request.args.get('severity')
        
        if cve_id.startswith("CVE-") and len(cve_id) == 13:
            try:
                cve = get_cve_detail(cve_id)
                
                # If CVE not found in API, return error instead of fake data
                if cve.get('Description') == 'Not found':
                    cve = {
                        'ID': cve_id,
                        'Description': 'CVE details not found in NVD database.',
                        'Severity': 'UNKNOWN',
                        'CWE': 'CWE-NVD-UNKNOWN',
                        'Published': 'Unknown',
                        'References': [],
                        'Products': [],
                        'metrics': {}
                    }
            except Exception as e:
                print(f"Error fetching CVE detail: {e}")
                cve = {
                    'ID': cve_id,
                    'Description': 'CVE details temporarily unavailable. Please try again later.',
                    'Severity': 'UNKNOWN',
                    'CWE': 'CWE-NVD-UNKNOWN',
                    'Published': 'Unknown',
                    'References': [],
                    'Products': [],
                    'metrics': {}
                }
        else:
            cve = {
                'ID': cve_id,
                'Description': 'Invalid CVE ID format.',
                'Severity': 'UNKNOWN'
            }
        
        return render_template(
            "cve_detail.html",
            cve=cve,
            year=year,
            month=month,
            page=page,
            severity=severity
        )
    
    except Exception as e:
        print(f"Error in cve_detail route: {e}")
        return render_template("error.html", error="Unable to load CVE details. Please try again."), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", error="Page not found."), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template("error.html", error="Internal server error. Please try again."), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)