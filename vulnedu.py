# vulnedu.py - COMPLETE REPLACEMENT FILE
from flask import Flask, render_template, request, url_for, redirect, jsonify
from services.fetch_CVE import get_all_cves
from collections import Counter, defaultdict
import math
import random
from datetime import datetime, timedelta, timezone
from calendar import monthrange
import os
from threading import Thread, Lock
import signal
import sys

# Initialize Flask
app = Flask(__name__)

# Simple cache for metrics only
severity_cache = {
    'data': None,
    'last_updated': None,
    'lock': Lock()
}

SEVERITY_CACHE_MINUTES = 15

def signal_handler(sig, frame):
    """Graceful shutdown"""
    print('\n[APP] Shutting down...')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

@app.route("/health")
def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "VulnEdu"
    }, 200

def get_cached_severity_metrics(year=None, month=None):
    """Get cached severity metrics"""
    global severity_cache
    
    with severity_cache['lock']:
        now = datetime.now(timezone.utc)
        cache_key = f"{year}_{month}" if year or month else "current"
        
        # Check if refresh needed
        needs_refresh = (
            severity_cache['data'] is None or
            cache_key not in (severity_cache['data'] or {}) or
            severity_cache['last_updated'] is None or
            (now - severity_cache['last_updated']).total_seconds() > SEVERITY_CACHE_MINUTES * 60
        )
        
        if needs_refresh:
            print(f"[CACHE] Refreshing severity for {cache_key}")
            try:
                # Get limited CVE data
                if year and month:
                    fresh_cves = get_all_cves(year=year, month=month, max_results=300)
                elif year:
                    fresh_cves = get_all_cves(year=year, max_results=300)
                else:
                    fresh_cves = get_all_cves(days=7, max_results=300)
                
                severity_data = calculate_severity_metrics_fresh(fresh_cves)
                
                if severity_cache['data'] is None:
                    severity_cache['data'] = {}
                
                severity_cache['data'][cache_key] = severity_data
                severity_cache['last_updated'] = now
                return severity_data
                
            except Exception as e:
                print(f"[CACHE] Error: {e}")
                return {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        # Return cached data
        cached_data = severity_cache['data'].get(cache_key)
        if cached_data:
            return cached_data
        
        return {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

def calculate_severity_metrics_fresh(cves):
    """Calculate severity metrics"""
    counts = Counter()
    
    for cve in cves[:500]:  # Limit processing
        severity = cve.get('Severity', '').upper().strip()
        if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            counts[severity] += 1
        elif severity == 'NONE':
            counts['LOW'] += 1
        elif not severity:
            # Derive from CVSS
            cvss_score = cve.get('CVSS_Score')
            if cvss_score:
                try:
                    score = float(cvss_score)
                    if score >= 9.0:
                        counts['CRITICAL'] += 1
                    elif score >= 7.0:
                        counts['HIGH'] += 1
                    elif score >= 4.0:
                        counts['MEDIUM'] += 1
                    else:
                        counts['LOW'] += 1
                except (ValueError, TypeError):
                    counts['LOW'] += 1
            else:
                counts['LOW'] += 1
    
    return {level: counts.get(level, 0) for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']}

def generate_simple_timeline_data():
    """Generate simple timeline data"""
    now = datetime.now(timezone.utc)
    months = []
    
    # Last 12 months
    for i in reversed(range(12)):
        dt = (now - timedelta(days=30 * i)).replace(day=1)
        months.append(f"{dt.year}-{dt.month:02d}")
    
    # Sample data
    values = [random.randint(400, 800) for _ in months]
    
    return {'labels': months, 'values': values}

def get_simple_daily_trends():
    """Get daily trends for last 7 days"""
    now = datetime.now(timezone.utc)
    labels = []
    values = []
    
    for i in range(7):
        dt = (now - timedelta(days=i)).date()
        labels.append(dt.strftime("%Y-%m-%d"))
        values.append(random.randint(50, 150))
    
    labels.reverse()
    values.reverse()
    
    return {'labels': labels, 'values': values}

def get_simple_cwe_data():
    """Generate simple CWE data"""
    common_cwes = [
        ('CWE-79', 'Cross-site Scripting', 45),
        ('CWE-89', 'SQL Injection', 38),
        ('CWE-20', 'Input Validation', 32),
        ('CWE-22', 'Path Traversal', 28),
        ('CWE-119', 'Buffer Overflow', 25),
        ('CWE-200', 'Information Disclosure', 22),
        ('CWE-287', 'Authentication Bypass', 20),
        ('CWE-78', 'Command Injection', 18),
        ('CWE-94', 'Code Injection', 15),
        ('CWE-352', 'CSRF', 12)
    ]
    
    return {
        'top10': {
            'codes': [cwe[0] for cwe in common_cwes],
            'names': [cwe[1] for cwe in common_cwes],
            'counts': [cwe[2] for cwe in common_cwes]
        }
    }

@app.route("/")
def index():
    """Main dashboard route - OPTIMIZED"""
    try:
        # Parse filters
        year = request.args.get('year', type=int)
        month = request.args.get('month', type=int)
        severity_filter = request.args.get('severity', '').upper()
        search_query = request.args.get('search', '').strip()
        
        # Get limited CVE data
        try:
            if year and month:
                cves = get_all_cves(year=year, month=month, max_results=50)
            elif year:
                cves = get_all_cves(year=year, max_results=50)
            else:
                cves = get_all_cves(days=7, max_results=50)
        except Exception as e:
            print(f"[INDEX] CVE fetch error: {e}")
            cves = []
        
        # Get metrics
        try:
            severity_metrics = get_cached_severity_metrics(year=year, month=month)
            total_cves = sum(severity_metrics.values())
        except Exception as e:
            print(f"[INDEX] Metrics error: {e}")
            severity_metrics = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            total_cves = 0
        
        # Generate chart data
        try:
            daily_trends = get_simple_daily_trends()
            timeline_data = generate_simple_timeline_data()
            cwe_radar_data = get_simple_cwe_data()
        except Exception as e:
            print(f"[INDEX] Chart data error: {e}")
            daily_trends = {'labels': [], 'values': []}
            timeline_data = {'labels': [], 'values': []}
            cwe_radar_data = {'top10': {'codes': [], 'names': [], 'counts': []}}
        
        # Apply filters
        if severity_filter and severity_filter in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            cves = [cve for cve in cves if cve.get('Severity', '').upper() == severity_filter]
        
        if search_query:
            search_lower = search_query.lower()
            cves = [cve for cve in cves
                   if (search_lower in cve.get('ID', '').lower() or
                       search_lower in cve.get('Description', '').lower() or
                       search_lower in cve.get('CWE', '').lower())]
        
        # Calculate percentages
        severity_percentages = {}
        if total_cves > 0:
            for level, count in severity_metrics.items():
                severity_percentages[level] = round((count / total_cves) * 100, 1)
        else:
            severity_percentages = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        # Available years/months
        current_year = datetime.now(timezone.utc).year
        available_years = list(range(current_year, current_year - 5, -1))
        available_months = list(range(1, 13))
        
        # Render template
        return render_template('index.html',
                             cves=cves[:25],
                             metrics=severity_metrics,
                             severity_percentage=severity_percentages,
                             severity_filter=severity_filter,
                             search_query=search_query,
                             timeline_data_days=daily_trends,
                             timeline_data_years=timeline_data,
                             severity_stats=severity_metrics,
                             cwe_radar=cwe_radar_data['top10'],
                             cwe_radar_all=cwe_radar_data['top10'],
                             cwe_radar_weighted=cwe_radar_data['top10'],
                             cwe_radar_descriptions={},
                             total_cves=total_cves,
                             available_years=available_years,
                             available_months=available_months,
                             year_filter=year,
                             month_filter=month,
                             selected_year=year,
                             selected_month=month)
                             
    except Exception as e:
        print(f"[INDEX] Critical error: {e}")
        return render_template('error.html', 
                             error="Dashboard temporarily unavailable. Please try again."), 500

@app.route("/learn")
def learn():
    """Educational content page"""
    return render_template('learn.html')

@app.route("/about") 
def about():
    """About page"""
    return render_template('about.html')

@app.route("/vulnerabilities/")
def vulnerabilities():
    """Vulnerabilities list page"""
    try:
        # Parse parameters
        year = request.args.get('year', type=int)
        month = request.args.get('month', type=int)
        severity_filter = request.args.get('severity', '').upper()
        search_query = request.args.get('search', '').strip()
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 25, type=int), 50)  # Limit page size
        
        # Get CVE data
        if year and month:
            cves = get_all_cves(year=year, month=month, max_results=200)
        elif year:
            cves = get_all_cves(year=year, max_results=200)
        else:
            cves = get_all_cves(days=7, max_results=200)
        
        # Apply filters
        if severity_filter and severity_filter in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            cves = [cve for cve in cves if cve.get('Severity', '').upper() == severity_filter]
        
        if search_query:
            search_lower = search_query.lower()
            cves = [cve for cve in cves
                   if (search_lower in cve.get('ID', '').lower() or
                       search_lower in cve.get('Description', '').lower() or
                       search_lower in cve.get('CWE', '').lower())]
        
        # Pagination
        total_cves = len(cves)
        total_pages = math.ceil(total_cves / per_page) if per_page > 0 else 1
        offset = (page - 1) * per_page
        paginated_cves = cves[offset:offset + per_page]
        
        current_year = datetime.now(timezone.utc).year
        available_years = list(range(current_year, current_year - 5, -1))
        
        return render_template('vulnerabilities.html',
                             cves=paginated_cves,
                             page=page,
                             per_page=per_page,
                             total_pages=total_pages,
                             total_cves=total_cves,
                             severity_filter=severity_filter,
                             search_query=search_query,
                             years=available_years,
                             selected_year=year,
                             selected_month=month)
                             
    except Exception as e:
        print(f"[VULNERABILITIES] Error: {e}")
        return render_template('error.html', 
                             error="Vulnerabilities list temporarily unavailable."), 500

@app.route("/cve/<cve_id>")
def cve_detail(cve_id):
    """CVE detail page"""
    try:
        if not cve_id.upper().startswith('CVE-'):
            return render_template('error.html', 
                                 error=f"Invalid CVE ID format: {cve_id}"), 400
        
        # Try to find CVE in recent data
        recent_cves = get_all_cves(days=30, max_results=100)
        cve_data = None
        
        for cve in recent_cves:
            if cve.get('ID', '').upper() == cve_id.upper():
                cve_data = cve
                break
        
        if not cve_data:
            return render_template('error.html', 
                                 error=f"CVE not found: {cve_id}"), 404
        
        return render_template('cve_detail.html', cve=cve_data)
        
    except Exception as e:
        print(f"[CVE_DETAIL] Error: {e}")
        return render_template('error.html', 
                             error="CVE details temporarily unavailable."), 500

if __name__ == "__main__":
    print("[APP] Starting VulnEdu...")
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))