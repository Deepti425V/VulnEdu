from flask import Flask, render_template, request, url_for, redirect, jsonify
from services.fetch_CVE import (
    get_all_cves, 
    reset_circuit_breaker,
    get_daily_cve_data_for_30_days,  # NEW: Proper 30-day data
    get_monthly_cve_data_for_5_years  # NEW: Proper 5-year data
)
from services.nvd_api import get_cve_detail
from services.cwe_data import get_cwe_dict, get_single_cwe, warm_cwe_cache
from services.cwe_map import CWE_TITLES, cwe_title
from collections import Counter, defaultdict
import math
from datetime import datetime, timedelta, timezone
from calendar import monthrange
import os
from threading import Thread, Lock
import time
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

# Reset circuit breaker on startup
try:
    reset_circuit_breaker()
    print("[Startup] Circuit breaker reset")
except:
    print("[Startup] Could not reset circuit breaker")

# FIXED: Enhanced global cache for ALL data
_global_cve_cache = {
    'all_data': None,           # All CVEs
    'daily_30_data': None,      # 30-day daily data
    'monthly_5yr_data': None,   # 5-year monthly data
    'last_updated': None,
    'lock': Lock()
}

CACHE_REFRESH_HOURS = 6

def get_all_cve_data_with_graphs(force_refresh=False):
    """
    FIXED: Get ALL CVE data + proper graph data
    This ensures we have complete data for both tables and graphs
    """
    global _global_cve_cache
    
    with _global_cve_cache['lock']:
        now = datetime.now(timezone.utc)
        
        # Check if cache is still fresh
        if (_global_cve_cache['all_data'] is not None and 
            _global_cve_cache['last_updated'] is not None and
            not force_refresh):
            
            hours_since_update = (now - _global_cve_cache['last_updated']).total_seconds() / 3600
            if hours_since_update < CACHE_REFRESH_HOURS:
                print(f"[Global Cache] Using cached data ({len(_global_cve_cache['all_data'])} CVEs)")
                return {
                    'all_cves': _global_cve_cache['all_data'],
                    'daily_30': _global_cve_cache['daily_30_data'],
                    'monthly_5yr': _global_cve_cache['monthly_5yr_data']
                }
        
        # Refresh ALL data
        print("[Global Cache] Refreshing ALL CVE data (tables + graphs)...")
        
        # Get ALL available CVEs (no limit)
        print("[Global Cache] Fetching ALL CVEs...")
        all_cves = get_all_cves(force_refresh=True, timeout=30)
        
        # Get proper 30-day daily data
        print("[Global Cache] Generating 30-day daily graph data...")
        daily_30_data = get_daily_cve_data_for_30_days()
        
        # Get proper 5-year monthly data  
        print("[Global Cache] Generating 5-year monthly graph data...")
        monthly_5yr_data = get_monthly_cve_data_for_5_years()
        
        # Cache everything
        _global_cve_cache['all_data'] = all_cves
        _global_cve_cache['daily_30_data'] = daily_30_data
        _global_cve_cache['monthly_5yr_data'] = monthly_5yr_data
        _global_cve_cache['last_updated'] = now
        
        print(f"[Global Cache] Cached {len(all_cves)} CVEs + graph data")
        
        return {
            'all_cves': all_cves,
            'daily_30': daily_30_data,
            'monthly_5yr': monthly_5yr_data
        }

# Thread pool for background tasks
executor = ThreadPoolExecutor(max_workers=2)
_warmed_up = False

def warm_dashboard_cache_if_needed():
    """Warm cache without blocking if it fails"""
    global _warmed_up
    if not _warmed_up:
        _warmed_up = True
        def _warm():
            try:
                get_all_cve_data_with_graphs()
                executor.submit(warm_cwe_cache)
            except Exception as e:
                print(f"Cache warming failed: {e}")
        Thread(target=_warm, daemon=True).start()

def calculate_severity_metrics(cves):
    """FIXED: Calculate severity metrics INCLUDING unknown CVEs"""
    counts = Counter()
    for cve in cves:
        sev = cve.get('Severity', '').upper()
        if sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            counts[sev] += 1
        else:
            counts['UNKNOWN'] += 1
    
    return {
        'CRITICAL': counts.get('CRITICAL', 0),
        'HIGH': counts.get('HIGH', 0),
        'MEDIUM': counts.get('MEDIUM', 0),
        'LOW': counts.get('LOW', 0),
        'UNKNOWN': counts.get('UNKNOWN', 0)
    }

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

# Health check endpoint
@app.route("/health")
def health_check():
    """Health check endpoint"""
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
    """FIXED: Main dashboard with ALL data + proper graphs"""
    try:
        # Start cache warming
        warm_dashboard_cache_if_needed()

        year = request.args.get('year', type=int)
        month = request.args.get('month', type=int)
        severity_filter = request.args.get('severity')
        search_query = request.args.get('q')

        # FIXED: Get ALL data + proper graph data
        data_bundle = get_all_cve_data_with_graphs()
        all_cves = data_bundle['all_cves']
        daily_30_data = data_bundle['daily_30']
        monthly_5yr_data = data_bundle['monthly_5yr']
        
        print(f"[Dashboard] Using {len(all_cves)} CVEs from enhanced cache")
        print(f"[Dashboard] 30-day data: {len(daily_30_data['labels'])} days")
        print(f"[Dashboard] 5-year data: {len(monthly_5yr_data['labels'])} months")

        # Process CVEs
        all_cves_with_dates = []
        for cve in all_cves:
            parsed_date = parse_published_date(cve)
            if parsed_date:
                cve['_parsed_published'] = parsed_date
            all_cves_with_dates.append(cve)

        all_cves_with_dates.sort(key=lambda cve: cve.get('_parsed_published', datetime.min), reverse=True)

        # FIXED: Calculate metrics from ALL CVEs (including UNKNOWN)
        metrics = calculate_severity_metrics(all_cves_with_dates)
        total_cves = len(all_cves_with_dates)  # Total count of ALL CVEs
        total_with_severity = sum(metrics[k] for k in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])
        
        print(f"[Dashboard] Total CVEs: {total_cves}")
        print(f"[Dashboard] With severity: {total_with_severity}, Unknown: {metrics.get('UNKNOWN', 0)}")
        print(f"[Dashboard] Breakdown: Critical={metrics['CRITICAL']}, High={metrics['HIGH']}, Medium={metrics['MEDIUM']}, Low={metrics['LOW']}")

        # Generate chart data from SAME data source
        cwe_radar_full = get_cwe_radar_data_full(all_cves_with_dates)
        cwe_radar_weighted = get_cwe_radar_weighted(all_cves_with_dates)
        cwe_radar_descriptions = get_cwe_radar_descriptions()

        # Apply filters to the SAME data
        display_metrics = metrics
        if severity_filter and severity_filter.upper() in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            filtered_cves = [cve for cve in all_cves_with_dates if cve.get('Severity', '').upper() == severity_filter.upper()]
            display_metrics = calculate_severity_metrics(filtered_cves)

        # Calculate percentages (only from CVEs with severity)
        if total_with_severity == 0:
            severity_percentage = {k: "0" for k in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']}
        else:
            severity_percentage = {
                k: f"{(metrics.get(k, 0) * 100 // total_with_severity)}" for k in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            }

        # Ensure all metrics have values
        for k in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if k not in metrics:
                metrics[k] = 0

        # Generate note text
        available_years = get_all_years()
        available_months = list(range(1, 13))
        note_text = None

        if year and month:
            days_in_month = monthrange(year, month)[1]
            note_start_date = datetime(year, month, 1).date()
            note_end_date = datetime(year, month, days_in_month).date()
            note_text = f"Showing data from {note_start_date.strftime('%Y-%m-%d')} to {note_end_date.strftime('%Y-%m-%d')}"
        elif year and not month:
            note_start_date = datetime(year, 1, 1).date()
            note_end_date = datetime(year, 12, 31).date()
            note_text = f"Showing data from {note_start_date.strftime('%Y-%m-%d')} to {note_end_date.strftime('%Y-%m-%d')}"
        else:
            now_date = datetime.now(timezone.utc).date()
            note_start_date = now_date - timedelta(days=29)
            note_end_date = now_date
            note_text = f"Showing data from {note_start_date.strftime('%Y-%m-%d')} to {note_end_date.strftime('%Y-%m-%d')}"

        return render_template(
            "index.html",
            year_filter=year,
            month_filter=month,
            severity_filter=severity_filter,
            search_query=search_query,
            metrics=display_metrics,
            available_years=available_years,
            available_months=available_months,
            timeline_data_days=daily_30_data,        # FIXED: Real 30-day data
            timeline_data_years=monthly_5yr_data,    # FIXED: Real 5-year data
            severity_stats=metrics,
            severity_percentage=severity_percentage,
            cwe_radar=cwe_radar_full['top10'],
            cwe_radar_all=cwe_radar_full,
            cwe_radar_weighted=cwe_radar_weighted,
            cwe_radar_descriptions=cwe_radar_descriptions,
            note_text=note_text,
            total_cves=total_cves  # Show TOTAL count including UNKNOWN
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
        # Use consistent data source
        data_bundle = get_all_cve_data_with_graphs()
        cves = data_bundle['all_cves']
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
    """FIXED: Vulnerabilities listing page with ALL data"""
    try:
        year = request.args.get('year', type=int)
        month = request.args.get('month', type=int)
        day = request.args.get('day', type=int)
        severity_filter = request.args.get('severity')
        search_query = request.args.get('q')
        page = request.args.get('page', default=1, type=int)
        per_page = 15

        # FIXED: Use SAME data source as dashboard
        data_bundle = get_all_cve_data_with_graphs()
        all_cves = data_bundle['all_cves']
        
        print(f"[Vulnerabilities] Using {len(all_cves)} CVEs from enhanced cache")

        # Process CVEs with dates (SAME as dashboard)
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
        elif year and month:
            filtered_cves = [cve for cve in filtered_cves if
                           cve.get('_parsed_published') is not None and
                           cve['_parsed_published'].year == year and
                           cve['_parsed_published'].month == month]
        elif year:
            filtered_cves = [cve for cve in filtered_cves if
                           cve.get('_parsed_published') is not None and
                           cve['_parsed_published'].year == year]
        
        if severity_filter and severity_filter.upper() in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
            filtered_cves = [cve for cve in filtered_cves if cve.get('Severity', 'UNKNOWN').upper() == severity_filter.upper()]

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

        # Generate note text
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

        note_text = None
        if show_note and note_start_date and note_end_date:
            if note_start_date == note_end_date:
                note_text = f"Showing data from {note_start_date.strftime('%Y-%m-%d')}"
            else:
                note_text = f"Showing data from {note_start_date.strftime('%Y-%m-%d')} to {note_end_date.strftime('%Y-%m-%d')}"

        print(f"[Vulnerabilities] Showing {total_results} total results, page {current_page} of {total_pages}")

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
                # If CVE not found in API, check our data
                if cve.get('Description') == 'Not found':
                    data_bundle = get_all_cve_data_with_graphs()
                    all_cves = data_bundle['all_cves']
                    found_cve = next((c for c in all_cves if c.get('ID') == cve_id), None)
                    if found_cve:
                        cve = found_cve
            except Exception as e:
                print(f"Error fetching CVE detail: {e}")
                cve = {
                    'ID': cve_id,
                    'Description': 'CVE details temporarily unavailable. Please try again later.',
                    'Severity': 'UNKNOWN',
                    'CWE': 'CWE-NVD-UNKNOWN',
                    'Published': datetime.now().strftime('%Y-%m-%d'),
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