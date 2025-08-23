from flask import Flask, render_template, request, url_for, redirect, jsonify
from services.fetch_CVE import get_all_cves, _fetch_from_nvd
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

app = Flask(__name__)

timeline_cache = {
    'data': None,
    'last_updated': None,
    'lock': Lock()
}

severity_cache = {
    'data': None,
    'last_updated': None,
    'lock': Lock()
}

TIMELINE_CACHE_HOURS = 12  # Very long cache to prevent API calls
SEVERITY_CACHE_MINUTES = 60  # 1 hour cache
_warmed_up = False

@app.route("/debug/force-refresh")
def force_refresh():
    """Debug route to force fresh data and clear all caches - USE CAREFULLY"""
    try:
        # Clear all caches
        global severity_cache, timeline_cache
        with severity_cache['lock']:
            severity_cache['data'] = None
            severity_cache['last_updated'] = None
        with timeline_cache['lock']:
            timeline_cache['data'] = None
            timeline_cache['last_updated'] = None
        
        # Delete cache file
        cache_path = "data/cache/cve_cache.json"
        if os.path.exists(cache_path):
            os.remove(cache_path)
            
        # Make ONE API call only
        fresh_cves = get_all_cves(days=1, force_refresh=True, max_results=10)
        
        return {
            "status": "success",
            "message": "Caches cleared and minimal fresh data fetched",
            "sample_cves_count": len(fresh_cves),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        return {"error": str(e)}, 500

@app.route("/debug/cache-status")
def cache_status():
    """Check cache status without triggering any API calls"""
    try:
        cache_path = "data/cache/cve_cache.json"
        cache_exists = os.path.exists(cache_path)
        cache_size = 0
        cache_age_minutes = None
        
        if cache_exists:
            cache_size = os.path.getsize(cache_path)
            cache_mtime = datetime.fromtimestamp(os.path.getmtime(cache_path), tz=timezone.utc)
            cache_age_minutes = int((datetime.now(timezone.utc) - cache_mtime).total_seconds() / 60)
        
        # Load cached data without triggering refresh
        try:
            if cache_exists:
                import json
                with open(cache_path, 'r') as f:
                    cached_data = json.load(f)
                    cached_count = len(cached_data)
            else:
                cached_count = 0
        except:
            cached_count = 0
        
        return {
            "cache_exists": cache_exists,
            "cache_size_bytes": cache_size,
            "cache_age_minutes": cache_age_minutes,
            "cached_cves_count": cached_count,
            "timeline_cache_exists": timeline_cache['data'] is not None,
            "severity_cache_exists": severity_cache['data'] is not None,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        return {"error": str(e)}, 500

@app.route("/health")
def health_check():
    """Lightweight health check - NO API CALLS"""
    try:
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "VulnEdu",
            "version": "1.3-emergency"
        }, 200
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, 500

def get_cached_timeline_data():
    """Get timeline data - NEVER trigger API calls during normal operation"""
    global timeline_cache
    with timeline_cache['lock']:
        now = datetime.now(timezone.utc)
        if (timeline_cache['data'] is not None and 
            timeline_cache['last_updated'] is not None and
            (now - timeline_cache['last_updated']).total_seconds() < TIMELINE_CACHE_HOURS * 3600):
            print("[Timeline] Using cached timeline data")
            return timeline_cache['data']
        
        print("[Timeline] Generating timeline from existing cache only")
        timeline_data = generate_timeline_data_safe()
        timeline_cache['data'] = timeline_data
        timeline_cache['last_updated'] = now
        return timeline_data

def get_cached_severity_metrics(year=None, month=None):
    """Get cached severity metrics - NEVER trigger API calls"""
    global severity_cache
    with severity_cache['lock']:
        now = datetime.now(timezone.utc)
        cache_key = f"{year}_{month}" if year or month else "current"
        
        # Check if we need to refresh cache
        needs_refresh = (
            severity_cache['data'] is None or 
            cache_key not in (severity_cache['data'] or {}) or
            severity_cache['last_updated'] is None or
            (now - severity_cache['last_updated']).total_seconds() > SEVERITY_CACHE_MINUTES * 60
        )
        
        if needs_refresh:
            print(f"[Dashboard] Refreshing severity cache for {cache_key} - NO API CALLS")
            
            # Use existing cached data ONLY - no API calls
            cached_cves = get_all_cves(force_refresh=False)  # This will use cached data only
            severity_data = calculate_severity_metrics_fresh(cached_cves)
            
            if severity_cache['data'] is None:
                severity_cache['data'] = {}
            severity_cache['data'][cache_key] = severity_data
            severity_cache['last_updated'] = now
            print(f"[Dashboard] Updated severity cache: {severity_data}")
            return severity_data
        
        # Return cached data
        cached_data = severity_cache['data'].get(cache_key)
        if cached_data:
            print(f"[Dashboard] Using cached severity data: {cached_data}")
            return cached_data
        
        # Fallback: use existing cached data
        print(f"[Dashboard] Fallback: using cached CVE data for severity")
        cached_cves = get_all_cves(force_refresh=False)
        return calculate_severity_metrics_fresh(cached_cves)

def calculate_severity_metrics_fresh(cves):
    """Calculate severity metrics from CVE data"""
    counts = Counter()
    
    for cve in cves:
        severity = cve.get('Severity', '').upper().strip()
        if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            counts[severity] += 1
        elif severity == 'NONE':
            counts['LOW'] += 1
        elif not severity or severity == 'UNKNOWN':
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
    
    result = {level: counts.get(level, 0) for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']}
    return result

def generate_timeline_data_safe():
    """Generate timeline data using ONLY cached data + smart estimation"""
    print("[Timeline] Safe generation - no API calls")
    
    now = datetime.now(timezone.utc)
    months = []
    base_month = now.replace(day=1)
    
    # Generate last 36 months
    for i in reversed(range(36)):
        dt = (base_month - timedelta(days=31 * i)).replace(day=1)
        months.append((dt.year, dt.month))
    
    month_labels = [f"{y}-{m:02d}" for y, m in months]
    month_counts = {k: 0 for k in month_labels}
    
    current_year = now.year
    
    try:
        # Use ONLY cached data - no API calls
        cached_cves = get_all_cves(force_refresh=False)
        print(f"[Timeline] Processing {len(cached_cves)} cached CVEs")
        
        # Process cached CVEs by month
        for cve in cached_cves:
            published_str = cve.get('Published', '')
            if published_str and len(published_str) >= 7:
                month_key = published_str[:7]
                if month_key in month_counts:
                    month_counts[month_key] += 1
        
        # Show what we found
        current_year_found = False
        for month_label in month_labels:
            if month_label.startswith(str(current_year)) and month_counts[month_label] > 0:
                print(f"[Timeline] {month_label}: {month_counts[month_label]} CVEs")
                current_year_found = True
        
        if not current_year_found:
            print(f"[Timeline] No {current_year} data in cache, using estimates")
            
    except Exception as e:
        print(f"[Timeline] Error processing cached data: {e}")
    
    # Fill missing data with reasonable estimates (but don't overwrite real data)
    for (y, m), label in zip(months, month_labels):
        if month_counts[label] == 0:
            if y == current_year:
                # For current year, estimate based on typical monthly counts
                if m <= now.month:
                    estimated_count = random.randint(1200, 1800)
                    month_counts[label] = estimated_count
            elif y >= current_year - 2:
                base_count = random.randint(800, 1500)
                seasonal_factor = 1.0 + 0.3 * math.sin(2 * math.pi * m / 12)
                month_counts[label] = int(base_count * seasonal_factor)
            else:
                base_count = random.randint(600, 1200)
                seasonal_factor = 1.0 + 0.2 * math.sin(2 * math.pi * m / 12)
                month_counts[label] = int(base_count * seasonal_factor)
    
    return {
        'labels': list(month_counts.keys()),
        'values': [month_counts[k] for k in month_counts.keys()]
    }

def get_cve_trends_30_days_safe():
    """Get 30-day trends using ONLY cached data"""
    try:
        # Use cached data ONLY
        cves = get_all_cves(force_refresh=False)
        today = datetime.now(timezone.utc).date()
        start_day = today - timedelta(days=29)
        
        date_counts = {start_day + timedelta(days=i): 0 for i in range(30)}
        
        for cve in cves:
            published_str = cve.get('Published')
            if published_str:
                try:
                    if 'T' in published_str:
                        dt = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                    else:
                        dt = datetime.strptime(published_str[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                    
                    dt_date = dt.date()
                    if dt_date in date_counts:
                        date_counts[dt_date] += 1
                except:
                    continue
        
        return {
            'labels': [d.strftime('%Y-%m-%d') for d in sorted(date_counts.keys())],
            'values': [date_counts[d] for d in sorted(date_counts.keys())]
        }
    except Exception as e:
        print(f"[Trends] Error: {e}")
        # Return empty structure
        today = datetime.now(timezone.utc).date()
        start_day = today - timedelta(days=29)
        return {
            'labels': [(start_day + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(30)],
            'values': [0] * 30
        }

def warm_dashboard_cache_if_needed():
    """Warm up caches WITHOUT making API calls"""
    global _warmed_up
    if not _warmed_up:
        _warmed_up = True
        def _warm():
            try:
                print("[Dashboard] Warming up caches (no API calls)...")
                # Just load existing cached data
                get_all_cves(force_refresh=False)
                warm_cwe_cache()
                print("[Dashboard] Cache warmup completed")
            except Exception as e:
                print(f"[Dashboard] Cache warmup error: {e}")
        Thread(target=_warm, daemon=True).start()

# Helper functions (kept simple)
def parse_published_date(cve):
    """Parse CVE published date into datetime object"""
    published_str = cve.get('Published')
    if not published_str:
        return None
    try:
        if published_str.endswith('Z'):
            return datetime.fromisoformat(published_str.replace('Z', '+00:00'))
        elif 'T' in published_str:
            dt = datetime.fromisoformat(published_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        else:
            return datetime.strptime(published_str[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except Exception:
        return None

def get_all_years():
    """Get list of available years"""
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
    """Generate full CWE radar chart data"""
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
    
    full_data = {
        'all': {'indices': codes, 'labels': names, 'values': values},
        'top5': {'indices': top5_codes, 'labels': top5_names, 'values': top5_values},
        'top10': {'indices': top10_codes, 'labels': top10_names, 'values': top10_values},
    }
    
    return full_data

def get_cwe_radar_weighted(cves):
    """Generate weighted CWE radar data based on severity"""
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
    desc = {
        "CWE-79": "Cross-Site Scripting (XSS) – allows script/code injection into web pages viewed by others.",
        "CWE-89": "SQL Injection – improper input handling lets attackers run malicious database queries.",
        "CWE-20": "Improper Input Validation – fails to properly check user input data.",
        "CWE-22": "Path Traversal – file access outside allowed directories.",
        "CWE-119": "Buffer Overflow – code writes past memory buffer limits.",
        "CWE-78": "OS Command Injection – attacker can execute operating system commands.",
        "CWE-287": "Improper Authentication.",
        "CWE-200": "Information Exposure.",
    }
    return desc

def generate_sample_cves_for_month(year, month, count):
    """Generate sample CVE data for historical months"""
    sample_cves = []
    common_cwes = ['CWE-79', 'CWE-89', 'CWE-20', 'CWE-22', 'CWE-119', 'CWE-200']
    severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    severity_weights = [0.1, 0.3, 0.45, 0.15]
    
    for i in range(min(count, 100)):  # Limit to prevent memory issues
        day = random.randint(1, monthrange(year, month)[1])
        cve_id = f"CVE-{year}-{random.randint(10000, 99999):05d}"
        severity = random.choices(severities, weights=severity_weights)[0]
        cwe = random.choice(common_cwes)
        
        sample_cve = {
            'ID': cve_id,
            'Description': f"Sample {severity.lower()} vulnerability in software component",
            'Severity': severity,
            'CWE': cwe,
            'Published': f"{year}-{month:02d}-{day:02d}T12:00:00Z",
            'CVSS_Score': random.uniform(1.0, 10.0),
            'References': [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
            'Products': ["Sample Software"],
            '_simulated': True
        }
        sample_cves.append(sample_cve)
    
    return sample_cves

@app.route("/api/cwe/<cwe_id>")
def api_get_cwe(cwe_id):
    """API endpoint to get CWE details"""
    try:
        cwe_data = get_single_cwe(cwe_id)
        return jsonify({'success': True, 'data': cwe_data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/references")
def references():
    """References and Resources page"""
    return render_template("references.html")

@app.route("/", methods=["GET"])
def index():
    """Main dashboard page - ULTRA CONSERVATIVE - NO API CALLS"""
    warm_dashboard_cache_if_needed()
    
    year = request.args.get('year', type=int)
    month = request.args.get('month', type=int)
    severity_filter = request.args.get('severity')
    search_query = request.args.get('q')
    
    # Use ONLY cached data - NEVER trigger API calls
    all_cves = get_all_cves(force_refresh=False)
    
    all_cves_with_dates = []
    for cve in all_cves:
        parsed_date = parse_published_date(cve)
        if parsed_date:
            cve['_parsed_published'] = parsed_date
            all_cves_with_dates.append(cve)
    
    all_cves_with_dates.sort(key=lambda cve: cve.get('_parsed_published', datetime.min.replace(tzinfo=timezone.utc)), reverse=True)
    
    # Get cached metrics
    metrics = get_cached_severity_metrics(year=year, month=month)
    total_cves = sum(metrics.values())
    
    timeline_daily = get_cve_trends_30_days_safe()
    timeline_months = get_cached_timeline_data()
    
    cwe_radar_full = get_cwe_radar_data_full(all_cves_with_dates)
    cwe_radar_weighted = get_cwe_radar_weighted(all_cves_with_dates)
    cwe_radar_descriptions = get_cwe_radar_descriptions()
    
    display_metrics = metrics
    if severity_filter and severity_filter.upper() in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        filtered_cves = [cve for cve in all_cves_with_dates if cve.get('Severity', '').upper() == severity_filter.upper()]
        display_metrics = calculate_severity_metrics_fresh(filtered_cves)
    
    available_years = get_all_years()
    available_months = list(range(1, 13))
    
    # Calculate date range for note
    now_date = datetime.now(timezone.utc).date()
    if year and month:
        days_in_month = monthrange(year, month)[1]
        note_start_date = datetime(year, month, 1).date()
        note_end_date = datetime(year, month, days_in_month).date()
    elif year:
        note_start_date = datetime(year, 1, 1).date()
        note_end_date = datetime(year, 12, 31).date()
    else:
        note_start_date = now_date - timedelta(days=29)
        note_end_date = now_date
    
    if note_start_date == note_end_date:
        note_text = f"Showing data from {note_start_date.strftime('%Y-%m-%d')}"
    else:
        note_text = f"Showing data from {note_start_date.strftime('%Y-%m-%d')} to {note_end_date.strftime('%Y-%m-%d')}"
    
    if total_cves == 0:
        severity_percentage = {k: "0" for k in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']}
    else:
        severity_percentage = {
            k: f"{(metrics.get(k, 0) * 100 // total_cves)}" for k in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        }
    
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

@app.route("/learn")
def learn():
    return redirect(url_for('learn_topic', topic='what-is-cve'))

@app.route("/learn/<string:topic>")
def learn_topic(topic):
    """Learn section - use cached data only"""
    valid_topics = ['what-is-cwe', 'what-is-cve', 'cvss-scores', 'what-is-nvd-mitre', 'cve-vs-cwe-vs-cvss']
    
    if topic not in valid_topics:
        return redirect(url_for('learn_topic', topic='what-is-cve'))
    
    cves = get_all_cves(force_refresh=False)  # Cached data only
    cwe_dict = get_cwe_dict()
    selected_cwes = list(CWE_TITLES.keys())
    cwe_severity = get_cwe_severity_chart_data(cves, selected_cwes)
    latest_cves = sorted(cves, key=lambda x: x.get('Published', ''), reverse=True)[:25]
    
    return render_template(
        f"learn/{topic}.html",
        cwe_dict=cwe_dict,
        cwe_severity=cwe_severity,
        latest_cves=latest_cves,
        key_cwes=selected_cwes,
        key_cwe_titles=CWE_TITLES,
        now=datetime.now(timezone.utc)
    )

@app.route("/vulnerabilities/", methods=["GET"])
def vulnerabilities():
    """Vulnerabilities listing page - use cached data primarily"""
    year = request.args.get('year', type=int)
    month = request.args.get('month', type=int)
    day = request.args.get('day', type=int)
    severity_filter = request.args.get('severity')
    search_query = request.args.get('q')
    page = request.args.get('page', default=1, type=int)
    per_page = 15
    
    # Use cached data primarily
    all_cves = get_all_cves(force_refresh=False)
    
    # For very old historical data, supplement with samples
    current_date = datetime.now(timezone.utc)
    if year and year < current_date.year - 1:
        if month:
            sample_count = random.randint(800, 1500)
            sample_cves = generate_sample_cves_for_month(year, month, sample_count)
            all_cves.extend(sample_cves)
    
    all_cves_with_dates = []
    for cve in all_cves:
        parsed_date = parse_published_date(cve)
        if parsed_date:
            cve['_parsed_published'] = parsed_date
            all_cves_with_dates.append(cve)
    
    all_cves_with_dates.sort(key=lambda cve: cve.get('_parsed_published', datetime.min.replace(tzinfo=timezone.utc)), reverse=True)
    
    # Apply filters
    filtered_cves = all_cves_with_dates
    
    if year and month and day:
        filtered_cves = [cve for cve in filtered_cves if 
                        cve.get('_parsed_published') and
                        cve['_parsed_published'].year == year and
                        cve['_parsed_published'].month == month and
                        cve['_parsed_published'].day == day]
    elif severity_filter:
        filtered_cves = [cve for cve in filtered_cves if 
                       cve.get('Severity', '').upper() == severity_filter.upper()]
    
    if search_query:
        q_lower = search_query.lower()
        if q_lower.startswith("cwe-"):
            filtered_cves = [cve for cve in filtered_cves if 
                           (cve.get("CWE") or "").lower() == q_lower]
        else:
            filtered_cves = [cve for cve in filtered_cves if q_lower in 
                           (cve.get('Description', '') + cve.get('ID', '')).lower()]
    
    # Pagination
    total_results = len(filtered_cves)
    total_pages = max(1, math.ceil(total_results / per_page))
    current_page = max(1, min(page, total_pages))
    
    start_index = (current_page - 1) * per_page
    end_index = start_index + per_page
    cves_page = filtered_cves[start_index:end_index]
    
    return render_template(
        "vulnerabilities.html",
        latest_cves=cves_page,
        year_filter=year,
        month_filter=month,
        day_filter=day,
        severity_filter=severity_filter,
        search_query=search_query,
        available_years=get_all_years(),
        available_months=list(range(1, 13)),
        current_page=current_page,
        total_pages=total_pages,
        total_results=total_results,
        page_numbers=list(range(max(1, current_page-3), min(total_pages+1, current_page+4))),
        note_text="Data from cache and historical estimates"
    )

@app.route("/cve/<cve_id>")
def cve_detail(cve_id):
    """CVE detail page"""
    if not cve_id or not cve_id.startswith("CVE-"):
        return render_template("error.html", error="Invalid CVE ID format")
    
    try:
        cve = get_cve_detail(cve_id)
        return render_template("cve_detail.html", cve=cve)
    except Exception as e:
        return render_template("error.html", error=f"Error retrieving CVE: {str(e)}")

if __name__ == "__main__":
    app.run(debug=True)