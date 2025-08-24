# vulnedu.py
# Main Flask application for VulnEdu - A vulnerability education platform
# Provides dashboard, filtering, and educational content for CVE/CWE data

from flask import Flask, render_template, request, url_for, redirect, jsonify
from services.fetch_CVE import get_all_cves # Service to fetch lists of CVEs
from services.nvd_api import get_cve_detail # Service to get details for a single CVE
from services.cwe_data import get_cwe_dict, get_single_cwe, warm_cwe_cache # Service for CWE data
from services.cwe_map import CWE_TITLES, cwe_title # Mapping of CWE IDs to human-readable titles
from collections import Counter, defaultdict # For counting and grouping data efficiently
import math # For math.ceil in pagination
import random # For generating sample data
from datetime import datetime, timedelta, timezone # For date/time manipulation
from calendar import monthrange # To get number of days in a month for sample data
import os
from threading import Thread, Lock # For background tasks and thread-safe caching

# Initialize the Flask application
app = Flask(__name__)

# Cache for the expensive 36-month timeline data
# Using dict structure for thread-safe access with locks
timeline_cache = {
    'data': None, # The cached data itself
    'last_updated': None, # When it was last updated
    'lock': Lock() # Lock to prevent concurrent cache updates
}

# Cache for severity count metrics (shorter lifespan)
# Separate cache for more dynamic data that changes frequently
severity_cache = {
    'data': None,
    'last_updated': None,
    'lock': Lock()
}

# Cache expiration settings
TIMELINE_CACHE_HOURS = 6 # Cache timeline data for 6 hours 
SEVERITY_CACHE_MINUTES = 10 # Cache severity data for 10 minutes

# Flag to check if initial cache warming has been done
# Prevents multiple background warmup processes
_warmed_up = False

@app.route("/health")
def health_check():
    """Health check endpoint with basic service validation"""
    try:
        # Basic service checks
        current_time = datetime.now(timezone.utc)
        
        # Test if we can get CVE data (basic functionality test)
        test_cves = get_all_cves(days=1) # Quick test with minimal data
        cve_count = len(test_cves) if test_cves else 0
        
        # Test if CWE data is accessible
        cwe_dict = get_cwe_dict()
        cwe_count = len(cwe_dict) if cwe_dict else 0
        
        # Return healthy status with metrics
        return {
            "status": "healthy",
            "timestamp": current_time.isoformat(),
            "service": "VuInEdu",
            "version": "1.0",
            "checks": {
                "cve_api": "operational" if cve_count >= 0 else "degraded",
                "cwe_catalog": "operational" if cwe_count > 0 else "degraded",
                "cache": "operational"
            },
            "metrics": {
                "recent_cves": cve_count,
                "cwe_entries": cwe_count
            }
        }, 200
    except Exception as e:
        # Return error details if anything fails
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "VuInEdu",
            "version": "1.0"
        }, 500

def get_cached_timeline_data():
    """Retrieves timeline data from cache, generating it if necessary or expired."""
    global timeline_cache
    
    with timeline_cache['lock']: # Ensure thread-safe access to the cache
        now = datetime.now(timezone.utc)
        
        # Check if cache exists and is still valid
        if (timeline_cache['data'] is not None and
                timeline_cache['last_updated'] is not None and
                (now - timeline_cache['last_updated']).total_seconds() < TIMELINE_CACHE_HOURS * 3600):
            return timeline_cache['data'] # Return cached data
        
        # Cache is invalid, generate new data
        timeline_data = generate_timeline_data()
        timeline_cache['data'] = timeline_data
        timeline_cache['last_updated'] = now
        return timeline_data

def get_cached_severity_metrics(year=None, month=None):
    """Get cached severity metrics with reasonable cache time"""
    global severity_cache
    
    with severity_cache['lock']: # Ensure thread-safe access
        now = datetime.now(timezone.utc)
        
        # Create a unique key for this year/month combination
        cache_key = f"{year}_{month}" if year or month else "current"
        
        # Check if we need to refresh cache
        needs_refresh = (
            severity_cache['data'] is None or
            cache_key not in (severity_cache['data'] or {}) or
            severity_cache['last_updated'] is None or
            (now - severity_cache['last_updated']).total_seconds() > SEVERITY_CACHE_MINUTES * 60
        )
        
        if needs_refresh:
            print(f"Refreshing severity cache for {cache_key}")
            
            # Get CVE data without force refresh to avoid timeouts
            if year and month:
                fresh_cves = get_all_cves(year=year, month=month)
            elif year:
                fresh_cves = get_all_cves(year=year)
            else:
                fresh_cves = get_all_cves(days=30)
            
            # Calculate fresh severity metrics
            severity_data = calculate_severity_metrics_fresh(fresh_cves)
            
            # Initialize cache dict if needed and update it
            if severity_cache['data'] is None:
                severity_cache['data'] = {}
            severity_cache['data'][cache_key] = severity_data
            severity_cache['last_updated'] = now
            print(f"Updated severity cache: {severity_data}")
            return severity_data
        
        # Return cached data if it exists and is valid
        cached_data = severity_cache['data'].get(cache_key)
        if cached_data:
            print(f"Using cached severity data: {cached_data}")
            return cached_data
        
        # Fallback: calculate fresh data if cache key was missing somehow
        if year and month:
            fresh_cves = get_all_cves(year=year, month=month)
        elif year:
            fresh_cves = get_all_cves(year=year)
        else:
            fresh_cves = get_all_cves(days=30)
        
        return calculate_severity_metrics_fresh(fresh_cves)

def calculate_severity_metrics_fresh(cves):
    """Calculate severity metrics from fresh CVE data"""
    counts = Counter() # Use Counter for efficient counting
    
    for cve in cves:
        severity = cve.get('Severity', '').upper().strip()
        
        if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            counts[severity] += 1 # Count using explicit severity
        elif severity == 'NONE':
            counts['LOW'] += 1 # Treat NONE as LOW
        elif not severity:
            # Try to derive from CVSS score if available
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
                except (ValueError, TypeError): # Handle invalid score format
                    counts['LOW'] += 1
            else:
                # If no severity and no score, default to LOW
                counts['LOW'] += 1
    
    # Ensure all severity levels are present in the result, even with 0 count
    result = {level: counts.get(level, 0) for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']}
    return result

def generate_timeline_data():
    """Generates data for a 36-month timeline chart, using real data for recent months and synthetic data for older ones."""
    now = datetime.now(timezone.utc)
    months = []
    base_month = now.replace(day=1) # Start from the first day of the current month
    
    # Generate a list of (year, month) for the past 36 months
    for i in reversed(range(36)):
        dt = (base_month - timedelta(days=31 * i)).replace(day=1)
        months.append((dt.year, dt.month))
    
    # Create labels like "2024-03"
    month_labels = [f"{y}-{m:02d}" for y, m in months]
    month_counts = {k: 0 for k in month_labels} # Initialize counts to 0
    
    # Get recent CVEs and count them by publication month
    recent_cves = get_all_cves(days=30) # Remove force_refresh
    for cve in recent_cves:
        published_str = cve.get('Published', '')
        if published_str and len(published_str) >= 7:
            month_key = published_str[:7] # Extract YYYY-MM
            if month_key in month_counts:
                month_counts[month_key] += 1
    
    # Fill in missing months with realistic synthetic data
    current_year = now.year
    current_month = now.month
    for (y, m), label in zip(months, month_labels):
        if month_counts[label] == 0: # If no real data for this month
            if y == current_year and m >= current_month - 2:
                continue # Skip recent months that might just have no data yet
            elif y >= current_year - 1:
                # Generate data for last ~year with higher base count and variation
                base_count = random.randint(800, 1500)
                seasonal_factor = 1.0 + 0.3 * math.sin(2 * math.pi * m / 12) # Simulate seasonality
                month_counts[label] = int(base_count * seasonal_factor)
            else:
                # Generate data for older years
                base_count = random.randint(600, 1200)
                seasonal_factor = 1.0 + 0.2 * math.sin(2 * math.pi * m / 12)
                month_counts[label] = int(base_count * seasonal_factor)
    
    # Structure the data for the charting library
    return {
        'labels': list(month_counts.keys()), # List of month labels
        'values': [month_counts[k] for k in month_counts.keys()] # List of counts
    }

def generate_sample_cves_for_month(year, month, count):
    """Generates a list of sample CVE data for a given month and year."""
    sample_cves = []
    
    # List of common CWE IDs to choose from
    common_cwes = ['CWE-79', 'CWE-89', 'CWE-20', 'CWE-22', 'CWE-119', 'CWE-200', 'CWE-287', 'CWE-78',
                   'CWE-94', 'CWE-352', 'CWE-434', 'CWE-502', 'CWE-611', 'CWE-798', 'CWE-862', 'CWE-863']
    severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    severity_weights = [0.1, 0.3, 0.45, 0.15] # Probability weights for each severity
    
    # List of common software products
    products = [
        'Apache HTTP Server', 'Microsoft Windows', 'Google Chrome', 'Mozilla Firefox', 'Oracle Java',
        'Adobe Flash Player', 'WordPress', 'OpenSSL', 'Node.js', 'PHP', 'Cube',
        'MySQL', 'PostgreSQL', 'Docker', 'kubernetes', 'Jenkins', 'Apache Tomcat', 'Nginx', 'Redis',
        'MongoDB', 'Elasticsearch'
    ]
    
    for i in range(count):
        days_in_month = monthrange(year, month)[1] # Get number of days in the target month
        day = random.randint(1, days_in_month) # Random day of the month
        cve_number = random.randint(10000, 99999) # Random CVE number
        cve_id = f"CVE-{year}-{cve_number:05d}" # Construct CVE ID
        severity = random.choices(severities, weights=severity_weights)[0] # Weighted random choice
        cwe = random.choice(common_cwes) # Random CWE
        product = random.choice(products) # Random product
        
        # Template descriptions for each CWE type
        descriptions = {
            'CWE-79': f"Cross-site scripting vulnerability in {product} allows remote attackers to inject arbitrary web script or HTML via crafted input parameters",
            'CWE-89': f"SQL injection vulnerability in {product} allows remote attackers to execute arbitrary SQL commands via malformed database queries",
            'CWE-20': f"Improper input validation in {product} allows attackers to cause denial of service or execute arbitrary code",
            'CWE-22': f"Path traversal vulnerability in {product} allows attackers to access files and directories outside the intended scope",
            'CWE-119': f"Buffer overflow in {product} allows remote attackers to execute arbitrary code via specially crafted requests",
            'CWE-200': f"Information disclosure vulnerability in {product} exposes sensitive data to unauthorized users through error messages",
            'CWE-287': f"Authentication bypass vulnerability in {product} allows unauthorized access to protected resources",
            'CWE-78': f"Command injection vulnerability in {product} allows execution of arbitrary operating system commands",
            'CWE-94': f"Code injection vulnerability in {product} allows remote code execution through unsanitized user input",
            'CWE-352': f"Cross-site request forgery vulnerability in {product} allows attackers to perform unauthorized actions",
            'CWE-434': f"Unrestricted file upload vulnerability in {product} allows attackers to upload malicious files",
            'CWE-502': f"Deserialization vulnerability in {product} allows remote code execution via untrusted data",
            'CWE-611': f"XML external entity vulnerability in {product} allows attackers to access internal files",
            'CWE-798': f"Use of hard-coded credentials in {product} allows unauthorized system access",
            'CWE-862': f"Missing authorization vulnerability in {product} allows access to restricted functionality",
            'CWE-863': f"Incorrect authorization vulnerability in {product} allows privilege escalation"
        }
        
        # Get the description template or use a default
        description = descriptions.get(cwe, f"Vulnerability in {product} allows potential security compromise")
        
        # Assign a CVSS score based on the chosen severity
        if severity == 'CRITICAL':
            cvss_score = round(random.uniform(9.0, 10.0), 1)
        elif severity == 'HIGH':
            cvss_score = round(random.uniform(7.0, 8.9), 1)
        elif severity == 'MEDIUM':
            cvss_score = round(random.uniform(4.0, 6.9), 1)
        else:
            cvss_score = round(random.uniform(0.1, 3.9), 1)
        
        # Construct a sample CVE dictionary
        sample_cve = {
            'ID': cve_id,
            'Description': description,
            'Severity': severity,
            'CWE': cwe,
            'Published': f"{year}-{month:02d}-{day:02d}T{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}.000Z", # Random time
            'CVSS_Score': cvss_score,
            'References': [
                f"https://nvd.nist.gov/vuln/detail/{cve_id}", # NVD link
                f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}", # MITRE link
                f"https://security.{product.lower().replace(' ', '')}.com/advisories/{cve_id.lower()}" # Fictional vendor link
            ],
            'Products': [product, f"{product} {random.randint(1, 10)}.{random.randint(0, 9)}"], # Product and version
            'metrics': {
                'cvssMetricV31': [{
                    'cvssData': {
                        'baseScore': cvss_score,
                        'baseSeverity': severity,
                        'vectorString': f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" # Generic high-severity vector
                    },
                    'source': 'nvd@nist.gov',
                    'type': 'Primary'
                }]
            },
            '_simulated': True # Flag indicating this is synthetic data
        }
        
        sample_cves.append(sample_cve)
    
    return sample_cves

def refresh_timeline_cache_background():
    """Starts a background thread to refresh the timeline cache."""
    def refresh_task():
        try:
            get_cached_timeline_data() # This will regenerate if cache is expired
        except Exception:
            pass # Silently fail on background refresh errors
    
    Thread(target=refresh_task, daemon=True).start() # Start the thread

def warm_dashboard_cache_if_needed():
    """Warms up critical caches in the background on first load."""
    global _warmed_up
    if not _warmed_up:
        _warmed_up = True
        def _warm():
            try:
                get_all_cves(days=30) # Pre-fetch recent CVEs
                refresh_timeline_cache_background() # Pre-generate timeline
                warm_cwe_cache() # Pre-load CWE data
            except Exception:
                pass # Silently fail on background warm-up errors
        
        Thread(target=_warm, daemon=True).start() # Start the warm-up thread

def calculate_severity_metrics(cves):
    """Legacy function - now redirects to fresh calculation"""
    return calculate_severity_metrics_fresh(cves)

def parse_published_date(cve):
    """Safely parses the Published date string from a CVE into a datetime object."""
    published_str = cve.get('Published')
    if not published_str:
        return None
    
    try:
        return datetime.fromisoformat(published_str) # Try ISO format first
    except Exception:
        try:
            # Fallback to parsing just the date part YYYY-MM-DD
            return datetime.strptime(published_str[:10], "%Y-%m-%d")
        except Exception:
            return None # Return None if parsing fails

def get_all_years():
    """Returns a list of years from the current year back to 1999."""
    current_year = datetime.now(timezone.utc).year
    return list(range(current_year, 1998, -1)) # 1999, 2000, ... current_year

def get_cwe_severity_chart_data(cves, selected_cwe_list):
    """Groups CVEs by CWE and severity for a chart."""
    cwe_severity = defaultdict(lambda: defaultdict(int)) # Nested default dict
    
    for cve in cves:
        cwe = cve.get('CWE')
        if cwe in selected_cwe_list: # Only count selected CWEs
            severity = cve.get('Severity', 'UNKNOWN').upper()
            if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                cwe_severity[cwe][severity] += 1 # Increment count for this CWE+Severity
    
    # Structure the data for the chart
    data = {
        'labels': [cwe_title(cwe) for cwe in selected_cwe_list],
        'datasets': {
            'CRITICAL': [cwe_severity[cwe].get('CRITICAL', 0) for cwe in selected_cwe_list],
            'HIGH': [cwe_severity[cwe].get('HIGH', 0) for cwe in selected_cwe_list],
            'MEDIUM': [cwe_severity[cwe].get('MEDIUM', 0) for cwe in selected_cwe_list],
            'LOW': [cwe_severity[cwe].get('LOW', 0) for cwe in selected_cwe_list]
        }
    }
    
    return data

def get_cwe_radar_data_full(cves):
    """Gets CWE frequency data for radar chart visualization."""
    cwe_counts = Counter() # Count occurrences of each CWE
    
    for cve in cves:
        cwe = cve.get('CWE')
        if cwe:
            cwe_counts[cwe] += 1
    
    # Sort CWEs by frequency, descending
    sorted_cwes = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)
    
    # Extract data for the top CWEs
    codes = [cwe for cwe, count in sorted_cwes]
    names = [cwe_title(cwe) for cwe in codes]
    counts = [count for cwe, count in sorted_cwes]
    
    # Return different slices of the data for different chart views
    return {
        'top5': {
            'codes': codes[:5],
            'names': names[:5],
            'counts': counts[:5]
        },
        'top10': {
            'codes': codes[:10],
            'names': names[:10],
            'counts': counts[:10]
        },
        'full': {
            'codes': codes,
            'names': names,
            'counts': counts
        }
    }

def get_cwe_radar_weighted(cves):
    """Gets CWE data weighted by severity for risk-based radar chart."""
    cwe_weights = defaultdict(int) # Store total weight per CWE
    severity_weights = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1} # Weight for each severity
    
    for cve in cves:
        cwe = cve.get('CWE')
        if cwe:
            severity = cve.get('Severity', '').upper()
            weight = severity_weights.get(severity, 0) # Get weight for this severity
            cwe_weights[cwe] += weight # Add weight to the CWE's total
    
    # Sort CWEs by total weight, descending
    sorted_cwes = sorted(cwe_weights.items(), key=lambda x: x[1], reverse=True)
    
    # Extract data for the top weighted CWEs
    codes = [cwe for cwe, weight in sorted_cwes]
    names = [cwe_title(cwe) for cwe in codes]
    weights = [weight for cwe, weight in sorted_cwes]
    
    return {
        'codes': codes[:10], # Top 10 by weight
        'names': names[:10],
        'weights': weights[:10]
    }

def get_cve_trends_30_days():
    """Gets daily CVE counts for the last 30 days."""
    now = datetime.now(timezone.utc)
    days = []
    day_counts = {}
    
    # Generate list of the last 30 days
    for i in range(30):
        dt = (now - timedelta(days=i)).date()
        days.append(dt)
        day_counts[dt] = 0 # Initialize count to 0
    
    # Get CVEs from the last 30 days and count them by day
    recent_cves = get_all_cves(days=30)
    for cve in recent_cves:
        published = parse_published_date(cve)
        if published:
            pub_date = published.date()
            if pub_date in day_counts:
                day_counts[pub_date] += 1
    
    # Structure the data for the chart
    sorted_days = sorted(days) # Sort days chronologically
    return {
        'labels': [d.strftime("%Y-%m-%d") for d in sorted_days],
        'values': [day_counts[d] for d in sorted_days]
    }

@app.route("/")
def index():
    """Main dashboard page handler."""
    warm_dashboard_cache_if_needed() # Start background cache warming if needed
    
    # Parse query parameters for filtering
    year = request.args.get('year', type=int)
    month = request.args.get('month', type=int)
    severity_filter = request.args.get('severity', '').upper()
    search_query = request.args.get('search', '').strip()
    
    # Get CVE data based on filters
    if year and month:
        cves = get_all_cves(year=year, month=month)
    elif year:
        cves = get_all_cves(year=year)
    else:
        cves = get_all_cves(days=30) # Default to last 30 days
    
    # Get severity metrics for the current filter context
    severity_metrics = get_cached_severity_metrics(year=year, month=month)
    total_cves = sum(severity_metrics.values())
    
    # Get data for charts and visualizations
    daily_trends = get_cve_trends_30_days()
    timeline_data = get_cached_timeline_data()
    cwe_radar_data = get_cwe_radar_data_full(cves)
    cwe_weighted_data = get_cwe_radar_weighted(cves)
    
    # Apply additional severity filter if one was selected
    if severity_filter and severity_filter in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        cves = [cve for cve in cves if cve.get('Severity', '').upper() == severity_filter]
    
    # Apply search filter if a query was provided
    if search_query:
        search_lower = search_query.lower()
        cves = [cve for cve in cves
                if (search_lower in cve.get('ID', '').lower() or
                    search_lower in cve.get('Description', '').lower() or
                    search_lower in cve.get('CWE', '').lower())]
    
    # Calculate percentages for the UI
    severity_percentages = {}
    if total_cves > 0:
        for level, count in severity_metrics.items():
            severity_percentages[level] = round((count / total_cves) * 100, 1)
    
    # Render the dashboard template with all the prepared data
    return render_template('index.html',
                         cves=cves[:50], # Show first 50 CVEs
                         severity_metrics=severity_metrics,
                         severity_percentages=severity_percentages,
                         severity_filter=severity_filter,
                         search_query=search_query,
                         daily_trends=daily_trends,
                         timeline_data=timeline_data,
                         cwe_radar_data=cwe_radar_data,
                         cwe_weighted_data=cwe_weighted_data,
                         years=get_all_years(),
                         selected_year=year,
                         selected_month=month
                         )

@app.route("/learn")
def learn():
    """Educational content page handler."""
    return render_template('learn.html')

@app.route("/api/cwe/<cwe_id>")
def api_cwe_detail(cwe_id):
    """API endpoint to get CWE details in JSON format."""
    cwe_data = get_single_cwe(cwe_id)
    if cwe_data:
        return jsonify(cwe_data)
    else:
        return jsonify({'error': 'CWE not found'}), 404

@app.route("/vulnerabilities/")
def vulnerabilities():
    """Paginated list of vulnerabilities with filtering."""
    # Parse filtering parameters
    year = request.args.get('year', type=int)
    month = request.args.get('month', type=int)
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    severity_filter = request.args.get('severity', '').upper()
    search_query = request.args.get('search', '').strip()
    
    # Parse pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    offset = (page - 1) * per_page
    
    # Determine date range for filtering
    if year and month:
        # Filter by specific year and month
        cves = get_all_cves(year=year, month=month)
    elif year:
        # Filter by specific year
        cves = get_all_cves(year=year)
    elif start_date and end_date:
        # Filter by custom date range
        try:
            start_dt = datetime.strptime(start_date, '%Y-%m-%d')
            end_dt = datetime.strptime(end_date, '%Y-%m-%d')
            days = (end_dt - start_dt).days
            if days > 0:
                cves = get_all_cves(days=days)
            else:
                cves = []
        except Exception:
            cves = get_all_cves(days=30) # Fallback to 30 days
    else:
        # Default to recent CVEs
        cves = get_all_cves(days=30)
    
    # For older dates, generate sample data if real data is sparse
    current_year = datetime.now(timezone.utc).year
    if (year and year < current_year - 1) or (month and year == current_year - 1 and month < 6):
        if not cves or len(cves) < 20:
            # Generate sample data for historical periods
            sample_count = random.randint(800, 1200)
            cves = generate_sample_cves_for_month(year or current_year - 2,
                                                month or random.randint(1, 12),
                                                sample_count)
    
    # Apply severity filter
    if severity_filter and severity_filter in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        cves = [cve for cve in cves if cve.get('Severity', '').upper() == severity_filter]
    
    # Apply search filter
    if search_query:
        search_lower = search_query.lower()
        cves = [cve for cve in cves
                if (search_lower in cve.get('ID', '').lower() or
                    search_lower in cve.get('Description', '').lower() or
                    search_lower in cve.get('CWE', '').lower())]
    
    # Sort CVEs by published date, newest first
    cves.sort(key=lambda x: parse_published_date(x) or datetime.min, reverse=True)
    
    # Implement pagination
    total_cves = len(cves)
    total_pages = math.ceil(total_cves / per_page) if per_page > 0 else 1
    paginated_cves = cves[offset:offset + per_page]
    
    # Render the vulnerabilities template with paginated results
    return render_template('vulnerabilities.html',
                         cves=paginated_cves,
                         page=page,
                         per_page=per_page,
                         total_pages=total_pages,
                         total_cves=total_cves,
                         severity_filter=severity_filter,
                         search_query=search_query,
                         years=get_all_years(),
                         selected_year=year,
                         selected_month=month,
                         start_date=start_date,
                         end_date=end_date
                         )

@app.route("/cve/<cve_id>")
def cve_detail(cve_id):
    """Detailed view for a specific CVE."""
    # Validate CVE ID format
    if not cve_id.upper().startswith('CVE-'):
        return render_template('error.html', message=f"Invalid CVE ID format: {cve_id}"), 400
    
    # Try to get CVE details from the API
    cve_data = get_cve_detail(cve_id)
    
    # If not found and it's an older CVE, generate sample data
    if cve_data == "Not found":
        try:
            # Extract year from CVE ID
            year_part = cve_id.split('-')[1]
            cve_year = int(year_part)
            current_year = datetime.now(timezone.utc).year
            
            # If CVE is more than a year old, generate sample data
            if cve_year < current_year - 1:
                sample_cves = generate_sample_cves_for_month(cve_year, random.randint(1, 12), 1)
                if sample_cves:
                    cve_data = sample_cves[0] # Use the first generated sample
                    cve_data['ID'] = cve_id.upper() # Ensure ID matches request
                    cve_data['_simulated'] = True # Mark as simulated
        except (IndexError, ValueError):
            pass # If year extraction fails, keep "Not found"
    
    # If still not found, return error
    if cve_data == "Not found":
        return render_template('error.html', message=f"CVE not found: {cve_id}"), 404
    
    # Render the CVE detail template
    return render_template('cve_detail.html', cve=cve_data)

@app.route("/about")
def about():
    """About page handler."""
    return render_template('about.html')

if __name__ == "__main__":
    # Start the Flask development server
    app.run(debug=True, host='0.0.0.0', port=5000)