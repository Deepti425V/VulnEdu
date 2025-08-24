# group_CVE.py (CHANGES MADE)

# Efficient counting and auto-initializing dictionary utilities
from collections import Counter, defaultdict
# Date/time operations for current year calculation
from datetime import datetime

def group_by_severity(cves):
    """
    Count up all CVEs by severity (CRITICAL, HIGH, MEDIUM, LOW).
    Return a dict ready for dashboard charts.
    """
    # Use Counter for efficient frequency counting
    counts = Counter()
    
    for cve in cves:
        # Extract and normalize severity level (handle case inconsistencies)
        sev = cve.get("Severity", "UNKNOWN").upper()
        counts[sev] += 1
    
    # Only pick canonical severity keys; drop weird stuff from the API
    # This ensures consistent chart structure even with API variations
    return {k: counts.get(k, 0) for k in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']}

def group_by_cwe(cves):
    """
    Counts the number of CVEs per CWE ID.
    Lets us show "top weaknesses" or run radar/bar charts.
    """
    # defaultdict automatically initializes new keys to 0
    counts = defaultdict(int)
    
    for cve in cves:
        cwe = cve.get("CWE")
        if cwe:  # Only count CVEs that have CWE classification
            counts[cwe] += 1
    
    # Convert to regular dict for JSON serialization compatibility
    return dict(counts)

def timeline_group(cves):
    """
    Sorts CVEs by published month (YYYY-MM), counts them.
    Used for timeline graphs. Handles weird/missing dates gracefully!
    """
    # Auto-initializing counter for monthly aggregation
    timeline = defaultdict(int)
    
    for cve in cves:
        date = cve.get("Published", "")
        if date:
            try:
                # Extract "YYYY-MM" from date string (fast string operation)
                month = date[:7]  # "YYYY-MM"
                timeline[month] += 1
            except:
                # Skip malformed dates silently to prevent crashes
                continue
    
    # Sort months chronologically for proper timeline display
    sorted_months = sorted(timeline.items())
    
    # Separate labels and values for chart library compatibility
    labels = [item[0] for item in sorted_months]
    values = [item[1] for item in sorted_months]
    
    # Return chart-ready format
    return {"labels": labels, "values": values}

def top_n_cwes(cwe_counts, n=7):
    """Find the top N CWEs (by count). Used for leaderboards/bar charts."""
    # Sort CWE IDs by their frequency counts (highest first)
    return sorted(cwe_counts, key=cwe_counts.get, reverse=True)[:n]

def yearly_trends(cves):
    """
    Count how many CVEs were published in each of the last 5 years.
    Used for yearly trend graphs.
    """
    # Get current year for dynamic 5-year window
    current_year = datetime.now().year
    
    # Pre-initialize counters for last 5 years (including current)
    year_counts = {year: 0 for year in range(current_year - 4, current_year + 1)}
    
    for cve in cves:
        published = cve.get('Published', '')
        if published:
            try:
                # Extract year from date string (simple string parsing)
                year = int(published[:4])
                
                # Only count years within our 5-year window
                if year in year_counts:
                    year_counts[year] += 1
            except ValueError:
                # Skip dates that can't be parsed as integers
                continue
    
    return year_counts