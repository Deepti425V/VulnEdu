# Type hints for function parameters and return structures
from typing import Dict, List, Any
# Date/time operations for temporal analysis and filtering
from datetime import datetime, timezone, timedelta
# Dictionary with automatic default value initialization for counting
from collections import defaultdict
# API client service for recent vulnerability data
from services.data.api_client import api_client

def get_cve_trends_last_30_days() -> Dict[str, Any]:
    """Get CVE trends for last 30 days – API ONLY"""
    print("[CVE Trends] Fetching 30-day trends from API...")
    # Get recent vulnerability data from API
    cves = api_client.get_cves_last_30_days()

    # Initialize daily counting structure with automatic zero defaults
    daily_counts = defaultdict(int)
    today = datetime.now(timezone.utc).date()

    # Pre-fill last 30 days with zero counts for complete timeline
    for i in range(30):
        day = today - timedelta(days=29-i)  # Count backwards from today
        daily_counts[day.strftime('%Y-%m-%d')] = 0

    # Process each CVE to count by publication date
    for cve in cves:
        pub_date = cve.get('Published', '')
        if pub_date:
            try:
                # Handle different date formats from API
                if 'T' in pub_date:
                    # ISO format: 2023-01-15T10:30:00Z
                    dt = datetime.fromisoformat(pub_date.replace('Z', '+0000'))
                else:
                    # Simple format: 2023-01-15
                    dt = datetime.strptime(pub_date[:10], '%Y-%m-%d')
                # Convert to date key and count if within our 30-day window
                date_key = dt.date().strftime('%Y-%m-%d')
                if date_key in daily_counts:
                    daily_counts[date_key] += 1
            except:
                # Skip CVEs with unparseable dates
                continue

    # Build chart-ready data structure with chronological ordering
    sorted_dates = sorted(daily_counts.keys())
    result = {
        'labels': sorted_dates,  # X-axis labels for chart
        'values': [daily_counts[date] for date in sorted_dates],  # Y-axis values
        'total_cves': len(cves),
        'date_range': {
            'start': sorted_dates[0] if sorted_dates else '',
            'end': sorted_dates[-1] if sorted_dates else ''
        }
    }

    print(f"[CVE Trends] Generated trends: {result['total_cves']} CVEs over {len(sorted_dates)} days")
    return result

def get_vulnerabilities_over_time_last_5_years() -> Dict[str, Any]:
    """Get vulnerability timeline for last 5 years – HISTORICAL DATA ONLY"""
    print("[Vulnerabilities Over Time] Loading last 5 years historical data...")
    # Lazy import to avoid circular dependencies
    from services.data.data_processor import historical_loader
    historical_data = historical_loader.get_last_5_years_data()

    # Initialize monthly counting structure
    monthly_counts = defaultdict(int)
    total_cves = 0

    # Process each year of historical data
    for year_str, year_cves in historical_data.items():
        print(f"[Vulnerabilities Over Time] Processing {year_str}: {len(year_cves)} CVEs")
        total_cves += len(year_cves)
        # Process each CVE in the year
        for cve in year_cves:
            pub_date = cve.get('Published', '')
            if pub_date:
                try:
                    # Handle different date formats from historical sources
                    if 'T' in pub_date:
                        # ISO format: 2021-04-15T00:00:00.000Z
                        dt = datetime.fromisoformat(pub_date.replace('Z', '+0000'))
                    else:
                        # Simple format: 2021-04-15
                        dt = datetime.strptime(pub_date[:10], '%Y-%m-%d')
                    # Group by year-month for appropriate granularity
                    month_key = dt.strftime('%Y-%m')
                    monthly_counts[month_key] += 1
                except Exception as e:
                    print(f"[Vulnerabilities Over Time] Error parsing date {pub_date}: {e}")
                    continue

    # Sort chronologically and build chart-ready structure
    sorted_months = sorted(monthly_counts.items())
    result = {
        'labels': [item[0] for item in sorted_months],  # Month labels
        'values': [item[1] for item in sorted_months],  # CVE counts per month
        'total_cves': total_cves,
        'months_covered': len(sorted_months),
        'raw_data': dict(monthly_counts)  # For debugging and verification
    }

    print(f"[Vulnerabilities Over Time] Generated timeline: {result['total_cves']} CVEs across {result['months_covered']} months")
    return result

def get_filtered_historical_cves(year: int = None, month: int = None, day: int = None) -> List[Dict[str, Any]]:
    """Get filtered CVEs from historical data - FIXED FILTERING LOGIC"""
    print(f"[Historical Filter] Getting filtered data for year={year}, month={month}, day={day}")

    # Year is required for historical filtering
    if not year:
        print("[Historical Filter] No year specified, returning empty list")
        return []

    # Lazy import to avoid circular dependencies
    from services.data.data_processor import historical_loader

    # Load specific year data for efficient filtering
    year_cves = historical_loader.get_year_data(year)
    print(f"[Historical Filter] Loaded {len(year_cves)} CVEs for year {year}")

    # If no month specified, return all CVEs for the year
    if not month:
        print(f"[Historical Filter] No month filter, returning all {len(year_cves)} CVEs for {year}")
        return year_cves

    # Apply hierarchical filtering: year → month → day
    filtered_cves = []
    for cve in year_cves:
        pub_date = cve.get('Published', '')
        if pub_date:
            try:
                # Handle different date formats consistently
                if 'T' in pub_date:
                    # ISO format: 2019-04-15T00:00:00.000Z
                    dt = datetime.fromisoformat(pub_date.replace('Z', '+0000'))
                else:
                    # Simple format: 2019-04-15
                    dt = datetime.strptime(pub_date[:10], '%Y-%m-%d')

                # CRITICAL: Check BOTH year and month for proper filtering
                if dt.year == year and dt.month == month:
                    # If day is specified, check day too
                    if day is None or dt.day == day:
                        filtered_cves.append(cve)
                        print(f"[Historical Filter] Match: CVE {cve.get('ID', 'Unknown')} from {dt.strftime('%Y-%m-%d')}")

            except Exception as e:
                print(f"[Historical Filter] Error parsing date {pub_date}: {e}")
                continue

    print(f"[Historical Filter] Filtered result: {len(filtered_cves)} CVEs for {year}-{month:02d}" + (f"-{day:02d}" if day else ""))

    # Debug: Show sample of filtered results for verification
    if filtered_cves:
        sample_count = min(3, len(filtered_cves))
        print(f"[Historical Filter] Sample of filtered CVEs:")
        for i in range(sample_count):
            cve = filtered_cves[i]
            print(f"  - {cve.get('ID', 'Unknown')}: {cve.get('Published', 'No date')}")

    return filtered_cves
