from typing import Dict, List, Any
from datetime import datetime, timezone, timedelta
from collections import defaultdict

def get_cve_trends_last_30_days() -> Dict[str, Any]:
    """Get CVE trends for last 30 days - API ONLY"""
    # LAZY IMPORT - only when function is called
    from services.data.api_client import api_client
    
    print("[CVE Trends] Fetching 30-day trends from API...")
    
    cves = api_client.get_cves_last_30_days()
    
    daily_counts = defaultdict(int)
    today = datetime.now(timezone.utc).date()
    
    for i in range(30):
        day = today - timedelta(days=29-i)
        daily_counts[day.strftime('%Y-%m-%d')] = 0
    
    for cve in cves:
        pub_date = cve.get('Published', '')
        if pub_date:
            try:
                if 'T' in pub_date:
                    dt = datetime.fromisoformat(pub_date.replace('Z', '+0000'))
                else:
                    dt = datetime.strptime(pub_date[:10], '%Y-%m-%d')
                
                date_key = dt.date().strftime('%Y-%m-%d')
                if date_key in daily_counts:
                    daily_counts[date_key] += 1
            except:
                continue
    
    sorted_dates = sorted(daily_counts.keys())
    
    result = {
        'labels': sorted_dates,
        'values': [daily_counts[date] for date in sorted_dates],
        'total_cves': len(cves),
        'date_range': {
            'start': sorted_dates[0] if sorted_dates else '',
            'end': sorted_dates[-1] if sorted_dates else ''
        }
    }
    
    print(f"[CVE Trends] Generated trends: {result['total_cves']} CVEs over {len(sorted_dates)} days")
    
    return result

def get_vulnerabilities_over_time_last_n_years(years=1) -> Dict[str, Any]:
    """Get vulnerability timeline for last N years - HISTORICAL DATA ONLY"""
    # LAZY IMPORT - only when function is called
    from services.data.data_processor import historical_loader
    
    print(f"[Vulnerabilities Over Time] Loading last {years} years historical data...")
    
    current_year = datetime.now().year
    years_to_load = list(range(current_year - years + 1, current_year + 1))
    
    print(f"[Vulnerabilities Over Time] Loading years: {years_to_load}")
    
    historical_data = historical_loader.get_multiple_years_data(years_to_load)
    
    monthly_counts = defaultdict(int)
    total_cves = 0
    
    for year_str, year_cves in historical_data.items():
        print(f"[Vulnerabilities Over Time] Processing {year_str}: {len(year_cves)} CVEs")
        total_cves += len(year_cves)
        
        for cve in year_cves:
            pub_date = cve.get('Published', '')
            if pub_date:
                try:
                    if 'T' in pub_date:
                        dt = datetime.fromisoformat(pub_date.replace('Z', '+0000'))
                    else:
                        dt = datetime.strptime(pub_date[:10], '%Y-%m-%d')
                    
                    month_key = dt.strftime('%Y-%m')
                    monthly_counts[month_key] += 1
                except Exception as e:
                    print(f"[Vulnerabilities Over Time] Error parsing date {pub_date}: {e}")
                    continue
    
    sorted_months = sorted(monthly_counts.items())
    
    result = {
        'labels': [item[0] for item in sorted_months],
        'values': [item[1] for item in sorted_months],
        'total_cves': total_cves,
        'months_covered': len(sorted_months),
        'raw_data': dict(monthly_counts)
    }
    
    print(f"[Vulnerabilities Over Time] Generated timeline: {result['total_cves']} CVEs across {result['months_covered']} months")
    
    return result

def get_filtered_historical_cves(year: int = None, month: int = None, day: int = None) -> List[Dict[str, Any]]:
    """Get filtered CVEs from historical data - FIXED FILTERING LOGIC"""
    # LAZY IMPORT - only when function is called
    from services.data.data_processor import historical_loader
    
    print(f"[Historical Filter] Getting filtered data for year={year}, month={month}, day={day}")
    
    if not year:
        print("[Historical Filter] No year specified, returning empty list")
        return []
    
    year_cves = historical_loader.get_year_data(year)
    print(f"[Historical Filter] Loaded {len(year_cves)} CVEs for year {year}")
    
    if not month:
        print(f"[Historical Filter] No month filter, returning all {len(year_cves)} CVEs for {year}")
        return year_cves
    
    filtered_cves = []
    for cve in year_cves:
        pub_date = cve.get('Published', '')
        if pub_date:
            try:
                if 'T' in pub_date:
                    dt = datetime.fromisoformat(pub_date.replace('Z', '+0000'))
                else:
                    dt = datetime.strptime(pub_date[:10], '%Y-%m-%d')
                
                if dt.year == year and dt.month == month:
                    if day is None or dt.day == day:
                        filtered_cves.append(cve)
                        print(f"[Historical Filter] Match: CVE {cve.get('ID', 'Unknown')} from {dt.strftime('%Y-%m-%d')}")
            except Exception as e:
                print(f"[Historical Filter] Error parsing date {pub_date}: {e}")
                continue
    
    print(f"[Historical Filter] Filtered result: {len(filtered_cves)} CVEs for {year}-{month:02d}" + (f"-{day:02d}" if day else ""))
    
    if filtered_cves:
        sample_count = min(3, len(filtered_cves))
        print(f"[Historical Filter] Sample of filtered CVEs:")
        for i in range(sample_count):
            cve = filtered_cves[i]
            print(f"  - {cve.get('ID', 'Unknown')}: {cve.get('Published', 'No date')}")
    
    return filtered_cves