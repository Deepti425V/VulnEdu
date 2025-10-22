from typing import Dict, List, Any
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from services.data.api_client import api_client

def get_cve_trends_last_30_days() -> Dict[str, Any]:
    """Get CVE trends for last 30 days - FETCHES ALL CVEs"""
    print("[CVE Trends] Fetching ALL CVEs from last 30 days...")
    
    daily_counts = defaultdict(int)
    today = datetime.now(timezone.utc).date()
    
    for i in range(30):
        day = today - timedelta(days=29-i)
        daily_counts[day.strftime('%Y-%m-%d')] = 0
    
    all_cves = []
    offset = 0
    batch_size = 400
    max_iterations = 15
    
    for iteration in range(max_iterations):
        print(f"[CVE Trends] Fetching batch {iteration+1}/{max_iterations} (offset={offset})...")
        batch = api_client.get_cves_last_30_days(batch_size=batch_size, offset=offset)
        
        if not batch:
            break
        
        all_cves.extend(batch)
        
        if len(batch) < batch_size:
            break
        
        offset += batch_size
    
    print(f"[CVE Trends] ✓ Fetched {len(all_cves)} CVEs total")
    
    for cve in all_cves:
        pub_date = cve.get('Published', '')
        if pub_date:
            try:
                if 'T' in pub_date:
                    dt = datetime.fromisoformat(pub_date.replace('Z', '+00:00'))
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
        'total_cves': len(all_cves)
    }
    
    print(f"[CVE Trends] Generated trends: {result['total_cves']} CVEs over {len(sorted_dates)} days")
    return result


def get_vulnerabilities_over_time_last_n_months(months=3) -> Dict[str, Any]:
    """Get vulnerability timeline for last N months - LIGHTWEIGHT"""
    print(f"[Timeline] Loading {months} months of data...")
    
    monthly_counts = defaultdict(int)
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=months * 30)
    
    all_cves = []
    offset = 0
    batch_size = 400
    max_cves = 2000  # Limit to 2000 CVEs to save memory
    
    while len(all_cves) < max_cves:
        batch = api_client.get_cves_last_30_days(batch_size=batch_size, offset=offset)
        if not batch:
            break
        all_cves.extend(batch)
        if len(batch) < batch_size:
            break
        offset += batch_size
    
    for cve in all_cves:
        pub_date = cve.get('Published', '')
        if pub_date:
            try:
                if 'T' in pub_date:
                    dt = datetime.fromisoformat(pub_date.replace('Z', '+00:00'))
                else:
                    dt = datetime.strptime(pub_date[:10], '%Y-%m-%d')
                month_key = dt.strftime('%Y-%m')
                monthly_counts[month_key] += 1
            except:
                continue
    
    sorted_months = sorted(monthly_counts.items())
    
    result = {
        'labels': [item[0] for item in sorted_months],
        'values': [item[1] for item in sorted_months],
        'total_cves': len(all_cves),
        'months_covered': len(sorted_months),
        'raw_data': dict(monthly_counts)
    }
    
    print(f"[Timeline] ✓ Loaded {result['total_cves']} CVEs across {result['months_covered']} months")
    return result


def get_vulnerabilities_over_time_last_n_years(years=1) -> Dict[str, Any]:
    """Get vulnerability timeline for last N years - FROM HISTORICAL DATA"""
    print(f"[Vulnerabilities Over Time] Loading {years} year(s) of historical data...")
    
    from services.data.data_processor import historical_loader
    
    current_year = datetime.now().year
    years_to_load = []
    for i in range(years):
        year = current_year - i
        years_to_load.append(year)
    
    print(f"[Vulnerabilities Over Time] Loading years: {years_to_load}")
    
    monthly_counts = defaultdict(int)
    total_cves = 0
    
    for year in years_to_load:
        try:
            print(f"[Vulnerabilities Over Time] Loading {year}...")
            year_cves = historical_loader.get_year_data(year)
            print(f"[Vulnerabilities Over Time] Processing {year}: {len(year_cves)} CVEs")
            total_cves += len(year_cves)
            
            for cve in year_cves:
                pub_date = cve.get('Published', '')
                if pub_date:
                    try:
                        if 'T' in pub_date:
                            dt = datetime.fromisoformat(pub_date.replace('Z', '+00:00'))
                        else:
                            dt = datetime.strptime(pub_date[:10], '%Y-%m-%d')
                        month_key = dt.strftime('%Y-%m')
                        monthly_counts[month_key] += 1
                    except Exception as e:
                        continue
            
            if str(year) in historical_loader.year_cache:
                print(f"[Vulnerabilities Over Time] Clearing cache for {year} to save memory")
                del historical_loader.year_cache[str(year)]
            
        except Exception as e:
            print(f"[Vulnerabilities Over Time] Error loading {year}: {e}")
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
