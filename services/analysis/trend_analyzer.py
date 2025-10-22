from typing import Dict, List, Any
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from services.data.api_client import api_client

def get_cve_trends_last_30_days() -> Dict[str, Any]:
    """Get CVE trends for last 30 days - API ONLY"""
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
        'total_cves': len(cves),
        'date_range': {
            'start': sorted_dates[0] if sorted_dates else '',
            'end': sorted_dates[-1] if sorted_dates else ''
        }
    }
    
    print(f"[CVE Trends] Generated trends: {result['total_cves']} CVEs over {len(sorted_dates)} days")
    return result

def get_vulnerabilities_over_time_last_n_years(years=1) -> Dict[str, Any]:
    """Get vulnerability timeline - LOADS HISTORICAL DATA FOR REAL TIMELINE"""
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
            
            # Clear cache after processing to save memory
            if str(year) in historical_loader._year_cache:
                print(f"[Vulnerabilities Over Time] Clearing cache for {year} to save memory")
                del historical_loader._year_cache[str(year)]
        
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

def get_filtered_historical_cves(year: int = None, month: int = None, day: int = None) -> List[Dict[str, Any]]:
    """Get filtered CVEs - FROM API"""
    print(f"[Historical Filter] Filtering from API for year={year}, month={month}, day={day}")
    
    if not year:
        return []
    
    # Use API to get data for specific year
    cves = api_client.get_cves_for_date_range(year=year, month=month, day=day)
    
    print(f"[Historical Filter] Filtered result: {len(cves)} CVEs")
    return cves