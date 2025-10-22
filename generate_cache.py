#!/usr/bin/env python
# generate_cache.py
import os
import sys
import time
import argparse
from datetime import datetime

def main():
    parser = argparse.ArgumentParser(description='Generate pre-computed cache files')
    parser.add_argument('--years', type=int, default=3, help='Number of years to cache (1-5)')
    parser.add_argument('--output-dir', type=str, default='./data/file_cache', help='Output directory')
    args = parser.parse_args()
    
    print("==================================================")
    print("  Pre-generating Vulnerability Data Cache Files")
    print("==================================================")
    print(f"Cache directory: {args.output_dir}")
    print(f"Years to cache: {args.years}")
    
    # Create cache directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Import dependencies
    try:
        from file_cache_manager import file_cache_manager
        from services.analysis.trend_analyzer import get_cve_trends_last_30_days
        from services.analysis.trend_analyzer import get_vulnerabilities_over_time_last_n_years
        from services.data.api_client import api_client
        from services.data.data_processor import historical_loader
    except ImportError as e:
        print(f"Error importing required modules: {str(e)}")
        print("Make sure you're running this script from the project root directory")
        return 1
    
    start_time = time.time()
    
    try:
        # Step 1: Generate 30-day trends cache
        print("\n1. Generating 30-day CVE trends cache...")
        trends_data = get_cve_trends_last_30_days()
        print(f"   Cached {trends_data['total_cves']} CVEs over 30 days")
        
        # Step 2: Generate historical year caches
        print("\n2. Generating historical year caches...")
        current_year = datetime.now().year
        for i in range(args.years):
            year = current_year - i
            print(f"   Processing year {year}...")
            
            # Load year data from historical_loader
            year_start = time.time()
            year_cves = historical_loader.get_year_data(year)
            
            if year_cves:
                # Save to cache
                file_cache_manager.save_to_cache(year_cves, 'historical_year', year=year)
                year_time = time.time() - year_start
                print(f"   Cached {len(year_cves)} CVEs for year {year} in {year_time:.1f}s")
            else:
                print(f"   No data available for year {year}")
        
        # Step 3: Generate timeline caches for different year ranges
        print("\n3. Generating timeline caches...")
        for years in range(1, args.years + 1):
            print(f"   Generating {years}-year timeline...")
            timeline_data = get_vulnerabilities_over_time_last_n_years(years=years)
            print(f"   Cached {timeline_data['total_cves']} CVEs across {timeline_data['months_covered']} months")
        
        # Step 4: Show cache statistics
        print("\n4. Cache generation complete!")
        stats = file_cache_manager.get_cache_stats()
        
        print(f"\nTotal cache size: {stats['total_size']}")
        print(f"Files generated: {len(stats['files'])}")
        
        elapsed_time = time.time() - start_time
        print(f"\nTotal elapsed time: {elapsed_time:.2f} seconds")
        
        return 0
    
    except Exception as e:
        print(f"\nError generating cache: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())