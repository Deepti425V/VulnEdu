import os
from datetime import datetime, timezone
from typing import Dict, Tuple
import config

class DataSourceConfig:
    """Dynamic data source configuration - NO execution on init"""
    
    def __init__(self):
        # CRITICAL: Only store current time, do NOT call any functions
        self.current_date = datetime.now(timezone.utc)
        self._cutoff_cache = None
        self._cache_date = None
    
    def get_data_source_cutoff(self) -> Tuple[Dict, str]:
        """Calculate dynamic cutoff between historical and API data"""
        today = self.current_date.date()
        
        if self._cutoff_cache and self._cache_date == today:
            return self._cutoff_cache
        
        current_year = self.current_date.year
        current_month = self.current_date.month
        
        if current_month == 1:
            historical_cutoff_year = current_year - 1
            historical_cutoff_month = 12
            api_start_year = current_year
            api_start_month = 1
        else:
            historical_cutoff_year = current_year
            historical_cutoff_month = current_month - 1
            api_start_year = current_year
            api_start_month = current_month
        
        cutoff_info = {
            'historical': {
                'end_year': historical_cutoff_year,
                'end_month': historical_cutoff_month,
                'years_range': list(range(2010, historical_cutoff_year + 1))
            },
            'api': {
                'start_year': api_start_year,
                'start_month': api_start_month
            },
            'current': {
                'year': current_year,
                'month': current_month,
                'date': today
            }
        }
        
        explanation = (
            f"Historical data: 2010 – {historical_cutoff_year}-{historical_cutoff_month:02d}, "
            f"API data: {api_start_year}-{api_start_month:02d} onwards"
        )
        
        self._cutoff_cache = (cutoff_info, explanation)
        self._cache_date = today
        
        return cutoff_info, explanation
    
    def should_use_historical(self, year: int, month: int = None) -> bool:
        """Determine if given year/month should use historical data"""
        cutoff_info, _ = self.get_data_source_cutoff()
        historical_end = cutoff_info['historical']
        
        if year < historical_end['end_year']:
            return True
        elif year == historical_end['end_year']:
            if month is None:
                return True
            return month <= historical_end['end_month']
        else:
            return False
    
    def should_use_api(self, year: int, month: int = None) -> bool:
        """Determine if given year/month should use API data"""
        return not self.should_use_historical(year, month)
    
    def get_available_historical_files(self) -> Dict[int, str]:
        """Get list of available historical data files"""
        available_files = {}
        
        if not os.path.exists(config.NVD_HISTORICAL_DIR):
            print(f"[DataSource] Historical directory does not exist: {config.NVD_HISTORICAL_DIR}")
            return available_files
        
        patterns = [
            "CVE-{year}.json",
            "nvdcve-1.1-{year}.json",
            "nvdcve-2.0-{year}.json",
            "CVE-{year}.json.gz",
            "nvdcve-1.1-{year}.json.gz",
            "nvdcve-2.0-{year}.json.gz"
        ]
        
        current_year = self.current_date.year
        for year in range(2010, current_year + 1):
            for pattern in patterns:
                filename = pattern.format(year=year)
                filepath = os.path.join(config.NVD_HISTORICAL_DIR, filename)
                if os.path.exists(filepath):
                    available_files[year] = filepath
                    break
        
        return available_files
    
    def log_data_source_status(self):
        """Log current data source configuration"""
        cutoff_info, explanation = self.get_data_source_cutoff()
        available_files = self.get_available_historical_files()
        
        print(f"[DataSource] Current date: {self.current_date.strftime('%Y-%m-%d')}")
        print(f"[DataSource] Configuration: {explanation}")
        print(f"[DataSource] Historical directory: {config.NVD_HISTORICAL_DIR}")
        print(f"[DataSource] Historical files available: {len(available_files)} years")
        
        if available_files:
            print(f"[DataSource] Historical years: {min(available_files.keys())} - {max(available_files.keys())}")
            print(f"[DataSource] Available files:")
            for year, filepath in sorted(available_files.items()):
                filename = os.path.basename(filepath)
                file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
                print(f"  {year}: {filename} ({file_size:,} bytes)")
        else:
            print(f"[DataSource] WARNING: No historical files found!")
        
        expected_years = list(range(2010, cutoff_info['historical']['end_year'] + 1))
        missing_years = [year for year in expected_years if year not in available_files]
        
        if missing_years:
            print(f"[DataSource] WARNING: Missing historical files for years: {missing_years}")

# Global instance - NO execution on instantiation
data_source_config = DataSourceConfig()