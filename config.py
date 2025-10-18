# Operating system interface for environment variables and file paths
import os
# Time duration objects for cache expiration settings
from datetime import timedelta

# Application Configuration
APP_NAME = "VulnEdu - Educational CVE Analysis Tool"  # Display name for the application
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')  # Flask session key from environment

# NVD API Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"  # National Vulnerability Database REST API endpoint
NVD_API_KEY = os.environ.get('NVD_API_KEY', '9d289859-60a3-4f9f-af3c-30fdcddf3918')  # API authentication key

# GitHub Repository Configuration for Historical Data
GITHUB_REPO_OWNER = "Deepti425V"
GITHUB_REPO_NAME = "vulnedu-data"
GITHUB_REPO_BRANCH = "main"
GITHUB_RAW_BASE_URL = f"https://raw.githubusercontent.com/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/{GITHUB_REPO_BRANCH}"

# Data Storage Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Get absolute path of this config file's directory
DATA_DIR = os.path.join(BASE_DIR, 'data')  # Main data storage directory
CACHE_DIR = os.path.join(DATA_DIR, 'cache')  # Cached API responses and processed data
NVD_DIR = os.path.join(DATA_DIR, 'nvd')  # NVD-specific data storage
NVD_HISTORICAL_DIR = os.path.join(NVD_DIR, 'historical')  # Historical CVE data feeds (now from GitHub)
NVD_PROCESSED_DIR = os.path.join(NVD_DIR, 'processed')  # Processed and enriched CVE data
CWE_XML_PATH = os.path.join(DATA_DIR, 'CWE_Catalog.xml')  # Common Weakness Enumeration catalog file

# NVD Data Feeds
NVD_FEEDS_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1"  # Base URL for historical data feeds
HISTORICAL_YEARS = list(range(2020, 2026))  # Years to download: 2020, 2021, 2022, 2023, 2024, 2025

# Cache Configuration
CACHE_DURATION = timedelta(minutes=30)  # How long to keep cached data before refreshing
MAX_CACHE_ENTRIES = 1000  # Maximum number of items to store in cache (memory management)

# Data Loading Strategy
RECENT_DAYS_THRESHOLD = 30  # Use API for last 30 days, use feeds for older data
USE_LOCAL_FEEDS = True  # Enable using downloaded feed files instead of API calls
AUTO_UPDATE_FEEDS = False  # Disable automatic feed updates (manual control for production)
USE_GITHUB_DATA = True  # Enable GitHub repository data fetching

# API Rate Limiting
API_REQUESTS_PER_30_SECONDS = 50  # NVD rate limit for authenticated requests
API_TIMEOUT = 30  # Seconds to wait for API response before timing out

# Pagination
DEFAULT_PAGE_SIZE = 25  # Default number of items per page in UI/API
MAX_PAGE_SIZE = 100  # Maximum items per page to prevent oversized responses

# Ensure directories exist - create them if missing
for directory in [CACHE_DIR, NVD_DIR, NVD_HISTORICAL_DIR, NVD_PROCESSED_DIR]:
    os.makedirs(directory, exist_ok=True)  # exist_ok=True prevents errors if directory already exists