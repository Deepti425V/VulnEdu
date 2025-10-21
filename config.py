import os
from datetime import timedelta

# Application Configuration
APP_NAME = "VulnEdu – Educational CVE Analysis Tool"
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')

# NVD API Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get('NVD_API_KEY', '9d289859-60a3-4f9f-af3c-30fdcddf3918')

# GitHub Repository Configuration for Historical Data
GITHUB_REPO_OWNER = "Deepti425V"
GITHUB_REPO_NAME = "vulnedu-data"
GITHUB_REPO_BRANCH = "main"
GITHUB_RAW_BASE_URL = f"https://raw.githubusercontent.com/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/{GITHUB_REPO_BRANCH}"

# Data Storage Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
CACHE_DIR = os.path.join(DATA_DIR, 'cache')
NVD_DIR = os.path.join(DATA_DIR, 'nvd')
NVD_HISTORICAL_DIR = os.path.join(NVD_DIR, 'historical')
NVD_PROCESSED_DIR = os.path.join(NVD_DIR, 'processed')
CWE_XML_PATH = os.path.join(DATA_DIR, 'CWE_Catalog.xml')

# NVD Data Feeds
NVD_FEEDS_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1"

# CRITICAL: ONLY LOAD CURRENT YEAR ON STARTUP
# Historical years will be loaded on-demand
current_year = 2025  # Update this as needed
HISTORICAL_YEARS = [current_year]  # ONLY current year

# Cache Configuration – REDUCED for memory optimization
CACHE_DURATION = timedelta(minutes=30)
MAX_CACHE_ENTRIES = 100  # Reduced from 1000

# Data Loading Strategy
RECENT_DAYS_THRESHOLD = 30
USE_LOCAL_FEEDS = True
AUTO_UPDATE_FEEDS = False
USE_GITHUB_DATA = True  # Enable GitHub data fetching

# API Rate Limiting
API_REQUESTS_PER_30_SECONDS = 50
API_TIMEOUT = 30

# Pagination
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100

# Ensure directories exist
for directory in [CACHE_DIR, NVD_DIR, NVD_HISTORICAL_DIR, NVD_PROCESSED_DIR]:
    os.makedirs(directory, exist_ok=True)