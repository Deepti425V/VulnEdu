import os
from datetime import timedelta

# Application Configuration
APP_NAME = "VulnEdu - Educational CVE Analysis Tool"
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')

# NVD API Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get('NVD_API_KEY', '9d289859-60a3-4f9f-af3c-30fdcddf3918')

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

# CRITICAL MEMORY OPTIMIZATION: Reduce to only current year
current_year = 2025
HISTORICAL_YEARS = [current_year]  # CHANGED: Only load current year

# Database Configuration
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
DATABASE_ENABLED = bool(DATABASE_URL)
SQLALCHEMY_DATABASE_URI = DATABASE_URL
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Extreme Memory Optimization
LAZY_LOAD_ENABLED = True
MAX_MEMORY_USAGE_MB = 400  # Reduced from 450 to stay well under 512MB
USE_MEMORY_EFFICIENT_MODE = True  # NEW FLAG for extreme memory optimization
SKIP_HISTORICAL_LOADING = True  # NEW: Skip loading historical data completely
MAX_CVES_TO_LOAD = 1000  # NEW: Maximum number of CVEs to load at once

# Cache Configuration - REDUCED
CACHE_DURATION = timedelta(minutes=30)
MAX_CACHE_ENTRIES = 5  # REDUCED from 10

# Data Loading Strategy - OPTIMIZED
RECENT_DAYS_THRESHOLD = 7  # REDUCED from 30 to 7 days
USE_LOCAL_FEEDS = False  # CHANGED: Use API instead of local files
AUTO_UPDATE_FEEDS = False
USE_GITHUB_DATA = False
USE_API_INSTEAD_OF_FILES = True  # NEW: Prefer API over files

# API Rate Limiting
API_REQUESTS_PER_30_SECONDS = 50
API_TIMEOUT = 30

# Pagination - REDUCED
DEFAULT_PAGE_SIZE = 10  # REDUCED from 25
MAX_PAGE_SIZE = 25  # REDUCED from 100

# Page-specific data loading flags
LOAD_ALL_DATA_FOR_LEARN_PAGES = False

# Ensure directories exist
for directory in [CACHE_DIR, NVD_DIR, NVD_HISTORICAL_DIR, NVD_PROCESSED_DIR]:
    os.makedirs(directory, exist_ok=True)