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

# Historical years configuration - REDUCED for memory efficiency
current_year = 2025
HISTORICAL_YEARS = [current_year - 1, current_year]  # Only 2024, 2025 to save memory

# Database Configuration - CRITICAL: Enable database storage for Render
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    # Fix Render's postgres:// vs postgresql:// URL format issue
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

DATABASE_ENABLED = bool(DATABASE_URL)
SQLALCHEMY_DATABASE_URI = DATABASE_URL
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Memory Management Settings - CRITICAL FOR RENDER
LAZY_LOAD_ENABLED = True
MAX_MEMORY_USAGE_MB = 400  # Conservative limit below 512MB
MEMORY_CHECK_INTERVAL = 30  # Check memory every 30 seconds
BATCH_SIZE = 1000  # Process CVEs in smaller batches
STREAM_JSON_ENABLED = True  # Enable streaming JSON parsing

# Cache Configuration
CACHE_DURATION = timedelta(minutes=30)
MAX_CACHE_ENTRIES = 5  # Drastically reduced to save memory
MAX_YEAR_CACHE_SIZE = 1  # Only keep 1 year in memory at a time

# Data Loading Strategy
RECENT_DAYS_THRESHOLD = 30
USE_LOCAL_FEEDS = True
AUTO_UPDATE_FEEDS = False
USE_GITHUB_DATA = False

# API Rate Limiting
API_REQUESTS_PER_30_SECONDS = 50
API_TIMEOUT = 30

# Pagination
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 50  # Reduced from 100

# Page-specific data loading flags
LOAD_ALL_DATA_FOR_LEARN_PAGES = False

# Gunicorn Configuration for Render
WORKERS = 1  # Single worker to conserve memory
THREADS = 2  # Minimal threads
WORKER_CLASS = 'sync'  # Sync workers use less memory than async
WORKER_CONNECTIONS = 50
TIMEOUT = 120
KEEPALIVE = 2
MAX_REQUESTS = 100  # Restart workers after 100 requests to prevent memory leaks
MAX_REQUESTS_JITTER = 20

# Ensure directories exist
for directory in [CACHE_DIR, NVD_DIR, NVD_HISTORICAL_DIR, NVD_PROCESSED_DIR]:
    os.makedirs(directory, exist_ok=True)