import os
from datetime import timedelta

# ===============================
# Application Configuration
# ===============================
APP_NAME = "VulnEdu - Educational CVE Analysis Tool"
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')

# ===============================
# NVD API Configuration
# ===============================
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Keep your key in Render env; the default here is only for local/dev fallback.
NVD_API_KEY = os.environ.get('NVD_API_KEY', '9d289859-60a3-4f9f-af3c-30fdcddf3918')

# ===============================
# Data Storage Paths
# ===============================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
CACHE_DIR = os.path.join(DATA_DIR, 'cache')
NVD_DIR = os.path.join(DATA_DIR, 'nvd')
NVD_HISTORICAL_DIR = os.path.join(NVD_DIR, 'historical')
NVD_PROCESSED_DIR = os.path.join(NVD_DIR, 'processed')
CWE_XML_PATH = os.path.join(DATA_DIR, 'CWE_Catalog.xml')

# Ensure directories exist locally (safe no-ops on Render)
for directory in [CACHE_DIR, NVD_DIR, NVD_HISTORICAL_DIR, NVD_PROCESSED_DIR]:
    os.makedirs(directory, exist_ok=True)

# ===============================
# Database (Render Postgres)
# ===============================
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    # Render uses postgres:// which psycopg2 accepts; some libs expect postgresql://
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

DATABASE_ENABLED = bool(DATABASE_URL)
SQLALCHEMY_DATABASE_URI = DATABASE_URL
SQLALCHEMY_TRACK_MODIFICATIONS = False  # not used directly; kept for compatibility

# ===============================
# Memory / Cache
# ===============================
# 512 MB free tier -> keep headroom
MAX_MEMORY_USAGE_MB = 450

# You asked for 1 hour
CACHE_TTL_SECONDS = 60 * 60  # 1 hour

# Cache durations for internal components (some parts keep 24h for API payloads);
# this leaves room for in-memory charts to be 1 hour without thrashing.
CACHE_DURATION = timedelta(minutes=60)
MAX_CACHE_ENTRIES = 10

# ===============================
# Data Strategy
# ===============================
RECENT_DAYS_THRESHOLD = 30

# >>> Important change: rely on the DB, not local files, in production
USE_LOCAL_FEEDS = False          # <— switch OFF local JSON at runtime
AUTO_UPDATE_FEEDS = False
USE_GITHUB_DATA = False          # no GitHub scraping/calls in free tier

# ===============================
# API Rate Limiting / Timeouts
# ===============================
API_REQUESTS_PER_30_SECONDS = 50
API_TIMEOUT = 30

# ===============================
# Pagination
# ===============================
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100

# Page-specific data loading flags
LOAD_ALL_DATA_FOR_LEARN_PAGES = False
