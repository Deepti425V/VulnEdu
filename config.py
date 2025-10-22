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

# Cache Configuration - OPTIMIZED FOR 512MB RAM
CACHE_DURATION = timedelta(hours=1)
MAX_CACHE_ENTRIES = 100
ENABLE_GZIP_CACHE = True
AUTO_REFRESH_INTERVAL_MINUTES = 60

# API Rate Limiting
API_REQUESTS_PER_30_SECONDS = 50
API_TIMEOUT = 30

# Pagination Configuration
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500
API_BATCH_SIZE = 400

# Memory Optimization Settings
ENABLE_GZIP_COMPRESSION = True
DATABASE_CONNECTION_POOL_MIN = 1
DATABASE_CONNECTION_POOL_MAX = 2

# Startup Configuration
LOAD_DATA_ON_STARTUP = False
