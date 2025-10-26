import os
from datetime import timedelta

# Application Configuration
APP_NAME = "VulnEdu - Educational CVE Analysis Tool"
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')

# Database Configuration for Render
DATABASE_URL = os.environ.get('DATABASE_URL')

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

# ===== MEMORY OPTIMIZATION FOR RENDER FREE TIER (512MB) =====

# Detect if running on Render
IS_RENDER = os.environ.get('RENDER') == 'true'

# Historical years configuration - HEAVILY REDUCED for memory
current_year = 2025
if IS_RENDER:
    # On Render: Only load CURRENT year to save memory
    HISTORICAL_YEARS = [current_year]  # Only 2025
    print("[Config] RENDER MODE: Loading only current year data")
else:
    # Local dev: Can load more
    HISTORICAL_YEARS = [current_year - 1, current_year]  # 2024, 2025

# Cache Configuration - AGGRESSIVE LIMITS
CACHE_DURATION = timedelta(hours=2)  # Increased from 30 min
MAX_CACHE_ENTRIES = 20  # REDUCED from 100 to save memory

# Memory Limits (in MB)
if IS_RENDER:
    MAX_MEMORY_MB = 400  # Stay well under 512MB limit
    MAX_CVES_IN_MEMORY = 500  # CRITICAL: Limit CVEs in memory
    MAX_BATCH_SIZE = 100  # Small batches for database inserts
    print(f"[Config] RENDER MODE: Max memory={MAX_MEMORY_MB}MB, Max CVEs={MAX_CVES_IN_MEMORY}")
else:
    MAX_MEMORY_MB = 1024  # Local can use more
    MAX_CVES_IN_MEMORY = 2000  # More for local dev
    MAX_BATCH_SIZE = 500

# Data Loading Strategy - OPTIMIZED FOR MEMORY
RECENT_DAYS_THRESHOLD = 7  # REDUCED from 30 - only load last week
USE_LOCAL_FEEDS = False  # CHANGED: Don't use local files (they're huge)
AUTO_UPDATE_FEEDS = False
USE_GITHUB_DATA = False
LAZY_LOAD = True  # CRITICAL: Load data on-demand, not at startup

# Database Strategy
if IS_RENDER:
    REQUIRE_DATABASE = True  # MUST use database on Render
    PRELOAD_DATA = False  # DON'T preload at startup
    USE_PAGINATION = True  # ALWAYS paginate
else:
    REQUIRE_DATABASE = False
    PRELOAD_DATA = False  # Still don't preload locally
    USE_PAGINATION = True

# API Rate Limiting
API_REQUESTS_PER_30_SECONDS = 50
API_TIMEOUT = 30

# Pagination - SMALLER PAGE SIZES
DEFAULT_PAGE_SIZE = 20  # REDUCED from 25
MAX_PAGE_SIZE = 50  # REDUCED from 100

# Logging Configuration
LOG_LEVEL = 'INFO'
if IS_RENDER:
    LOG_MEMORY = True  # Log memory usage on Render
    LOG_VERBOSE = True  # Detailed logs
else:
    LOG_MEMORY = False
    LOG_VERBOSE = False

# Ensure directories exist
for directory in [CACHE_DIR, NVD_DIR, NVD_HISTORICAL_DIR, NVD_PROCESSED_DIR]:
    os.makedirs(directory, exist_ok=True)

# Print configuration on load
if IS_RENDER:
    print("=" * 60)
    print("🚀 RENDER FREE TIER OPTIMIZATION ACTIVE")
    print("=" * 60)
    print(f"✓ Max Memory: {MAX_MEMORY_MB}MB")
    print(f"✓ Max CVEs in Memory: {MAX_CVES_IN_MEMORY}")
    print(f"✓ Database Required: {REQUIRE_DATABASE}")
    print(f"✓ Lazy Loading: {LAZY_LOAD}")
    print(f"✓ Years Loading: {HISTORICAL_YEARS}")
    print("=" * 60)