import os
from datetime import timedelta

# ===============================
# Application Configuration
# ===============================
APP_NAME = "VulnEdu - Educational CVE Analysis Tool"
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-key-change-in-production")

# ===============================
# NVD API Configuration
# ===============================
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "9d289859-60a3-4f9f-af3c-30fdcddf3918")

# ===============================
# Data Storage Paths
# ===============================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
CACHE_DIR = os.path.join(DATA_DIR, "cache")
NVD_DIR = os.path.join(DATA_DIR, "nvd")
NVD_HISTORICAL_DIR = os.path.join(NVD_DIR, "historical")
NVD_PROCESSED_DIR = os.path.join(NVD_DIR, "processed")
CWE_XML_PATH = os.path.join(DATA_DIR, "CWE_Catalog.xml")

for directory in [CACHE_DIR, NVD_DIR, NVD_HISTORICAL_DIR, NVD_PROCESSED_DIR]:
    os.makedirs(directory, exist_ok=True)

# ===============================
# Database (Render Postgres)
# ===============================
DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

DATABASE_ENABLED = bool(DATABASE_URL)
SQLALCHEMY_DATABASE_URI = DATABASE_URL
SQLALCHEMY_TRACK_MODIFICATIONS = False

# ===============================
# Memory / Cache
# ===============================
MAX_MEMORY_USAGE_MB = 450
CACHE_TTL_SECONDS = 60 * 60  # 1 hour
CACHE_DURATION = timedelta(minutes=60)
MAX_CACHE_ENTRIES = 10

# ===============================
# Data Strategy
# ===============================

def running_on_render() -> bool:
    """Detect if the app is running on Render"""
    return os.getenv("RENDER", None) is not None

# Force Render to use local JSON feeds, not DB
USE_LOCAL_FEEDS = True
AUTO_UPDATE_FEEDS = False
USE_GITHUB_DATA = False

# Safety: disable DB caching on Render unless explicitly set
USE_DATABASE_CACHE = False
if running_on_render():
    USE_DATABASE_CACHE = os.environ.get("USE_DATABASE_CACHE", "false").lower() == "true"    
else:
    USE_DATABASE_CACHE = True
    

# Path for JSON.gz historical data
LOCAL_HISTORICAL_PATH = os.path.join(DATA_DIR, "nvd", "historical")
if not os.path.exists(LOCAL_HISTORICAL_PATH):
    print(f"[Config] WARNING: Local historical data folder missing: {LOCAL_HISTORICAL_PATH}")
    USE_LOCAL_FEEDS = False

# ===============================
# API / Timeouts / Pagination
# ===============================
API_REQUESTS_PER_30_SECONDS = 50
API_TIMEOUT = 30
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 100
LOAD_ALL_DATA_FOR_LEARN_PAGES = False
RECENT_DAYS_THRESHOLD = 30

print(f"[Config] DATABASE_ENABLED={DATABASE_ENABLED}, USE_LOCAL_FEEDS={USE_LOCAL_FEEDS}, USE_DATABASE_CACHE={USE_DATABASE_CACHE}")
