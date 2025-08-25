import os  

# === NVD API Configuration ===
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"  # Base URL for NVD CVE REST API
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")                   # API key, loaded from env variable if set

# === Cache Configuration ===
CACHE_TIMEOUT = 3600                  # Duration (in seconds) cache is valid; here, set to 1 hour
CACHE_TYPE = "simple"                 # Flask-Cache backend type: "simple" means in-process memory

# === Application Configuration ===
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"  # Debug mode (bool); from env, else False
PORT = int(os.environ.get("PORT", 5000))                    # Port to listen on; env or default 5000

# === API Rate Limiting ===
API_RATE_LIMIT = "100/hour"   # How many API requests allowed per client per hour
API_TIMEOUT = 10              # How many seconds before an API HTTP request is abandoned

# === Circuit Breaker Configuration ===
CIRCUIT_BREAKER_FAILURE_THRESHOLD = 3   # Trip breaker after this many consecutive failures
CIRCUIT_BREAKER_TIMEOUT = 300           # When open, wait this long (secs; here 5 min) before retry