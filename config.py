import os

# NVD API Configuration
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

# Cache Configuration
CACHE_TIMEOUT = 3600  # 1 hour
CACHE_TYPE = "simple"

# Application Configuration
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
PORT = int(os.environ.get("PORT", 5000))

# API Rate Limiting
API_RATE_LIMIT = "100/hour"
API_TIMEOUT = 10  # seconds

# Circuit Breaker Configuration
CIRCUIT_BREAKER_FAILURE_THRESHOLD = 3
CIRCUIT_BREAKER_TIMEOUT = 300  # 5 minutes