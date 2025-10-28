#!/bin/bash

# Startup script for VulnEdu with memory management
echo "[Startup] Starting VulnEdu application..."

# Set memory limits for Python
export PYTHONMALLOC=malloc
export MALLOC_TRIM_THRESHOLD_=100000
export MALLOC_MMAP_THRESHOLD_=100000

# Monitor initial memory
echo "[Startup] Checking initial memory..."
python3 -c "
import psutil
import os
process = psutil.Process(os.getpid())
mem_mb = process.memory_info().rss / 1024 / 1024
print(f'[Startup] Initial memory usage: {mem_mb:.2f} MB')
"

# Create required directories
echo "[Startup] Creating required directories..."
mkdir -p data/cache
mkdir -p data/nvd/historical
mkdir -p data/nvd/processed

# Initialize database if URL is provided
if [ ! -z "$DATABASE_URL" ]; then
    echo "[Startup] Database URL found, initializing database..."
    python3 -c "
from database.db_manager import DatabaseManager
db = DatabaseManager()
if db.use_database:
    stats = db.get_stats()
    print('[Startup] Database initialized:', stats)
else:
    print('[Startup] Database initialization failed')
"
fi

# Check available memory before starting
python3 -c "
import psutil
mem = psutil.virtual_memory()
available_mb = mem.available / 1024 / 1024
if available_mb < 400:
    print(f'[Startup] WARNING: Low memory available: {available_mb:.2f} MB')
    print('[Startup] Application may experience memory issues')
else:
    print(f'[Startup] Memory available: {available_mb:.2f} MB - OK')
"

echo "[Startup] Starting Gunicorn server..."
exec gunicorn vulnedu:app \
    --workers=1 \
    --threads=2 \
    --worker-class=sync \
    --max-requests=100 \
    --max-requests-jitter=20 \
    --timeout=120 \
    --keepalive=2 \
    --log-level=info \
    --access-logfile=- \
    --error-logfile=- \
    --preload