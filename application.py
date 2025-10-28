"""
Application entry point for Render deployment.
This file works alongside your existing vulnedu.py file.
"""
import os
import sys
import psutil
from vulnedu import app  # Import the app created in vulnedu.py

def print_memory_stats():
    """Helper function to print memory stats for debugging"""
    try:
        memory = psutil.virtual_memory()
        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()

        print(f"[application.py] MEMORY: Total: {memory.total / (1024*1024):.1f}MB, "
              f"Available: {memory.available / (1024*1024):.1f}MB")
        print(f"[application.py] PROCESS: RSS: {memory_info.rss / (1024*1024):.1f}MB, "
              f"VMS: {memory_info.vms / (1024*1024):.1f}MB")
    except:
        print("[application.py] Failed to get memory stats")

# Render provides PORT; default for local/dev
port = int(os.environ.get('PORT', 10000))

print(f"[application.py] Starting VulnEdu application on port {port}")
print(f"[application.py] Python version: {sys.version}")
print(f"[application.py] Current directory: {os.getcwd()}")
print_memory_stats()

if __name__ == "__main__":
    # For local testing and Render deployment
    app.run(host='0.0.0.0', port=port)
