"""
application.py — Render entrypoint for VulnEdu
Simplified so Render/Gunicorn detect the $PORT reliably.
This script is intended for local debug only; production on Render
should use the Gunicorn start command that points directly at vulnedu:app.
"""

import os
import sys
import psutil

# Import the Flask app created in vulnedu.py
# (vulnedu.py defines `app = create_app()` at module level)
from vulnedu import app


def print_memory_stats():
    """Print simple memory stats for debugging in logs."""
    try:
        mem = psutil.virtual_memory()
        proc = psutil.Process(os.getpid())
        pinfo = proc.memory_info()
        print(
            f"[application.py] Total RAM: {mem.total / (1024*1024):.1f} MB | "
            f"Available: {mem.available / (1024*1024):.1f} MB | "
            f"Proc RSS: {pinfo.rss / (1024*1024):.1f} MB | VMS: {pinfo.vms / (1024*1024):.1f} MB"
        )
    except Exception as e:
        print(f"[application.py] Memory stats unavailable: {e}")


def main():
    port = int(os.environ.get("PORT", 10000))
    print(f"[application.py] Starting VulnEdu on port {port}")
    print(f"[application.py] Python version: {sys.version}")
    print(f"[application.py] Current directory: {os.getcwd()}")
    print_memory_stats()

    # Use Flask's built-in server only for local debugging.
    # On Render use Gunicorn with the command pointing to vulnedu:app
    app.run(host="0.0.0.0", port=port, debug=False)


if __name__ == "__main__":
    main()
