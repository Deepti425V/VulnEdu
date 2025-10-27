"""
Application entry point for Render deployment.
This file works alongside your existing vulnedu.py file.
"""
import os
import sys
from vulnedu import app  # Import the app directly from your main vulnedu.py file

# Get the port from environment or use default
port = int(os.environ.get('PORT', 10000))

print(f"[application.py] Starting VulnEdu application on port {port}")
print(f"[application.py] Python version: {sys.version}")
print(f"[application.py] Current directory: {os.getcwd()}")

if __name__ == "__main__":
    # For local testing
    app.run(host='0.0.0.0', port=port)
