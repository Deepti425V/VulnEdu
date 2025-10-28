# check_db.py
import os, sys
sys.path.append(os.getcwd())  # 👈 add this line

from services.database_manager import DatabaseManager

db = DatabaseManager()

try:
    result = db.fetch("SELECT COUNT(*) FROM cve_data;")
    print("✅ Total CVEs in database:", result[0][0])
except Exception as e:
    print("⚠️  Error querying database:", e)
