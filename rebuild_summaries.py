from database.db_manager import DatabaseManager
import json

print("🔄 Rebuilding timeline and vendor summaries...")
db = DatabaseManager()

conn = db.get_connection()
cur = conn.cursor()

# 🧹 Clear existing summary data
cur.execute("DELETE FROM timeline_data;")
cur.execute("DELETE FROM vendor_risk_cache;")

# 📈 Build timeline data (cast text -> date)
print("📈 Generating timeline_data ...")
cur.execute("""
    INSERT INTO timeline_data (year, month, count)
    SELECT
        EXTRACT(YEAR FROM TO_TIMESTAMP(published, 'YYYY-MM-DD"T"HH24:MI:SS'))::INT AS year,
        EXTRACT(MONTH FROM TO_TIMESTAMP(published, 'YYYY-MM-DD"T"HH24:MI:SS'))::INT AS month,
        COUNT(*)
    FROM cves
    WHERE published IS NOT NULL
    GROUP BY year, month
    ORDER BY year, month;
""")

# 🏢 Build vendor_risk_cache (JSON-safe insert)
print("🏢 Generating vendor_risk_cache ...")
summary_json = json.dumps({"summary": "Global Vendor Risk Summary"})
cur.execute("""
    INSERT INTO vendor_risk_cache (vendor_risk, weighted_risk, created_at, updated_at)
    SELECT
        %s::json AS vendor_risk,
        ROUND(AVG(cvss_score)::NUMERIC, 2) AS weighted_risk,
        NOW(), NOW()
    FROM cves
    WHERE cvss_score IS NOT NULL;
""", (summary_json,))

conn.commit()
cur.close()
db.return_connection(conn)
print("✅ Summary rebuild completed successfully!")
