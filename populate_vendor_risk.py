from database.db_manager import DatabaseManager

print("🏢 Populating vendor_risk_cache …")

db = DatabaseManager()
conn = db.get_connection()
cur = conn.cursor()

cur.execute("""
    INSERT INTO vendor_risk_cache (vendor_risk, weighted_risk, created_at, updated_at)
    SELECT
        jsonb_build_object('summary', 'Global Vendor Risk Summary'),
        jsonb_build_object('average_cvss_score', ROUND(AVG(cvss_score)::numeric, 2)),
        NOW(), NOW()
    FROM cves
    WHERE cvss_score IS NOT NULL;
""")

conn.commit()
cur.close()
db.return_connection(conn)

print("✅ vendor_risk_cache populated successfully!")
