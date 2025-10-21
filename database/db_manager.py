import os
import psycopg2
from psycopg2.extras import RealDictCursor, execute_batch
from typing import List, Dict, Any, Optional
import json
from datetime import datetime


class DatabaseManager:
    """Manages PostgreSQL database connections and operations"""
    
    def __init__(self):
        # Get database URL from environment variable (Render provides this automatically)
        self.database_url = os.environ.get('DATABASE_URL')
        self.conn = None
        self.use_database = bool(self.database_url)
        
        if self.use_database:
            print("[Database] Database URL found, database mode ENABLED")
            self.connect()
            self.init_tables()
        else:
            print("[Database] No DATABASE_URL found, database mode DISABLED (using memory)")
    
    def connect(self):
        """Establish database connection"""
        if not self.database_url:
            return False
        
        try:
            # Render's DATABASE_URL starts with postgres://, but psycopg2 needs postgresql://
            database_url = self.database_url.replace('postgres://', 'postgresql://', 1)
            self.conn = psycopg2.connect(database_url, cursor_factory=RealDictCursor)
            self.conn.autocommit = False  # Use transactions
            print("[Database] Successfully connected to PostgreSQL")
            return True
        except Exception as e:
            print(f"[Database] Connection error: {e}")
            self.use_database = False
            return False
    
    def init_tables(self):
        """Initialize database tables if they don't exist"""
        if not self.conn:
            return
        
        try:
            cursor = self.conn.cursor()
            
            # CVE table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cves (
                    id VARCHAR(50) PRIMARY KEY,
                    description TEXT,
                    severity VARCHAR(20),
                    cvss_score FLOAT,
                    cwe VARCHAR(50),
                    published VARCHAR(50),
                    last_modified VARCHAR(50),
                    references JSONB,
                    products JSONB,
                    metrics JSONB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for faster queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_cves_cwe ON cves(cwe)
            """)
            
            # Cache metadata table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cache_metadata (
                    key VARCHAR(100) PRIMARY KEY,
                    last_updated TIMESTAMP,
                    total_records INTEGER,
                    metadata JSONB
                )
            """)
            
            self.conn.commit()
            print("[Database] Tables initialized successfully")
            
        except Exception as e:
            print(f"[Database] Error initializing tables: {e}")
            self.conn.rollback()
    
    def save_cves_batch(self, cves: List[Dict[str, Any]]) -> bool:
        """Save multiple CVEs to database"""
        if not self.conn or not cves:
            return False
        
        try:
            cursor = self.conn.cursor()
            
            # Prepare data for batch insert
            values = []
            for cve in cves:
                values.append((
                    cve.get('ID', ''),
                    cve.get('Description', ''),
                    cve.get('Severity', 'UNKNOWN'),
                    cve.get('CVSS_Score'),
                    cve.get('CWE'),
                    cve.get('Published', ''),
                    cve.get('lastModified', ''),
                    json.dumps(cve.get('References', [])),
                    json.dumps(cve.get('Products', [])),
                    json.dumps(cve.get('metrics', {}))
                ))
            
            # Use ON CONFLICT to update existing records
            execute_batch(cursor, """
                INSERT INTO cves (id, description, severity, cvss_score, cwe, 
                                published, last_modified, references, products, metrics)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    description = EXCLUDED.description,
                    severity = EXCLUDED.severity,
                    cvss_score = EXCLUDED.cvss_score,
                    cwe = EXCLUDED.cwe,
                    published = EXCLUDED.published,
                    last_modified = EXCLUDED.last_modified,
                    references = EXCLUDED.references,
                    products = EXCLUDED.products,
                    metrics = EXCLUDED.metrics,
                    updated_at = CURRENT_TIMESTAMP
            """, values)
            
            self.conn.commit()
            print(f"[Database] Saved {len(cves)} CVEs to database")
            return True
            
        except Exception as e:
            print(f"[Database] Error saving CVEs: {e}")
            self.conn.rollback()
            return False
    
    def get_all_cves(self) -> List[Dict[str, Any]]:
        """Get all CVEs from database"""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT id, description, severity, cvss_score, cwe,
                       published, last_modified, references, products, metrics
                FROM cves
                ORDER BY published DESC
            """)
            
            rows = cursor.fetchall()
            
            # Convert to list of dicts (RealDictCursor already gives us dicts)
            cves = []
            for row in rows:
                cve = {
                    'ID': row['id'],
                    'Description': row['description'],
                    'Severity': row['severity'],
                    'CVSS_Score': row['cvss_score'],
                    'CWE': row['cwe'],
                    'Published': row['published'],
                    'lastModified': row['last_modified'],
                    'References': row['references'] if isinstance(row['references'], list) else [],
                    'Products': row['products'] if isinstance(row['products'], list) else [],
                    'metrics': row['metrics'] if isinstance(row['metrics'], dict) else {}
                }
                cves.append(cve)
            
            return cves
            
        except Exception as e:
            print(f"[Database] Error fetching CVEs: {e}")
            return []
    
    def get_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific CVE by ID"""
        if not self.conn:
            return None
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT id, description, severity, cvss_score, cwe,
                       published, last_modified, references, products, metrics
                FROM cves
                WHERE id = %s
            """, (cve_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            return {
                'ID': row['id'],
                'Description': row['description'],
                'Severity': row['severity'],
                'CVSS_Score': row['cvss_score'],
                'CWE': row['cwe'],
                'Published': row['published'],
                'lastModified': row['last_modified'],
                'References': row['references'] if isinstance(row['references'], list) else [],
                'Products': row['products'] if isinstance(row['products'], list) else [],
                'metrics': row['metrics'] if isinstance(row['metrics'], dict) else {}
            }
            
        except Exception as e:
            print(f"[Database] Error fetching CVE {cve_id}: {e}")
            return None
    
    def get_recent_cves(self, days: int = 30) -> List[Dict[str, Any]]:
        """Get CVEs from the last N days"""
        if not self.conn:
            return []
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT id, description, severity, cvss_score, cwe,
                       published, last_modified, references, products, metrics
                FROM cves
                WHERE published >= TO_CHAR(CURRENT_DATE - INTERVAL '%s days', 'YYYY-MM-DD')
                ORDER BY published DESC
            """, (days,))
            
            rows = cursor.fetchall()
            
            cves = []
            for row in rows:
                cve = {
                    'ID': row['id'],
                    'Description': row['description'],
                    'Severity': row['severity'],
                    'CVSS_Score': row['cvss_score'],
                    'CWE': row['cwe'],
                    'Published': row['published'],
                    'lastModified': row['last_modified'],
                    'References': row['references'] if isinstance(row['references'], list) else [],
                    'Products': row['products'] if isinstance(row['products'], list) else [],
                    'metrics': row['metrics'] if isinstance(row['metrics'], dict) else {}
                }
                cves.append(cve)
            
            return cves
            
        except Exception as e:
            print(f"[Database] Error fetching recent CVEs: {e}")
            return []
    
    def update_cache_metadata(self, key: str, total_records: int, metadata: Dict = None):
        """Update cache metadata"""
        if not self.conn:
            return
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO cache_metadata (key, last_updated, total_records, metadata)
                VALUES (%s, CURRENT_TIMESTAMP, %s, %s)
                ON CONFLICT (key) DO UPDATE SET
                    last_updated = CURRENT_TIMESTAMP,
                    total_records = EXCLUDED.total_records,
                    metadata = EXCLUDED.metadata
            """, (key, total_records, json.dumps(metadata or {})))
            
            self.conn.commit()
            
        except Exception as e:
            print(f"[Database] Error updating metadata: {e}")
            self.conn.rollback()
    
    def get_cache_metadata(self, key: str) -> Optional[Dict]:
        """Get cache metadata"""
        if not self.conn:
            return None
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT last_updated, total_records, metadata
                FROM cache_metadata
                WHERE key = %s
            """, (key,))
            
            row = cursor.fetchone()
            if row:
                return {
                    'last_updated': row['last_updated'],
                    'total_records': row['total_records'],
                    'metadata': row['metadata']
                }
            return None
            
        except Exception as e:
            print(f"[Database] Error fetching metadata: {e}")
            return None
    
    def clear_all_cves(self):
        """Clear all CVE data (for refresh)"""
        if not self.conn:
            return
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM cves")
            self.conn.commit()
            print("[Database] Cleared all CVEs from database")
            
        except Exception as e:
            print(f"[Database] Error clearing CVEs: {e}")
            self.conn.rollback()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        if not self.conn:
            return {'enabled': False}
        
        try:
            cursor = self.conn.cursor()
            
            cursor.execute("SELECT COUNT(*) as total FROM cves")
            total = cursor.fetchone()['total']
            
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM cves
                GROUP BY severity
            """)
            severity_counts = {row['severity']: row['count'] for row in cursor.fetchall()}
            
            return {
                'enabled': True,
                'total_cves': total,
                'severity_counts': severity_counts
            }
            
        except Exception as e:
            print(f"[Database] Error getting stats: {e}")
            return {'enabled': True, 'error': str(e)}
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            print("[Database] Connection closed")