import os
import psycopg2
from psycopg2.extras import RealDictCursor, execute_batch
from psycopg2 import pool
from typing import List, Dict, Any, Optional
import json
from datetime import datetime

class DatabaseManager:
    """Manages PostgreSQL database connections - MEMORY OPTIMIZED WITH PAGINATION"""
    
    def __init__(self):
        self.database_url = os.environ.get('DATABASE_URL')
        self.connection_pool = None
        self.use_database = bool(self.database_url)
        
        if self.use_database:
            print("[Database] Database URL found, database mode ENABLED")
            self.init_connection_pool()
            self.init_tables()
        else:
            print("[Database] No DATABASE_URL found, database mode DISABLED (using memory)")
    
    def init_connection_pool(self):
        """Initialize connection pool with MINIMAL connections"""
        if not self.database_url:
            return False
        
        try:
            database_url = self.database_url.replace('postgres://', 'postgresql://', 1)
            self.connection_pool = pool.SimpleConnectionPool(
                1,  # Min connections
                2,  # Max connections - OPTIMIZED FOR LOW MEMORY
                database_url
            )
            print("[Database] Connection pool initialized (1-2 connections)")
            return True
        except Exception as e:
            print(f"[Database] Connection pool error: {e}")
            self.use_database = False
            return False
    
    def get_connection(self):
        """Get connection from pool"""
        if self.connection_pool:
            return self.connection_pool.getconn()
        return None
    
    def return_connection(self, conn):
        """Return connection to pool"""
        if self.connection_pool and conn:
            self.connection_pool.putconn(conn)
    
    def init_tables(self):
        """Initialize database tables if they don't exist"""
        conn = self.get_connection()
        if not conn:
            return
        
        try:
            cursor = conn.cursor()
            
            # CVE table with optimized indexes
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cves (
                    id VARCHAR(50) PRIMARY KEY,
                    description TEXT,
                    severity VARCHAR(20),
                    cvss_score FLOAT,
                    cwe VARCHAR(50),
                    published VARCHAR(50),
                    last_modified VARCHAR(50),
                    reference_links JSONB,
                    products JSONB,
                    metrics JSONB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cves_cwe ON cves(cwe)")
            
            # Cache metadata table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cache_metadata (
                    key VARCHAR(100) PRIMARY KEY,
                    last_updated TIMESTAMP,
                    total_records INTEGER,
                    metadata JSONB
                )
            """)
            
            # Vendor risk cache table for 24h caching
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vendor_risk_cache (
                    id SERIAL PRIMARY KEY,
                    vendor_risk JSONB,
                    weighted_risk JSONB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
            print("[Database] Tables initialized successfully")
        except Exception as e:
            print(f"[Database] Error initializing tables: {e}")
            conn.rollback()
        finally:
            cursor.close()
            self.return_connection(conn)
    
    def save_cves_batch(self, cves: List[Dict[str, Any]]) -> bool:
        """Save multiple CVEs to database - MEMORY OPTIMIZED"""
        if not self.use_database or not cves:
            return False
        
        conn = self.get_connection()
        if not conn:
            return False
        
        try:
            cursor = conn.cursor()
            values = []
            
            for cve in cves:
                refs = cve.get('References', [])[:3]  # Limit references to save space
                values.append((
                    cve.get('ID'),
                    cve.get('Description', '')[:500],  # Limit description length
                    cve.get('Severity'),
                    cve.get('CVSSScore'),
                    cve.get('CWE'),
                    cve.get('Published'),
                    cve.get('LastModified'),
                    json.dumps(refs),
                    None,  # products - not stored to save space
                    None   # metrics - not stored to save space
                ))
            
            # Use ON CONFLICT to update existing records
            query = """
                INSERT INTO cves (id, description, severity, cvss_score, cwe, published, 
                    last_modified, reference_links, products, metrics)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    description = EXCLUDED.description,
                    severity = EXCLUDED.severity,
                    cvss_score = EXCLUDED.cvss_score,
                    cwe = EXCLUDED.cwe,
                    last_modified = EXCLUDED.last_modified,
                    updated_at = CURRENT_TIMESTAMP
            """
            
            execute_batch(cursor, query, values, page_size=100)
            conn.commit()
            print(f"[Database] Saved {len(cves)} CVEs successfully")
            return True
        except Exception as e:
            print(f"[Database] Error saving CVEs: {e}")
            conn.rollback()
            return False
        finally:
            cursor.close()
            self.return_connection(conn)
    
    def get_all_cves(self, limit=100, offset=0) -> List[Dict[str, Any]]:
        """Get all CVEs with PAGINATION - MEMORY SAFE - ONLY ESSENTIAL FIELDS"""
        if not self.use_database:
            return []
        
        conn = self.get_connection()
        if not conn:
            return []
        
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            # Only select essential fields to reduce memory usage
            cursor.execute("""
                SELECT id, description, severity, cvss_score, cwe, published, 
                    last_modified, reference_links
                FROM cves
                ORDER BY published DESC
                LIMIT %s OFFSET %s
            """, (limit, offset))
            
            rows = cursor.fetchall()
            
            cves = []
            for row in rows:
                cves.append({
                    'ID': row['id'],
                    'Description': row['description'],
                    'Severity': row['severity'],
                    'CVSSScore': row['cvss_score'],
                    'CWE': row['cwe'],
                    'Published': row['published'],
                    'LastModified': row['last_modified'],
                    'References': json.loads(row['reference_links']) if row['reference_links'] else []
                })
            
            return cves
        except Exception as e:
            print(f"[Database] Error getting CVEs: {e}")
            return []
        finally:
            cursor.close()
            self.return_connection(conn)
    
    def get_cve_count(self) -> int:
        """Get total count of CVEs in database"""
        if not self.use_database:
            return 0
        
        conn = self.get_connection()
        if not conn:
            return 0
        
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM cves")
            count = cursor.fetchone()[0]
            return count
        except Exception as e:
            print(f"[Database] Error getting CVE count: {e}")
            return 0
        finally:
            cursor.close()
            self.return_connection(conn)
    
    def search_cves(self, keyword: str, limit=50) -> List[Dict[str, Any]]:
        """Search CVEs by keyword - MEMORY SAFE - ONLY ESSENTIAL FIELDS"""
        if not self.use_database:
            return []
        
        conn = self.get_connection()
        if not conn:
            return []
        
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            search_pattern = f"%{keyword}%"
            
            # Only select essential fields
            cursor.execute("""
                SELECT id, description, severity, cvss_score, cwe, published, 
                    last_modified, reference_links
                FROM cves
                WHERE id ILIKE %s OR description ILIKE %s
                ORDER BY published DESC
                LIMIT %s
            """, (search_pattern, search_pattern, limit))
            
            rows = cursor.fetchall()
            
            cves = []
            for row in rows:
                cves.append({
                    'ID': row['id'],
                    'Description': row['description'],
                    'Severity': row['severity'],
                    'CVSSScore': row['cvss_score'],
                    'CWE': row['cwe'],
                    'Published': row['published'],
                    'LastModified': row['last_modified'],
                    'References': json.loads(row['reference_links']) if row['reference_links'] else []
                })
            
            return cves
        except Exception as e:
            print(f"[Database] Error searching CVEs: {e}")
            return []
        finally:
            cursor.close()
            self.return_connection(conn)
    
    def get_cache_metadata(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cache metadata"""
        if not self.use_database:
            return None
        
        conn = self.get_connection()
        if not conn:
            return None
        
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("SELECT * FROM cache_metadata WHERE key = %s", (key,))
            row = cursor.fetchone()
            return dict(row) if row else None
        except Exception as e:
            print(f"[Database] Error getting cache metadata: {e}")
            return None
        finally:
            cursor.close()
            self.return_connection(conn)
    
    def update_cache_metadata(self, key: str, total_records: int) -> bool:
        """Update cache metadata"""
        if not self.use_database:
            return False
        
        conn = self.get_connection()
        if not conn:
            return False
        
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO cache_metadata (key, last_updated, total_records)
                VALUES (%s, %s, %s)
                ON CONFLICT (key) DO UPDATE SET
                    last_updated = EXCLUDED.last_updated,
                    total_records = EXCLUDED.total_records
            """, (key, datetime.now(), total_records))
            
            conn.commit()
            return True
        except Exception as e:
            print(f"[Database] Error updating cache metadata: {e}")
            conn.rollback()
            return False
        finally:
            cursor.close()
            self.return_connection(conn)
    
    def save_vendor_risk_cache(self, vendor_risk: Dict, weighted_risk: Dict) -> bool:
        """Save vendor risk analysis to cache (24h cache)"""
        if not self.use_database:
            return False
        
        conn = self.get_connection()
        if not conn:
            return False
        
        try:
            cursor = conn.cursor()
            
            # Clear old cache entries
            cursor.execute("DELETE FROM vendor_risk_cache")
            
            # Insert new cache
            cursor.execute("""
                INSERT INTO vendor_risk_cache (vendor_risk, weighted_risk, updated_at)
                VALUES (%s, %s, CURRENT_TIMESTAMP)
            """, (json.dumps(vendor_risk), json.dumps(weighted_risk)))
            
            conn.commit()
            print("[Database] Vendor risk cache saved successfully")
            return True
        except Exception as e:
            print(f"[Database] Error saving vendor risk cache: {e}")
            conn.rollback()
            return False
        finally:
            cursor.close()
            self.return_connection(conn)
    
    def get_vendor_risk_cache(self) -> Optional[Dict[str, Any]]:
        """Get vendor risk analysis from cache"""
        if not self.use_database:
            return None
        
        conn = self.get_connection()
        if not conn:
            return None
        
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT vendor_risk, weighted_risk, updated_at
                FROM vendor_risk_cache
                ORDER BY updated_at DESC
                LIMIT 1
            """)
            
            row = cursor.fetchone()
            if row:
                return {
                    'vendor_risk': row['vendor_risk'],
                    'weighted_risk': row['weighted_risk'],
                    'updated_at': row['updated_at']
                }
            return None
        except Exception as e:
            print(f"[Database] Error getting vendor risk cache: {e}")
            return None
        finally:
            cursor.close()
            self.return_connection(conn)
