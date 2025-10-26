import os
import psycopg2
from psycopg2.extras import RealDictCursor, execute_batch
from psycopg2 import pool
from typing import List, Dict, Any, Optional
import json
from datetime import datetime
import config

# Import memory monitor
try:
    from memory_monitor import memory_monitor
except:
    memory_monitor = None

class DatabaseManager:
    """Manages PostgreSQL database connections - OPTIMIZED FOR RENDER FREE TIER (512MB)"""
    
    def __init__(self):
        # Get database URL from environment variable
        self.database_url = os.environ.get('DATABASE_URL')
        self.connection_pool = None
        self.use_database = bool(self.database_url)
        self.is_render = os.environ.get('RENDER') == 'true'
        
        if self.use_database:
            print("[Database] ✓ Database URL found, database mode ENABLED")
            self.init_connection_pool()
            self.init_tables()
        else:
            print("[Database] ⚠️ No DATABASE_URL found")
            if self.is_render:
                print("[Database] 🔴 CRITICAL: Database required on Render!")
            else:
                print("[Database] Using memory mode (local dev)")
    
    def init_connection_pool(self):
        """Initialize connection pool with MINIMAL connections for Render"""
        if not self.database_url:
            return False
        
        try:
            # Fix URL format for psycopg2
            database_url = self.database_url
            if database_url.startswith('postgres://'):
                database_url = database_url.replace('postgres://', 'postgresql://', 1)
            
            # MINIMAL connection pool for Render free tier
            if self.is_render:
                min_conn = 1
                max_conn = 2  # Very limited on free tier
            else:
                min_conn = 1
                max_conn = 3
            
            self.connection_pool = pool.SimpleConnectionPool(
                min_conn,
                max_conn,
                database_url
            )
            print(f"[Database] ✓ Connection pool initialized ({min_conn}-{max_conn} connections)")
            return True
            
        except Exception as e:
            print(f"[Database] 🔴 Connection pool error: {e}")
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
            
            print("[Database] Creating tables...")
            
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
                    reference_links JSONB,
                    products JSONB,
                    metrics JSONB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for better query performance
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
            
            conn.commit()
            print("[Database] ✓ Tables initialized successfully")
            
        except Exception as e:
            print(f"[Database] 🔴 Error initializing tables: {e}")
            conn.rollback()
        finally:
            cursor.close()
            self.return_connection(conn)
    
    def save_cves_batch(self, cves: List[Dict[str, Any]]) -> bool:
        """Save multiple CVEs to database - MEMORY OPTIMIZED"""
        if not self.use_database or not cves:
            return False
        
        # Memory check before operation
        if memory_monitor and not memory_monitor.check_memory_limit("save_cves_batch"):
            print("[Database] ⚠️ Skipping batch save - low memory")
            return False
        
        conn = self.get_connection()
        if not conn:
            return False
        
        try:
            cursor = conn.cursor()
            
            # Process in smaller sub-batches to save memory
            batch_size = getattr(config, 'MAX_BATCH_SIZE', 100)
            total_saved = 0
            
            for i in range(0, len(cves), batch_size):
                sub_batch = cves[i:i + batch_size]
                
                # Prepare data - MINIMAL fields to save space
                values = []
                for cve in sub_batch:
                    # Limit references to first 2 to save space
                    refs = cve.get('References', [])[:2]
                    
                    values.append((
                        cve.get('ID', ''),
                        cve.get('Description', '')[:500],  # Truncate long descriptions
                        cve.get('Severity', 'UNKNOWN'),
                        cve.get('CVSS_Score'),
                        cve.get('CWE'),
                        cve.get('Published', ''),
                        cve.get('lastModified', ''),
                        json.dumps(refs),
                        json.dumps([]),  # Empty products to save space
                        json.dumps({})   # Empty metrics to save space
                    ))
                
                # Use ON CONFLICT to update existing records
                execute_batch(cursor, """
                    INSERT INTO cves (id, description, severity, cvss_score, cwe,
                                    published, last_modified, reference_links, products, metrics)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        description = EXCLUDED.description,
                        severity = EXCLUDED.severity,
                        cvss_score = EXCLUDED.cvss_score,
                        cwe = EXCLUDED.cwe,
                        published = EXCLUDED.published,
                        last_modified = EXCLUDED.last_modified,
                        reference_links = EXCLUDED.reference_links,
                        updated_at = CURRENT_TIMESTAMP
                """, values)
                
                total_saved += len(sub_batch)
                
                # Memory check between batches
                if memory_monitor:
                    memory_monitor.log_memory(f"Saved {total_saved}/{len(cves)} CVEs")
            
            conn.commit()
            print(f"[Database] ✓ Saved {total_saved} CVEs to database")
            return True
            
        except Exception as e:
            print(f"[Database] 🔴 Error saving CVEs: {e}")
            conn.rollback()
            return False
        finally:
            cursor.close()
            self.return_connection(conn)
    
    def get_cves_paginated(self, page: int = 1, per_page: int = 20, 
                          severity: str = None, search: str = None) -> Dict[str, Any]:
        """Get CVEs with pagination - CRITICAL for memory optimization"""
        if not self.use_database:
            return {'cves': [], 'total': 0, 'page': page, 'per_page': per_page}
        
        conn = self.get_connection()
        if not conn:
            return {'cves': [], 'total': 0, 'page': page, 'per_page': per_page}
        
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            # Build query with filters
            where_clauses = []
            params = []
            
            if severity:
                where_clauses.append("severity = %s")
                params.append(severity.upper())
            
            if search:
                where_clauses.append("(id ILIKE %s OR description ILIKE %s OR cwe ILIKE %s)")
                search_param = f"%{search}%"
                params.extend([search_param, search_param, search_param])
            
            where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""
            
            # Get total count
            cursor.execute(f"SELECT COUNT(*) as total FROM cves{where_sql}", params)
            total = cursor.fetchone()['total']
            
            # Get paginated results
            offset = (page - 1) * per_page
            params.extend([per_page, offset])
            
            cursor.execute(f"""
                SELECT id, description, severity, cvss_score, cwe,
                       published, last_modified, reference_links
                FROM cves
                {where_sql}
                ORDER BY published DESC
                LIMIT %s OFFSET %s
            """, params)
            
            rows = cursor.fetchall()
            
            # Convert to list of dicts
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
                    'References': row['reference_links'] if isinstance(row['reference_links'], list) else []
                }
                cves.append(cve)
            
            return {
                'cves': cves,
                'total': total,
                'page': page,
                'per_page': per_page,
                'total_pages': (total + per_page - 1) // per_page
            }
            
        except Exception as e:
            print(f"[Database] 🔴 Error fetching paginated CVEs: {e}")
            return {'cves': [], 'total': 0, 'page': page, 'per_page': per_page}
        finally:
            cursor.close()
            self.return_connection(conn)
    
    def get_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific CVE by ID"""
        if not self.use_database:
            return None
        
        conn = self.get_connection()
        if not conn:
            return None
        
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT id, description, severity, cvss_score, cwe,
                       published, last_modified, reference_links, products, metrics
                FROM cves
                WHERE id = %s
            """, (cve_id,))
            
            row = cursor.fetchone()
            
            if row:
                return {
                    'ID': row['id'],
                    'Description': row['description'],
                    'Severity': row['severity'],
                    'CVSS_Score': row['cvss_score'],
                    'CWE': row['cwe'],
                    'Published': row['published'],
                    'lastModified': row['last_modified'],
                    'References': row['reference_links'] if isinstance(row['reference_links'], list) else [],
                    'Products': row['products'] if isinstance(row['products'], list) else [],
                    'metrics': row['metrics'] if isinstance(row['metrics'], dict) else {}
                }
            
            return None
            
        except Exception as e:
            print(f"[Database] 🔴 Error fetching CVE {cve_id}: {e}")
            return None
        finally:
            cursor.close()
            self.return_connection(conn)
    
    def get_severity_counts(self) -> Dict[str, int]:
        """Get count of CVEs by severity - for dashboard"""
        if not self.use_database:
            return {}
        
        conn = self.get_connection()
        if not conn:
            return {}
        
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM cves
                GROUP BY severity
            """)
            
            rows = cursor.fetchall()
            return {row['severity']: row['count'] for row in rows}
            
        except Exception as e:
            print(f"[Database] 🔴 Error getting severity counts: {e}")
            return {}
        finally:
            cursor.close()
            self.return_connection(conn)
    
    def update_cache_metadata(self, key: str, total_records: int, metadata: Dict = None):
        """Update cache metadata"""
        if not self.use_database:
            return
        
        conn = self.get_connection()
        if not conn:
            return
        
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO cache_metadata (key, last_updated, total_records, metadata)
                VALUES (%s, CURRENT_TIMESTAMP, %s, %s)
                ON CONFLICT (key) DO UPDATE SET
                    last_updated = CURRENT_TIMESTAMP,
                    total_records = EXCLUDED.total_records,
                    metadata = EXCLUDED.metadata
            """, (key, total_records, json.dumps(metadata or {})))
            
            conn.commit()
            
        except Exception as e:
            print(f"[Database] 🔴 Error updating metadata: {e}")
            conn.rollback()
        finally:
            cursor.close()
            self.return_connection(conn)
    
    def get_cache_metadata(self, key: str) -> Optional[Dict]:
        """Get cache metadata"""
        if not self.use_database:
            return None
        
        conn = self.get_connection()
        if not conn:
            return None
        
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
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
            print(f"[Database] 🔴 Error fetching metadata: {e}")
            return None
        finally:
            cursor.close()
            self.return_connection(conn)
    
    def clear_all_cves(self):
        """Clear all CVE data (for refresh)"""
        if not self.use_database:
            return
        
        conn = self.get_connection()
        if not conn:
            return
        
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cves")
            cursor.execute("DELETE FROM cache_metadata")
            conn.commit()
            print("[Database] ✓ All CVE data cleared")
            
        except Exception as e:
            print(f"[Database] 🔴 Error clearing data: {e}")
            conn.rollback()
        finally:
            cursor.close()
            self.return_connection(conn)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        if not self.use_database:
            return {'using_database': False}
        
        conn = self.get_connection()
        if not conn:
            return {'using_database': False}
        
        try:
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            # Get total CVE count
            cursor.execute("SELECT COUNT(*) as total FROM cves")
            total = cursor.fetchone()['total']
            
            # Get severity distribution
            severity_counts = self.get_severity_counts()
            
            return {
                'total_cves': total,
                'severity_distribution': severity_counts,
                'using_database': True
            }
            
        except Exception as e:
            print(f"[Database] 🔴 Error getting stats: {e}")
            return {'using_database': True, 'error': str(e)}
        finally:
            cursor.close()
            self.return_connection(conn)
    
    def close(self):
        """Close all connections in the pool"""
        if self.connection_pool:
            self.connection_pool.closeall()
            print("[Database] Connection pool closed")