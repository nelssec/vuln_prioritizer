#!/usr/bin/env python3
import sqlite3
import json
from datetime import datetime, timedelta
from typing import Dict, Optional, List
import os


class EPSSCacheDB:
    def __init__(self, db_path: str = "epss_cache.db"):
        """Initialize the cache database"""
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self._init_database()
    
    def _init_database(self):
        """Create database tables if they don't exist"""
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        
        # EPSS scores cache table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS epss_cache (
                cve_id TEXT PRIMARY KEY,
                epss_score REAL,
                percentile REAL,
                model_version TEXT,
                score_date TEXT,
                cached_at TEXT,
                last_accessed TEXT
            )
        ''')
        
        # CISA KEV cache table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS cisa_kev_cache (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT,
                product TEXT,
                vulnerability_name TEXT,
                date_added TEXT,
                short_description TEXT,
                required_action TEXT,
                due_date TEXT,
                cached_at TEXT,
                last_accessed TEXT
            )
        ''')
        
        # API call log table
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_call_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_type TEXT,
                endpoint TEXT,
                parameters TEXT,
                status_code INTEGER,
                response_time REAL,
                cached BOOLEAN,
                timestamp TEXT
            )
        ''')
        
        # Metadata table for tracking database info
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT
            )
        ''')
        
        self.conn.commit()
        
        # Set database version
        self._set_metadata('db_version', '1.0')
        self._set_metadata('created_at', datetime.now().isoformat())
    
    def _set_metadata(self, key: str, value: str):
        """Set metadata key-value pair"""
        self.cursor.execute('''
            INSERT OR REPLACE INTO metadata (key, value, updated_at)
            VALUES (?, ?, ?)
        ''', (key, value, datetime.now().isoformat()))
        self.conn.commit()
    
    def _get_metadata(self, key: str) -> Optional[str]:
        """Get metadata value"""
        self.cursor.execute('SELECT value FROM metadata WHERE key = ?', (key,))
        result = self.cursor.fetchone()
        return result[0] if result else None
    
    def cache_epss_score(self, cve_id: str, epss_score: float, percentile: float, 
                        model_version: str = "", score_date: str = ""):
        """Cache an EPSS score"""
        now = datetime.now().isoformat()
        self.cursor.execute('''
            INSERT OR REPLACE INTO epss_cache 
            (cve_id, epss_score, percentile, model_version, score_date, cached_at, last_accessed)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (cve_id, epss_score, percentile, model_version, score_date, now, now))
        self.conn.commit()
    
    def get_epss_score(self, cve_id: str, max_age_days: int = 7) -> Optional[Dict]:
        """Get cached EPSS score if not expired"""
        self.cursor.execute('''
            SELECT epss_score, percentile, model_version, score_date, cached_at 
            FROM epss_cache 
            WHERE cve_id = ?
        ''', (cve_id,))
        
        result = self.cursor.fetchone()
        if not result:
            return None
        
        # Check if cache is expired
        cached_at = datetime.fromisoformat(result[4])
        if datetime.now() - cached_at > timedelta(days=max_age_days):
            return None
        
        # Update last accessed time
        self.cursor.execute('''
            UPDATE epss_cache 
            SET last_accessed = ?
            WHERE cve_id = ?
        ''', (datetime.now().isoformat(), cve_id))
        self.conn.commit()
        
        return {
            'epss': result[0],
            'percentile': result[1],
            'model_version': result[2],
            'score_date': result[3]
        }
    
    def cache_cisa_kev(self, cve_id: str, vendor_project: str, product: str,
                       vulnerability_name: str, date_added: str, short_description: str,
                       required_action: str, due_date: str):
        """Cache a CISA KEV entry"""
        now = datetime.now().isoformat()
        self.cursor.execute('''
            INSERT OR REPLACE INTO cisa_kev_cache 
            (cve_id, vendor_project, product, vulnerability_name, date_added,
             short_description, required_action, due_date, cached_at, last_accessed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (cve_id, vendor_project, product, vulnerability_name, date_added,
              short_description, required_action, due_date, now, now))
        self.conn.commit()
    
    def is_in_cisa_kev(self, cve_id: str, max_age_days: int = 1) -> bool:
        """Check if CVE is in CISA KEV (with cache expiration)"""
        self.cursor.execute('''
            SELECT cached_at FROM cisa_kev_cache WHERE cve_id = ?
        ''', (cve_id,))
        
        result = self.cursor.fetchone()
        if not result:
            return False
        
        # Check if cache is expired
        cached_at = datetime.fromisoformat(result[0])
        if datetime.now() - cached_at > timedelta(days=max_age_days):
            # Cache expired, need to refresh
            return False
        
        # Update last accessed time
        self.cursor.execute('''
            UPDATE cisa_kev_cache 
            SET last_accessed = ?
            WHERE cve_id = ?
        ''', (datetime.now().isoformat(), cve_id))
        self.conn.commit()
        
        return True
    
    def get_all_cisa_kev_cves(self, max_age_days: int = 1) -> set:
        """Get all CVEs in CISA KEV cache"""
        cutoff = (datetime.now() - timedelta(days=max_age_days)).isoformat()
        self.cursor.execute('''
            SELECT cve_id FROM cisa_kev_cache 
            WHERE cached_at > ?
        ''', (cutoff,))
        
        return {row[0] for row in self.cursor.fetchall()}
    
    def log_api_call(self, api_type: str, endpoint: str, parameters: Dict,
                     status_code: int, response_time: float, cached: bool = False):
        """Log an API call"""
        self.cursor.execute('''
            INSERT INTO api_call_log 
            (api_type, endpoint, parameters, status_code, response_time, cached, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (api_type, endpoint, json.dumps(parameters), status_code, 
              response_time, cached, datetime.now().isoformat()))
        self.conn.commit()
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        stats = {}
        
        # EPSS cache stats
        self.cursor.execute('SELECT COUNT(*) FROM epss_cache')
        stats['epss_cached_entries'] = self.cursor.fetchone()[0]
        
        # CISA KEV cache stats
        self.cursor.execute('SELECT COUNT(*) FROM cisa_kev_cache')
        stats['cisa_kev_cached_entries'] = self.cursor.fetchone()[0]
        
        # API call stats
        self.cursor.execute('SELECT COUNT(*) FROM api_call_log')
        stats['total_api_calls'] = self.cursor.fetchone()[0]
        
        self.cursor.execute('SELECT COUNT(*) FROM api_call_log WHERE cached = 1')
        stats['cached_api_calls'] = self.cursor.fetchone()[0]
        
        # Recent API calls
        self.cursor.execute('''
            SELECT api_type, COUNT(*) 
            FROM api_call_log 
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY api_type
        ''')
        stats['recent_calls_by_type'] = dict(self.cursor.fetchall())
        
        return stats
    
    def clear_expired_cache(self, epss_max_age_days: int = 7, kev_max_age_days: int = 1):
        """Clear expired cache entries"""
        epss_cutoff = (datetime.now() - timedelta(days=epss_max_age_days)).isoformat()
        kev_cutoff = (datetime.now() - timedelta(days=kev_max_age_days)).isoformat()
        
        self.cursor.execute('DELETE FROM epss_cache WHERE cached_at < ?', (epss_cutoff,))
        epss_deleted = self.cursor.rowcount
        
        self.cursor.execute('DELETE FROM cisa_kev_cache WHERE cached_at < ?', (kev_cutoff,))
        kev_deleted = self.cursor.rowcount
        
        self.conn.commit()
        
        return {'epss_deleted': epss_deleted, 'kev_deleted': kev_deleted}
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


if __name__ == "__main__":
    # Test the database
    print("EPSS Cache Database Test")
    print("=" * 60)
    
    db = EPSSCacheDB("test_cache.db")
    
    # Test caching EPSS score
    db.cache_epss_score("CVE-2024-1234", 0.5, 85.5, "v2023.03.01", "2024-10-01")
    
    # Test retrieving score
    score = db.get_epss_score("CVE-2024-1234")
    print(f"Retrieved score: {score}")
    
    # Test CISA KEV
    db.cache_cisa_kev("CVE-2024-1234", "Vendor", "Product", "Test Vuln",
                      "2024-01-01", "Test description", "Take action", "2024-02-01")
    
    is_kev = db.is_in_cisa_kev("CVE-2024-1234")
    print(f"Is in CISA KEV: {is_kev}")
    
    # Test API logging
    db.log_api_call("EPSS", "https://api.first.org/data/v1/epss",
                    {"cve": "CVE-2024-1234"}, 200, 0.5, False)
    
    # Get stats
    stats = db.get_cache_stats()
    print(f"\nCache Stats:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    db.close()
    
    # Clean up test database
    if os.path.exists("test_cache.db"):
        os.remove("test_cache.db")
    
    print("\nDatabase test completed successfully")
