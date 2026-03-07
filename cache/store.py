#!/usr/bin/env python3

import sqlite3
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


class FeedCache:
    def __init__(self, db_path: str = "feed_cache.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._registered_feeds: Dict[str, int] = {}
        self._init_meta_table()

    def _init_meta_table(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS feed_registry (
                feed_name TEXT PRIMARY KEY,
                ttl_days INTEGER NOT NULL,
                registered_at TEXT NOT NULL
            )
        """)
        self.conn.commit()

        # Load existing registrations
        for row in self.conn.execute("SELECT feed_name, ttl_days FROM feed_registry"):
            self._registered_feeds[row[0]] = row[1]

    def register_feed(self, name: str, ttl_days: int, schema_sql: str):
        """Register a new feed with its schema. Idempotent."""
        self.conn.execute(schema_sql)
        self.conn.execute(
            "INSERT OR REPLACE INTO feed_registry (feed_name, ttl_days, registered_at) VALUES (?, ?, ?)",
            (name, ttl_days, datetime.now().isoformat()),
        )
        self.conn.commit()
        self._registered_feeds[name] = ttl_days

    def get_ttl(self, feed_name: str) -> int:
        return self._registered_feeds.get(feed_name, 7)

    def is_expired(self, cached_at_iso: str, feed_name: str) -> bool:
        ttl = self.get_ttl(feed_name)
        cached_at = datetime.fromisoformat(cached_at_iso)
        return datetime.now() - cached_at > timedelta(days=ttl)

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        return self.conn.execute(sql, params)

    def executemany(self, sql: str, params_list: List[tuple]):
        self.conn.executemany(sql, params_list)

    def commit(self):
        self.conn.commit()

    def fetchone(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        cursor = self.conn.execute(sql, params)
        return cursor.fetchone()

    def fetchall(self, sql: str, params: tuple = ()) -> List[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    def clear_expired(self, table: str, feed_name: str, timestamp_column: str = "cached_at"):
        ttl = self.get_ttl(feed_name)
        cutoff = (datetime.now() - timedelta(days=ttl)).isoformat()
        self.conn.execute(f"DELETE FROM {table} WHERE {timestamp_column} < ?", (cutoff,))
        self.conn.commit()

    def close(self):
        if self.conn:
            self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
