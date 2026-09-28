
from __future__ import annotations
import sqlite3
from contextlib import contextmanager
from app.core.config import settings

DB_PATH=settings.app_data_dir/"casebook.sqlite3"

def _cols(conn,table): return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
def _add(conn,table,name,definition):
    if name not in _cols(conn,table): conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")

def init_db():
    with sqlite3.connect(DB_PATH) as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        c.executescript("""
        CREATE TABLE IF NOT EXISTS cases(
          id TEXT PRIMARY KEY,name TEXT NOT NULL,created_at TEXT NOT NULL,notes TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS evidence(
          id TEXT PRIMARY KEY,case_id TEXT NOT NULL,path TEXT NOT NULL,size_bytes INTEGER NOT NULL,
          sha256 TEXT NOT NULL,discovered_at TEXT NOT NULL,pre_scan_sha256 TEXT,post_scan_sha256 TEXT,
          FOREIGN KEY(case_id) REFERENCES cases(id)
        );
        CREATE TABLE IF NOT EXISTS scans(
          id TEXT PRIMARY KEY,case_id TEXT NOT NULL,evidence_id TEXT NOT NULL,status TEXT NOT NULL,
          progress REAL DEFAULT 0,stage TEXT DEFAULT 'queued',message TEXT DEFAULT '',
          started_at TEXT,finished_at TEXT,error TEXT,io_workers INTEGER,hash_workers INTEGER,
          resource_policy TEXT DEFAULT 'laptop',
          FOREIGN KEY(case_id) REFERENCES cases(id),FOREIGN KEY(evidence_id) REFERENCES evidence(id)
        );
        CREATE TABLE IF NOT EXISTS findings(
          id TEXT PRIMARY KEY,scan_id TEXT NOT NULL,inode INTEGER,name TEXT,path TEXT,file_type TEXT,
          size_bytes INTEGER,deletion_time TEXT,mode TEXT,confidence TEXT,recoverable INTEGER DEFAULT 0,
          recovered_path TEXT,recovered_sha256 TEXT,validation_status TEXT,source TEXT DEFAULT 'inode',
          metadata_json TEXT DEFAULT '{}',
          FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS artifacts(
          id TEXT PRIMARY KEY,scan_id TEXT NOT NULL,inode INTEGER,path TEXT,type TEXT,size_bytes INTEGER,
          atime TEXT,mtime TEXT,ctime TEXT,dtime TEXT,content TEXT DEFAULT '',
          content_sha256 TEXT,metadata_json TEXT DEFAULT '{}',
          FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS timeline_events(
          id TEXT PRIMARY KEY,scan_id TEXT NOT NULL,timestamp TEXT NOT NULL,local_time TEXT,
          source TEXT,event TEXT,details TEXT,classification TEXT DEFAULT 'fact',
          FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS integrity_events(
          id INTEGER PRIMARY KEY AUTOINCREMENT,case_id TEXT NOT NULL,evidence_id TEXT,scan_id TEXT,
          event_type TEXT NOT NULL,algorithm TEXT,value TEXT,created_at TEXT NOT NULL,details TEXT DEFAULT '',
          FOREIGN KEY(case_id) REFERENCES cases(id),FOREIGN KEY(evidence_id) REFERENCES evidence(id),
          FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        """)
        for name,definition in {
          "original_name":"TEXT","original_path":"TEXT","file_signature":"TEXT",
          "recovery_status":"TEXT","recovered_size_bytes":"INTEGER","confidence_score":"REAL",
          "journal_evidence_json":"TEXT DEFAULT '[]'","validation_reason":"TEXT",
          "original_name_candidates_json":"TEXT DEFAULT '[]'"
        }.items(): _add(c,"findings",name,definition)
        c.execute("PRAGMA user_version=3")

@contextmanager
def db_conn():
    c=sqlite3.connect(DB_PATH)
    c.row_factory=sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c;c.commit()
    finally: c.close()
