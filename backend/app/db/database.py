from __future__ import annotations
import sqlite3
from contextlib import contextmanager
from app.core.config import settings

DB_PATH = settings.app_data_dir / "casebook.sqlite3"


def _cols(conn, table):
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _add(conn, table, name, definition):
    if name not in _cols(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


CASE_COLUMNS = {
    "case_number": "TEXT",
    "case_reference": "TEXT",
    "investigation_type": "TEXT",
    "lead_investigator": "TEXT",
    "requesting_organization": "TEXT",
    "jurisdiction": "TEXT",
    "incident_date_start": "TEXT",
    "incident_date_end": "TEXT",
    "timezone": "TEXT DEFAULT 'UTC'",
    "incident_summary": "TEXT DEFAULT ''",
    "scope": "TEXT DEFAULT ''",
    "legal_authority": "TEXT DEFAULT ''",
    "status": "TEXT DEFAULT 'Open'",
}

EVIDENCE_COLUMNS = {
    "evidence_item_number": "TEXT",
    "evidence_type": "TEXT",
    "description": "TEXT DEFAULT ''",
    "source_device": "TEXT DEFAULT ''",
    "device_type": "TEXT DEFAULT ''",
    "device_make_model": "TEXT DEFAULT ''",
    "device_serial_number": "TEXT DEFAULT ''",
    "device_owner": "TEXT DEFAULT ''",
    "acquisition_method": "TEXT DEFAULT ''",
    "acquisition_tool": "TEXT DEFAULT ''",
    "acquisition_operator": "TEXT DEFAULT ''",
    "acquisition_datetime": "TEXT",
    "received_datetime": "TEXT",
    "received_by": "TEXT DEFAULT ''",
    "evidence_location": "TEXT DEFAULT ''",
    "chain_of_custody_notes": "TEXT DEFAULT ''",
}


def init_db():
    with sqlite3.connect(DB_PATH) as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        c.executescript("""
        CREATE TABLE IF NOT EXISTS cases(
          id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL, notes TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS evidence(
          id TEXT PRIMARY KEY, case_id TEXT NOT NULL, path TEXT NOT NULL, size_bytes INTEGER NOT NULL,
          sha256 TEXT NOT NULL, discovered_at TEXT NOT NULL, pre_scan_sha256 TEXT, post_scan_sha256 TEXT,
          FOREIGN KEY(case_id) REFERENCES cases(id)
        );
        CREATE TABLE IF NOT EXISTS scans(
          id TEXT PRIMARY KEY, case_id TEXT NOT NULL, evidence_id TEXT NOT NULL, status TEXT NOT NULL,
          progress REAL DEFAULT 0, stage TEXT DEFAULT 'queued', message TEXT DEFAULT '',
          started_at TEXT, finished_at TEXT, error TEXT, io_workers INTEGER, hash_workers INTEGER,
          resource_policy TEXT DEFAULT 'laptop',
          FOREIGN KEY(case_id) REFERENCES cases(id), FOREIGN KEY(evidence_id) REFERENCES evidence(id)
        );
        CREATE TABLE IF NOT EXISTS findings(
          id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, inode INTEGER, name TEXT, path TEXT, file_type TEXT,
          size_bytes INTEGER, deletion_time TEXT, mode TEXT, confidence TEXT, recoverable INTEGER DEFAULT 0,
          recovered_path TEXT, recovered_sha256 TEXT, validation_status TEXT, source TEXT DEFAULT 'inode',
          metadata_json TEXT DEFAULT '{}',
          FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS artifacts(
          id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, inode INTEGER, path TEXT, type TEXT, size_bytes INTEGER,
          atime TEXT, mtime TEXT, ctime TEXT, dtime TEXT, content TEXT DEFAULT '',
          content_sha256 TEXT, metadata_json TEXT DEFAULT '{}',
          FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS timeline_events(
          id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, timestamp TEXT NOT NULL, local_time TEXT,
          source TEXT, event TEXT, details TEXT, classification TEXT DEFAULT 'fact',
          FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS integrity_events(
          id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL, evidence_id TEXT, scan_id TEXT,
          event_type TEXT NOT NULL, algorithm TEXT, value TEXT, created_at TEXT NOT NULL, details TEXT DEFAULT '',
          FOREIGN KEY(case_id) REFERENCES cases(id), FOREIGN KEY(evidence_id) REFERENCES evidence(id),
          FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        """)
        for name, definition in CASE_COLUMNS.items():
            _add(c, "cases", name, definition)
        for name, definition in EVIDENCE_COLUMNS.items():
            _add(c, "evidence", name, definition)
        for name, definition in {
            "original_name": "TEXT", "original_path": "TEXT", "file_signature": "TEXT",
            "recovery_status": "TEXT", "recovered_size_bytes": "INTEGER", "confidence_score": "REAL",
            "journal_evidence_json": "TEXT DEFAULT '[]'", "validation_reason": "TEXT",
            "original_name_candidates_json": "TEXT DEFAULT '[]'"
        }.items():
            _add(c, "findings", name, definition)
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_cases_case_number ON cases(case_number) WHERE case_number IS NOT NULL AND case_number != ''")
        c.execute("PRAGMA user_version=4")


@contextmanager
def db_conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    finally:
        c.close()
