from __future__ import annotations
import json
from datetime import datetime, timezone
from app.db.database import db_conn, CASE_COLUMNS, EVIDENCE_COLUMNS


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def insert_case(i, name, notes="", details=None):
    details = dict(details or {})
    data = {k: details[k] for k in CASE_COLUMNS if k in details}
    if "notes" in details:
        notes = details["notes"]
    cols = ["id", "name", "created_at", "notes", *data.keys()]
    vals = [i, name, now_iso(), notes, *data.values()]
    with db_conn() as c:
        c.execute(f"INSERT INTO cases ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})", vals)


def update_case_details(case_id, name=None, details=None):
    details = dict(details or {})
    updates = {}
    if name:
        updates["name"] = name
    for key in (*CASE_COLUMNS.keys(), "notes"):
        if key in details:
            updates[key] = details[key]
    if not updates:
        return
    with db_conn() as c:
        c.execute(f"UPDATE cases SET {','.join(f'{k}=?' for k in updates)} WHERE id=?", (*updates.values(), case_id))


def get_case(i):
    with db_conn() as c:
        return c.execute("SELECT * FROM cases WHERE id=?", (i,)).fetchone()


def get_case_by_number(number):
    if not number:
        return None
    with db_conn() as c:
        return c.execute("SELECT * FROM cases WHERE case_number=?", (number,)).fetchone()


def insert_evidence(i, case_id, path, size, digest, details=None):
    details = dict(details or {})
    extra = {k: details[k] for k in EVIDENCE_COLUMNS if k in details}
    cols = ["id", "case_id", "path", "size_bytes", "sha256", "discovered_at", "pre_scan_sha256", *extra.keys()]
    vals = [i, case_id, path, size, digest, now_iso(), digest, *extra.values()]
    with db_conn() as c:
        c.execute(f"INSERT INTO evidence ({','.join(cols)}) VALUES ({','.join('?' for _ in cols)})", vals)


def set_post_hash(evidence_id, digest):
    with db_conn() as c:
        c.execute("UPDATE evidence SET post_scan_sha256=? WHERE id=?", (digest, evidence_id))


def insert_scan(i, case_id, evidence_id, io_w, hash_w, policy):
    with db_conn() as c:
        c.execute("INSERT INTO scans (id,case_id,evidence_id,status,progress,stage,message,io_workers,hash_workers,resource_policy) VALUES(?,?,?,?,?,?,?,?,?,?)",
                  (i, case_id, evidence_id, "queued", 0, "queued", "", io_w, hash_w, policy))


def update_scan(i, **kw):
    allowed = {"status", "progress", "stage", "message", "started_at", "finished_at", "error"}
    fields, vals = [], []
    for k, v in kw.items():
        if k in allowed and v is not None:
            fields.append(f"{k}=?")
            vals.append(v)
    if fields:
        with db_conn() as c:
            c.execute(f"UPDATE scans SET {','.join(fields)} WHERE id=?", (*vals, i))


def get_scan(i):
    q = """SELECT s.*, e.path AS evidence_path, e.size_bytes, e.sha256 AS evidence_sha256,
        e.pre_scan_sha256, e.post_scan_sha256, c.name AS case_name,
        e.evidence_item_number, e.evidence_type, e.description AS evidence_description,
        e.source_device, e.device_type, e.device_make_model, e.device_serial_number, e.device_owner,
        e.acquisition_method, e.acquisition_tool, e.acquisition_operator, e.acquisition_datetime,
        e.received_datetime, e.received_by, e.evidence_location, e.chain_of_custody_notes,
        c.case_number, c.case_reference, c.investigation_type, c.lead_investigator,
        c.requesting_organization, c.jurisdiction, c.incident_date_start, c.incident_date_end,
        c.timezone AS case_timezone, c.incident_summary, c.scope AS case_scope,
        c.legal_authority, c.status AS case_status, c.notes AS case_notes
        FROM scans s JOIN evidence e ON e.id=s.evidence_id JOIN cases c ON c.id=s.case_id WHERE s.id=?"""
    with db_conn() as c:
        return c.execute(q, (i,)).fetchone()


def insert_finding(f):
    with db_conn() as c:
        c.execute("INSERT INTO findings (id,scan_id,inode,name,path,file_type,size_bytes,deletion_time,mode,confidence,recoverable,recovered_path,recovered_sha256,validation_status,source,metadata_json,original_name,original_path,file_signature,recovery_status,recovered_size_bytes,confidence_score,journal_evidence_json,validation_reason,original_name_candidates_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (f["id"], f["scan_id"], f.get("inode"), f.get("name"), f.get("path"), f.get("file_type"), f.get("size_bytes"), f.get("deletion_time"), f.get("mode"), f.get("confidence", "medium"), int(bool(f.get("recoverable"))), f.get("recovered_path"), f.get("recovered_sha256"), f.get("validation_status"), f.get("source", "inode"), json.dumps(f.get("metadata", {}), sort_keys=True), f.get("original_name"), f.get("original_path"), f.get("file_signature"), f.get("recovery_status"), f.get("recovered_size_bytes"), f.get("confidence_score"), json.dumps(f.get("journal_evidence", []), sort_keys=True), f.get("validation_reason"), json.dumps(f.get("original_name_candidates", []), sort_keys=True)))


def update_finding(i, **kw):
    allowed = {"recovered_path", "recovered_sha256", "validation_status", "confidence", "recoverable", "metadata_json", "original_name", "original_path", "file_signature", "recovery_status", "recovered_size_bytes", "confidence_score", "journal_evidence_json", "validation_reason", "original_name_candidates_json"}
    fields, vals = [], []
    for k, v in kw.items():
        if k in allowed:
            fields.append(f"{k}=?")
            vals.append(int(bool(v)) if k == "recoverable" else v)
    if fields:
        with db_conn() as c:
            c.execute(f"UPDATE findings SET {','.join(fields)} WHERE id=?", (*vals, i))


def insert_artifact(a):
    with db_conn() as c:
        c.execute("INSERT OR REPLACE INTO artifacts (id,scan_id,inode,path,type,size_bytes,atime,mtime,ctime,dtime,content,content_sha256,metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (a["id"], a["scan_id"], a.get("inode"), a.get("path"), a.get("type"), a.get("size_bytes", a.get("size")), a.get("atime"), a.get("mtime"), a.get("ctime"), a.get("dtime"), a.get("content", ""), a.get("content_sha256"), json.dumps(a.get("metadata", {}), sort_keys=True)))


def insert_timeline(e):
    with db_conn() as c:
        c.execute("INSERT INTO timeline_events (id,scan_id,timestamp,local_time,source,event,details,classification) VALUES(?,?,?,?,?,?,?,?)",
                  (e["id"], e["scan_id"], e.get("timestamp") or "", e.get("local_time"), e.get("source"), e.get("event"), e.get("details", ""), e.get("classification", "fact")))


def list_findings(scan_id):
    with db_conn() as c:
        return c.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY inode,id", (scan_id,)).fetchall()


def list_artifacts(scan_id):
    with db_conn() as c:
        return c.execute("SELECT * FROM artifacts WHERE scan_id=? ORDER BY path", (scan_id,)).fetchall()


def list_timeline(scan_id):
    with db_conn() as c:
        return c.execute("SELECT * FROM timeline_events WHERE scan_id=? ORDER BY CASE WHEN timestamp='' THEN '9999' ELSE timestamp END,id", (scan_id,)).fetchall()


def list_integrity(case_id):
    with db_conn() as c:
        return c.execute("SELECT * FROM integrity_events WHERE case_id=? ORDER BY id", (case_id,)).fetchall()


def get_finding(i):
    with db_conn() as c:
        return c.execute("SELECT * FROM findings WHERE id=?", (i,)).fetchone()


def get_findings_by_ids(ids):
    ids = list(ids)
    if not ids:
        return []
    q = ",".join("?" for _ in ids)
    with db_conn() as c:
        return c.execute(f"SELECT * FROM findings WHERE id IN ({q})", ids).fetchall()


def insert_integrity(e):
    with db_conn() as c:
        c.execute("INSERT INTO integrity_events (case_id,evidence_id,scan_id,event_type,algorithm,value,created_at,details) VALUES(?,?,?,?,?,?,?,?)",
                  (e["case_id"], e.get("evidence_id"), e.get("scan_id"), e["event_type"], e.get("algorithm"), e.get("value"), now_iso(), e.get("details", "")))


def clear_artifacts(scan_id):
    with db_conn() as c:
        c.execute("DELETE FROM artifacts WHERE scan_id=?", (scan_id,))
        c.execute("DELETE FROM timeline_events WHERE scan_id=?", (scan_id,))
