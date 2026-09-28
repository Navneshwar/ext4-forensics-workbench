from __future__ import annotations
import json
import uuid
from pathlib import Path
from app.db.repository import get_scan, clear_artifacts, insert_artifact, insert_timeline
from app.forensics.pytsk_artifacts import extract_artifacts

def refresh_artifacts(scan_id: str, force: bool = True) -> dict:
    scan=get_scan(scan_id)
    if not scan: raise ValueError("Scan not found.")
    if force: clear_artifacts(scan_id)
    payload=extract_artifacts(Path(scan["evidence_path"]), int(json.loads(_analysis_details(scan, "{}"))["ext4"]["filesystem_offset"]))
    for a in payload.get("files",[]):
        insert_artifact({"id":str(uuid.uuid4()),"scan_id":scan_id,**a,"metadata":{"allocated":a.get("allocated"),"meta_type":a.get("meta_type")}})
    for e in payload.get("timeline",[]):
        insert_timeline({"id":str(uuid.uuid4()),"scan_id":scan_id,**e})
    return payload

def _analysis_details(scan, default):
    # Import locally so artifact refresh has one narrow dependency on integrity records.
    from app.db.repository import list_integrity
    for row in list_integrity(scan["case_id"]):
        if row["scan_id"]==scan["id"] and row["event_type"]=="analysis_completed":
            return row["details"]
    return default

def ensure_artifacts(scan_id: str) -> dict:
    from app.db.repository import list_artifacts
    if list_artifacts(scan_id):
        return {"status":"ok","message":"Artifacts already populated.","refreshed":False}
    payload=refresh_artifacts(scan_id,force=True)
    return {**payload,"refreshed":True}
