from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.resources import snapshot
from app.db.repository import (
    get_case, get_case_by_number, get_finding, get_findings_by_ids, get_scan,
    insert_case, insert_evidence, insert_scan, list_artifacts, list_findings,
    list_timeline, update_case_details,
)
from app.forensics.hashing import sha256_file
from app.services.integrity_ledger import verify_chain
from app.services.scanner import submit_scan, recover_findings
from app.services.report_builder import build_report
from app.services.docx_report import generate_docx
from app.services.artifact_service import refresh_artifacts

router = APIRouter(prefix="/api")


class ScanRequest(BaseModel):
    image_path: str = Field(min_length=1, max_length=4096)
    case_id: str | None = None
    case_name: str = Field(default="EXT4 recovery case", min_length=1, max_length=160)
    case_number: str | None = Field(default=None, max_length=80)
    attach_to_existing_case: bool = False
    case_reference: str | None = Field(default=None, max_length=160)
    investigation_type: str | None = Field(default=None, max_length=120)
    lead_investigator: str | None = Field(default=None, max_length=160)
    requesting_organization: str | None = Field(default=None, max_length=200)
    jurisdiction: str | None = Field(default=None, max_length=160)
    incident_date_start: str | None = Field(default=None, max_length=80)
    incident_date_end: str | None = Field(default=None, max_length=80)
    timezone: str | None = Field(default="UTC", max_length=80)
    incident_summary: str | None = Field(default=None, max_length=6000)
    scope: str | None = Field(default=None, max_length=6000)
    legal_authority: str | None = Field(default=None, max_length=2000)
    case_status: str | None = Field(default="Open", max_length=40)
    notes: str | None = Field(default=None, max_length=6000)

    evidence_item_number: str | None = Field(default=None, max_length=80)
    evidence_type: str | None = Field(default="Disk image", max_length=120)
    evidence_description: str | None = Field(default=None, max_length=2000)
    source_device: str | None = Field(default=None, max_length=200)
    device_type: str | None = Field(default=None, max_length=120)
    device_make_model: str | None = Field(default=None, max_length=200)
    device_serial_number: str | None = Field(default=None, max_length=200)
    device_owner: str | None = Field(default=None, max_length=200)
    acquisition_method: str | None = Field(default=None, max_length=160)
    acquisition_tool: str | None = Field(default=None, max_length=200)
    acquisition_operator: str | None = Field(default=None, max_length=160)
    acquisition_datetime: str | None = Field(default=None, max_length=80)
    received_datetime: str | None = Field(default=None, max_length=80)
    received_by: str | None = Field(default=None, max_length=160)
    evidence_location: str | None = Field(default=None, max_length=500)
    chain_of_custody_notes: str | None = Field(default=None, max_length=6000)

    io_workers: int = Field(default=1, ge=1, le=8)
    hash_workers: int = Field(default=2, ge=1, le=8)
    resource_policy: str = Field(default="laptop", max_length=40)


class RecoverRequest(BaseModel):
    finding_ids: list[str] = Field(min_length=1, max_length=100)


CASE_FIELD_MAP = {
    "case_number": "case_number", "case_reference": "case_reference",
    "investigation_type": "investigation_type", "lead_investigator": "lead_investigator",
    "requesting_organization": "requesting_organization", "jurisdiction": "jurisdiction",
    "incident_date_start": "incident_date_start", "incident_date_end": "incident_date_end",
    "timezone": "timezone", "incident_summary": "incident_summary", "scope": "scope",
    "legal_authority": "legal_authority", "case_status": "status", "notes": "notes",
}
EVIDENCE_FIELD_MAP = {
    "evidence_item_number": "evidence_item_number", "evidence_type": "evidence_type",
    "evidence_description": "description", "source_device": "source_device", "device_type": "device_type",
    "device_make_model": "device_make_model", "device_serial_number": "device_serial_number",
    "device_owner": "device_owner", "acquisition_method": "acquisition_method",
    "acquisition_tool": "acquisition_tool", "acquisition_operator": "acquisition_operator",
    "acquisition_datetime": "acquisition_datetime", "received_datetime": "received_datetime",
    "received_by": "received_by", "evidence_location": "evidence_location",
    "chain_of_custody_notes": "chain_of_custody_notes",
}


def norm(raw: str) -> Path:
    s = raw.strip()
    while len(s) >= 2 and s[0] == s[-1] and s[0] in {'"', "'"}:
        s = s[1:-1].strip()
    return Path(os.path.expandvars(s)).expanduser()


def _generated_case_number() -> str:
    return f"CASE-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:6].upper()}"


@router.get("/health")
def health():
    return {"status": "ok", "version": "0.5.1"}


@router.get("/system/resources")
def resources():
    return snapshot()


@router.get("/system/ai-status")
def ai_status():
    return {
        "provider": "Groq",
        "configured": bool(settings.groq_api_key),
        "model": settings.groq_model,
        "message": "Groq narrative generation is enabled." if settings.groq_api_key else "GROQ_API_KEY is not set; report exports will use a labelled local fallback narrative.",
    }


@router.post("/scans")
def create_scan(req: ScanRequest):
    path = norm(req.image_path)
    if not path.exists() or not path.is_file():
        raise HTTPException(400, f"Image file does not exist: {path}")

    sent = req.model_dump(exclude_unset=True)
    case_details = {db_key: getattr(req, req_key) for req_key, db_key in CASE_FIELD_MAP.items()
                    if req_key in sent}
    evidence_details = {db_key: getattr(req, req_key) for req_key, db_key in EVIDENCE_FIELD_MAP.items()
                        if req_key in sent}

    case_id = req.case_id
    if case_id:
        existing = get_case(case_id)
        if not existing:
            raise HTTPException(404, "Case not found.")
        requested_number = case_details.get("case_number")
        if requested_number and requested_number != existing["case_number"]:
            other = get_case_by_number(requested_number)
            if other and other["id"] != case_id:
                raise HTTPException(409, "That case number is already assigned to another case.")
        try:
            update_case_details(case_id, name=req.case_name if "case_name" in sent else None, details=case_details)
        except Exception as exc:
            raise HTTPException(409, f"Could not update case metadata: {exc}")
    else:
        supplied_number = (req.case_number or "").strip()
        matching_case = get_case_by_number(supplied_number) if supplied_number else None
        if matching_case:
            # Reuse the matching case number automatically; the simplified UI does
            # not expose a separate attach-to-existing-case toggle.
            case_id = matching_case["id"]
            try:
                update_case_details(case_id, name=req.case_name, details=case_details)
            except Exception as exc:
                raise HTTPException(409, f"Could not update existing case metadata: {exc}")
        else:
            case_id = str(uuid.uuid4())
            case_number = supplied_number or _generated_case_number()
            case_details["case_number"] = case_number
            try:
                insert_case(case_id, req.case_name, notes=case_details.get("notes") or "", details=case_details)
            except Exception as exc:
                raise HTTPException(409, f"Could not create case: {exc}")

    digest = sha256_file(path)
    evidence_id = str(uuid.uuid4())
    evidence_details.setdefault("evidence_item_number", f"EVD-{evidence_id[:8].upper()}")
    try:
        insert_evidence(evidence_id, case_id, str(path.resolve()), path.stat().st_size, digest, evidence_details)
    except Exception as exc:
        raise HTTPException(500, f"Could not register evidence: {exc}")

    io_w = min(settings.max_io_workers, max(1, req.io_workers))
    hash_w = min(settings.max_hash_workers, max(1, req.hash_workers))
    scan_id = str(uuid.uuid4())
    insert_scan(scan_id, case_id, evidence_id, io_w, hash_w, req.resource_policy)
    submit_scan(scan_id, case_id, evidence_id)
    return {
        "scan_id": scan_id, "case_id": case_id, "evidence_id": evidence_id,
        "case_number": case_details.get("case_number") or (get_case(case_id)["case_number"] if get_case(case_id) else None),
        "evidence_item_number": evidence_details["evidence_item_number"],
        "sha256": digest, "path": str(path.resolve()), "io_workers": io_w, "hash_workers": hash_w,
    }


@router.get("/cases/{case_id}")
def case_detail(case_id: str):
    row = get_case(case_id)
    if not row:
        raise HTTPException(404, "Case not found.")
    return dict(row)


@router.get("/scans/{scan_id}")
def scan_detail(scan_id: str):
    row = get_scan(scan_id)
    if not row:
        raise HTTPException(404, "Scan not found.")
    return dict(row)


@router.get("/scans/{scan_id}/findings")
def findings(scan_id: str):
    if not get_scan(scan_id):
        raise HTTPException(404, "Scan not found.")
    return [dict(r) for r in list_findings(scan_id)]


@router.get("/scans/{scan_id}/artifacts")
def artifacts(scan_id: str):
    if not get_scan(scan_id):
        raise HTTPException(404, "Scan not found.")
    return {"artifacts": [dict(r) for r in list_artifacts(scan_id)], "timeline": [dict(r) for r in list_timeline(scan_id)]}


@router.post("/scans/{scan_id}/artifacts/refresh")
def artifact_refresh(scan_id: str):
    try:
        return refresh_artifacts(scan_id, force=True)
    except ValueError as e:
        raise HTTPException(404, str(e))
    except Exception as e:
        raise HTTPException(500, f"Artifact extraction failed: {e}")


@router.post("/scans/{scan_id}/recover")
def recover(scan_id: str, req: RecoverRequest):
    if not get_scan(scan_id):
        raise HTTPException(404, "Scan not found.")
    rows = get_findings_by_ids(req.finding_ids)
    rows = [r for r in rows if r["scan_id"] == scan_id]
    if not rows:
        raise HTTPException(404, "No findings selected for this scan.")
    return {"scan_id": scan_id, "results": recover_findings(scan_id, rows)}


@router.get("/findings/{finding_id}/download")
def download(finding_id: str):
    row = get_finding(finding_id)
    if not row or not row["recovered_path"]:
        raise HTTPException(404, "Recovered file not found.")
    p = Path(row["recovered_path"]).resolve()
    try:
        p.relative_to(settings.recovery_dir.resolve())
    except ValueError:
        raise HTTPException(403, "Recovered path is outside recovery directory.")
    if not p.exists() or not p.is_file():
        raise HTTPException(404, "Recovered file does not exist.")
    return FileResponse(str(p), filename=row["original_name"] or p.name, media_type="application/octet-stream")


@router.get("/scans/{scan_id}/report.json")
def report_json(scan_id: str):
    try:
        report = build_report(scan_id)
    except ValueError as e:
        raise HTTPException(404, str(e))
    except Exception as e:
        raise HTTPException(500, f"JSON report generation failed: {type(e).__name__}: {e}")
    return JSONResponse(report, headers={"Content-Disposition": f'attachment; filename="forensic-report-{scan_id[:8]}.json"'})


@router.get("/scans/{scan_id}/report.docx")
def report_docx(scan_id: str):
    out = settings.report_dir / f"forensic-report-{scan_id[:8]}.docx"
    try:
        generate_docx(scan_id, out)
    except ValueError as e:
        raise HTTPException(404, str(e))
    except Exception as e:
        raise HTTPException(500, f"DOCX report generation failed: {type(e).__name__}: {e}")
    return FileResponse(str(out), filename=out.name, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")


@router.get("/cases/{case_id}/integrity")
def integrity(case_id: str):
    if not get_case(case_id):
        raise HTTPException(404, "Case not found.")
    ok, msg, count = verify_chain()
    return {"verified": ok, "message": msg, "events": count}

# Backwards-compatible name used by the project's unit tests and small integrations.
normalize_windows_path = norm
