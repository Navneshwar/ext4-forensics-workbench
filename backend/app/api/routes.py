from __future__ import annotations
import json,os,uuid
from pathlib import Path
from fastapi import APIRouter,HTTPException
from fastapi.responses import FileResponse,PlainTextResponse
from pydantic import BaseModel,Field
from app.core.config import settings
from app.core.resources import snapshot
from app.db.repository import get_case,get_finding,get_findings_by_ids,get_scan,insert_case,insert_evidence,insert_scan,list_findings,list_artifacts,list_timeline
from app.forensics.hashing import sha256_file
from app.services.integrity_ledger import verify_chain
from app.services.scanner import submit_scan,recover_findings
from app.services.report_builder import build_report
from app.services.docx_report import generate_docx
from app.services.artifact_service import refresh_artifacts

router=APIRouter(prefix="/api")
class ScanRequest(BaseModel):
    image_path:str=Field(min_length=1,max_length=4096)
    case_id:str|None=None
    case_name:str=Field(default="EXT4 recovery case",min_length=1,max_length=120)
    io_workers:int=Field(default=1,ge=1,le=8)
    hash_workers:int=Field(default=2,ge=1,le=8)
    resource_policy:str="laptop"
class RecoverRequest(BaseModel):finding_ids:list[str]=Field(min_length=1,max_length=100)
def norm(raw):
    s=raw.strip()
    while len(s)>=2 and s[0]==s[-1] and s[0] in {'"',"'"}:s=s[1:-1].strip()
    return Path(os.path.expandvars(s)).expanduser()
@router.get("/health")
def health():return {"status":"ok","version":"0.4.0"}
@router.get("/system/resources")
def resources():return snapshot()
@router.post("/scans")
def create_scan(req:ScanRequest):
    path=norm(req.image_path)
    if not path.exists() or not path.is_file():raise HTTPException(400,f"Image file does not exist: {path}")
    case_id=req.case_id
    if case_id:
        if not get_case(case_id):raise HTTPException(404,"Case not found.")
    else:
        case_id=str(uuid.uuid4());insert_case(case_id,req.case_name)
    digest=sha256_file(path);evidence_id=str(uuid.uuid4());insert_evidence(evidence_id,case_id,str(path.resolve()),path.stat().st_size,digest)
    io_w=min(settings.max_io_workers,max(1,req.io_workers));hash_w=min(settings.max_hash_workers,max(1,req.hash_workers))
    scan_id=str(uuid.uuid4());insert_scan(scan_id,case_id,evidence_id,io_w,hash_w,req.resource_policy);submit_scan(scan_id,case_id,evidence_id)
    return {"scan_id":scan_id,"case_id":case_id,"evidence_id":evidence_id,"sha256":digest,"path":str(path.resolve()),"io_workers":io_w,"hash_workers":hash_w}
@router.get("/scans/{scan_id}")
def scan_detail(scan_id):
    row=get_scan(scan_id)
    if not row:raise HTTPException(404,"Scan not found.")
    return dict(row)
@router.get("/scans/{scan_id}/findings")
def findings(scan_id):
    if not get_scan(scan_id):raise HTTPException(404,"Scan not found.")
    return [dict(r) for r in list_findings(scan_id)]
@router.get("/scans/{scan_id}/artifacts")
def artifacts(scan_id):
    if not get_scan(scan_id):raise HTTPException(404,"Scan not found.")
    return {"artifacts":[dict(r) for r in list_artifacts(scan_id)],"timeline":[dict(r) for r in list_timeline(scan_id)]}
@router.post("/scans/{scan_id}/artifacts/refresh")
def artifact_refresh(scan_id):
    try:return refresh_artifacts(scan_id,force=True)
    except ValueError as e:raise HTTPException(404,str(e))
    except Exception as e:raise HTTPException(500,f"Artifact extraction failed: {e}")
@router.post("/scans/{scan_id}/recover")
def recover(scan_id,req:RecoverRequest):
    rows=get_findings_by_ids(req.finding_ids)
    if not rows:raise HTTPException(404,"No findings selected.")
    return {"scan_id":scan_id,"results":recover_findings(scan_id,rows)}
@router.get("/findings/{finding_id}/download")
def download(finding_id):
    row=get_finding(finding_id)
    if not row or not row["recovered_path"]:raise HTTPException(404,"Recovered file not found.")
    p=Path(row["recovered_path"]).resolve()
    try:p.relative_to(settings.recovery_dir.resolve())
    except ValueError:raise HTTPException(403,"Recovered path is outside recovery directory.")
    if not p.exists() or not p.is_file():raise HTTPException(404,"Recovered file does not exist.")
    return FileResponse(str(p),filename=row["original_name"] or p.name,media_type="application/octet-stream")
@router.get("/scans/{scan_id}/report.json")
def report_json(scan_id):
    try:r=build_report(scan_id)
    except ValueError as e:raise HTTPException(404,str(e))
    return PlainTextResponse(json.dumps(r,indent=2,ensure_ascii=False,default=str),media_type="application/json",headers={"Content-Disposition":f'attachment; filename="ext4-report-{scan_id[:8]}.json"'})
@router.get("/scans/{scan_id}/report.docx")
def report_docx(scan_id):
    out=settings.report_dir/f"ext4-report-{scan_id[:8]}.docx"
    try:generate_docx(scan_id,out)
    except ValueError as e:raise HTTPException(404,str(e))
    except Exception as e:raise HTTPException(500,f"DOCX report generation failed: {type(e).__name__}: {e}")
    return FileResponse(str(out),filename=out.name,media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
@router.get("/cases/{case_id}/integrity")
def integrity(case_id):
    if not get_case(case_id):raise HTTPException(404,"Case not found.")
    ok,msg,count=verify_chain();return {"verified":ok,"message":msg,"events":count}
