from __future__ import annotations
import json
import re
import zipfile
import hashlib
from pathlib import Path
from app.db.repository import get_scan,list_findings,list_artifacts,list_timeline,list_integrity
from app.services.integrity_ledger import verify_chain
from app.services.artifact_service import ensure_artifacts

def _json_row(row):
    d=dict(row)
    for key in ("metadata_json","journal_evidence_json","original_name_candidates_json"):
        try:d[key]=json.loads(d.get(key) or ("{}" if key=="metadata_json" else "[]"))
        except Exception:pass
    return d

def _strings(path: Path, limit=8192):
    try:data=path.read_bytes()[:limit]
    except Exception:return ""
    text=data.decode("latin-1","ignore")
    runs=re.findall(r"[\x20-\x7e]{6,}",text)
    return "\n".join(runs[:40])

def _analyse_zip(path: Path):
    try:
        with zipfile.ZipFile(path) as z:
            members=[]
            for info in z.infolist()[:100]:
                item={"name":info.filename,"size_bytes":info.file_size,"compressed_size_bytes":info.compress_size}
                if info.file_size<=25*1024*1024 and not info.is_dir():
                    data=z.read(info)
                    item["sha256"]=hashlib.sha256(data).hexdigest()
                members.append(item)
            return {"status":"ok","members":members}
    except Exception as exc:return {"status":"error","message":str(exc),"members":[]}

def build_report(scan_id):
    scan=get_scan(scan_id)
    if not scan:raise ValueError("Scan not found.")
    ensure_artifacts(scan_id)
    findings=[_json_row(r) for r in list_findings(scan_id)]
    artifacts=[]
    for r in list_artifacts(scan_id):
        a=dict(r)
        if "size" not in a:
            a["size"]=a.get("size_bytes", 0)
        if "meta_type" not in a:
            a["meta_type"]=a.get("type")
        artifacts.append(a)
    timeline=[dict(r) for r in list_timeline(scan_id)]
    integrity=[dict(r) for r in list_integrity(scan["case_id"])]
    ledger_ok,msg,count=verify_chain()

    ext4=None
    for e in integrity:
        if e["event_type"]=="analysis_completed":
            try: ext4=json.loads(e["details"]).get("ext4")
            except Exception: pass
            break

    deleted=[]
    for f in findings:
        duplicate_of=None
        for other in findings:
            if other["id"]!=f["id"] and f.get("recovered_sha256") and f.get("recovered_sha256")==other.get("recovered_sha256"):
                duplicate_of=other.get("inode");break
        deleted.append({
            "inode":f["inode"],"original_name":f.get("original_name") or f.get("name"),
            "original_path":f.get("original_path"),"size_bytes":f.get("size_bytes"),
            "deletion_time":f.get("deletion_time"),"file_type":f.get("file_type"),
            "file_signature":f.get("file_signature"),"recovery_status":f.get("recovery_status"),
            "recovered_size_bytes":f.get("recovered_size_bytes"),"recovered_sha256":f.get("recovered_sha256"),
            "validation_status":f.get("validation_status"),"validation_reason":f.get("validation_reason"),
            "source":f.get("source"),"confidence":f.get("confidence"),
            "journal_evidence":f.get("journal_evidence_json") or [],
            "name_candidates":f.get("original_name_candidates_json") or [],
            "duplicate_of_inode":duplicate_of,
            "recovered_path":f.get("recovered_path"),
        })

    by_name={a["path"].lower():a for a in artifacts}
    def find_artifact(basename):
        for path,a in by_name.items():
            if path.rsplit("/",1)[-1]==basename.lower():return a
        return None

    activity=find_artifact("activity.log")
    bash=find_artifact(".bash_history")
    meeting=find_artifact("meeting-notes.txt")
    clients=find_artifact("confidential-clients.txt")

    activity_events=[e for e in timeline if (e.get("source") or "").lower().endswith("activity.log")]
    bash_events=[e for e in timeline if (e.get("source") or "").lower().endswith(".bash_history")]

    def first_event(kind):
        return next((e for e in activity_events if e.get("event")==kind),None)

    usb_conn=first_event("usb_connected")
    usb_disc=first_event("usb_disconnected")
    archive_event=first_event("archive_created")
    history_clear=first_event("history_clear")

    archive_analysis=None
    for f in deleted:
        if f["file_signature"] and "ZIP" in f["file_signature"].upper() and f.get("recovered_path"):
            archive_analysis=_analyse_zip(Path(f["recovered_path"]))
            break

    recovered_content=[]
    for f in deleted:
        if f.get("recovered_path") and f.get("recovery_status") in {"complete","partial"}:
            p=Path(f["recovered_path"]);strings=_strings(p)
            if strings: recovered_content.append({"inode":f["inode"],"path":str(p),"strings":strings[:5000]})

    facts=[]
    if ext4:
        facts.append(f'Filesystem: {ext4.get("filesystem")}; volume label: {ext4.get("volume_label") or "not available"}.')
    facts.append(f'{len(deleted)} deleted inode candidate(s) identified.')
    for e in activity_events:
        facts.append(f'{e["timestamp"]} — {e["event"]}: {e.get("details","")}')
    for f in deleted:
        if f.get("recovery_status")=="complete":
            facts.append(f'Inode {f["inode"]} was recovered completely with a size match ({f["size_bytes"]} bytes).')
    if bash and bash.get("content"):
        facts.append('On-disk .bash_history was recovered as a live artifact and its command sequence was preserved.')
    if meeting and "transfer" in (meeting.get("content") or "").lower():
        facts.append('meeting-notes.txt contains a reference to the TRANSFER USB label.')
    if clients and "orion" in (clients.get("content") or "").lower():
        facts.append('confidential-clients.txt references Project ORION.')

    hypotheses=[]
    if usb_conn and archive_event:
        hypotheses.append('The short interval between USB connection and archive creation is consistent with a staged transfer workflow, but it does not prove that the archive was copied to the USB device.')
    hypotheses.append('A recovered archive, USB connection event and deletion sequence may support an exfiltration hypothesis; the image does not by itself prove successful external transmission.')

    limitations=[
        'A recovered file is validated by its logical size, readable data and recovered-file SHA-256. An external known-good hash is needed for independent identity verification.',
        'Filename/path reconstruction is based on surviving filesystem metadata; journal extraction is supplemental and is not a full JBD2 replay engine.',
        'The activity log and shell history can establish recorded events/commands, but they do not by themselves prove that a file was successfully written to a removable device.',
        'Timeline items derived from shell history are sequence evidence when no timestamp is present and should not be assigned an invented clock time.'
    ]

    return {
        "report_version":"0.4",
        "case":{"id":scan["case_id"],"name":scan["case_name"]},
        "evidence":{
            "path":scan["evidence_path"],"size_bytes":scan["size_bytes"],
            "sha256":scan["pre_scan_sha256"],"pre_scan_sha256":scan["pre_scan_sha256"],
            "post_scan_sha256":scan["post_scan_sha256"],
            "integrity_match":bool(scan["post_scan_sha256"] and scan["post_scan_sha256"]==scan["pre_scan_sha256"])
        },
        "filesystem":ext4.get("filesystem") if ext4 else None,
        "volume_label":ext4.get("volume_label") if ext4 else None,
        "filesystem_metadata":ext4 or {},
        "deleted_files":deleted,
        "timeline":timeline,
        "live_artifacts":artifacts,
        "recovered_content":recovered_content,
        "recovered_archive_analysis":archive_analysis,
        "lab02_deliverables":{
            "1_image_sha256":scan["pre_scan_sha256"],
            "2_filesystem_and_volume_label":{"filesystem":ext4.get("filesystem") if ext4 else None,"volume_label":ext4.get("volume_label") if ext4 else None},
            "3_deleted_files_and_inodes":deleted,
            "4_usb_connected":usb_conn,
            "5_archive_created":archive_event,
            "6_confidential_document_recovered":{
                "description":"Recovered Project ORION PDF",
                "candidates":[f for f in deleted if f.get("file_signature") and "PDF" in f["file_signature"].upper()]
            } if any(f.get("file_signature") and "PDF" in f["file_signature"].upper() for f in deleted) else None,
            "7_icat_vs_carving":{
                "metadata_recovery":"Uses the filesystem entry and inode/data-block context. It can retain inode, original name/path and logical file context when metadata survives.",
                "carving":"Searches raw blocks for file signatures. It can recover content without a filesystem entry, but original name/path context is usually unavailable and fragmentation can cause incomplete results."
            },
            "8_facts_and_hypotheses":{"facts":facts,"hypotheses":hypotheses}
        },
        "artefact_summary":{
            "activity_log":activity,
            "bash_history":bash,
            "meeting_notes":meeting,
            "confidential_clients":clients,
            "history_clear_event":history_clear,
        },
        "integrity_events":integrity,
        "integrity_ledger":{"verified":ledger_ok,"message":msg,"events":count},
        "limitations":limitations,
        "tooling":{
            "application":"EXT4 Deleted File Recovery Workbench 0.4",
            "backend":"Python/FastAPI","filesystem_cross_check":"pytsk3",
            "integrity":"SHA-256 + chained local JSONL ledger",
            "resource_policy":{"io_workers":scan["io_workers"],"hash_workers":scan["hash_workers"],"policy":scan["resource_policy"]}
        }
    }
