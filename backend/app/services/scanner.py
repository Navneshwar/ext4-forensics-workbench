
from __future__ import annotations
import json,uuid,re
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path
from app.core.config import settings
from app.db.repository import *
from app.forensics.ext4_scanner import scan
from app.forensics.hashing import sha256_file,hash_files
from app.forensics.io import ReadOnlyImage
from app.forensics.ext4_structs import group_inode_table,parse_inode,read_superblock
from app.forensics.directory_entries import build_index
from app.forensics.journal import inspect
from app.forensics.pytsk_artifacts import extract_artifacts
from app.forensics.recovery import recover
from app.services.integrity_ledger import append_event

pool=ThreadPoolExecutor(max_workers=settings.max_concurrent_scans,thread_name_prefix="scan-job")

def submit_scan(i,case_id,evidence_id):pool.submit(run_scan,i,case_id,evidence_id)
def _progress(i,p,stage,msg):update_scan(i,progress=p,stage=stage,message=msg)

def ledger(case_id,evidence_id,scan_id,event_type,algorithm,value,details):
    e={"case_id":case_id,"evidence_id":evidence_id,"scan_id":scan_id,
       "event_type":event_type,"algorithm":algorithm,"value":value,"details":details}
    insert_integrity(e);append_event({**e,"created_at":now_iso()})

def _adapter(reader):
    class A:
        def __init__(self):self.off=0
        def seek(self,o):self.off=o
        def read(self,n):return reader.read_at(self.off,n)
    return A()

def journal_inode(reader,sb,fs_offset):
    if not sb.journal_inum:return None
    ino=sb.journal_inum;g=(ino-1)//sb.inodes_per_group;i=(ino-1)%sb.inodes_per_group
    table=group_inode_table(_adapter(reader),sb,fs_offset,g);off=table+i*sb.inode_size
    raw=reader.read_at(off,sb.inode_size)
    return parse_inode(raw,ino,g,off) if len(raw)==sb.inode_size else None

def _clean_name(name,inode):
    name=(name or f"inode_{inode}").replace("/","_").replace("\\","_")
    name=re.sub(r'[<>:"|?*\x00-\x1f]','_',name).strip(" .")
    return name or f"inode_{inode}"

def run_scan(scan_id,case_id,evidence_id):
    s=get_scan(scan_id);image=Path(s["evidence_path"])
    try:
        update_scan(scan_id,status="running",started_at=now_iso())
        _progress(scan_id,2,"hash_pre","Hashing evidence image before analysis.")
        pre=sha256_file(image);ledger(case_id,evidence_id,scan_id,"pre_scan_hash","SHA-256",pre,"Pre-analysis evidence hash.")

        meta,deleted,dirs,fs_offset,sb=scan(image,int(s["io_workers"] or 2),
            lambda p,st,msg:_progress(scan_id,p,st,msg))

        _progress(scan_id,80,"directory_scan","Reconstructing surviving deleted filenames and parent directories.")
        reader=ReadOnlyImage(image);index=build_index(reader,sb,fs_offset,dirs)

        # derive a conservative parent path from active directory structure
        parent_map={}
        name_map={}
        for parent, entries in index["children_by_parent"].items():
            for e in entries:
                if e.inode not in name_map:
                    name_map[e.inode]=e.name
                    parent_map[e.inode]=parent

        def full_path(parent_inode,name):
            chain=[];cur=parent_inode;seen=set()
            while cur and cur not in seen and len(chain)<30:
                seen.add(cur)
                n=name_map.get(cur)
                if n and n not in {".",".."}:chain.append(n)
                cur=parent_map.get(cur)
            chain.reverse()
            return "/" + "/".join(chain+[name]) if name else None

        _progress(scan_id,84,"journal","Inspecting targeted EXT4 journal blocks.")
        jinode=journal_inode(reader,sb,fs_offset)
        j=inspect(reader,sb,fs_offset,jinode,{x.inode for x in deleted},settings.journal_max_blocks)

        _progress(scan_id,88,"artifacts","Extracting targeted live artifacts with pytsk3.")
        arts=extract_artifacts(image,fs_offset)
        for a in arts.get("files",[]):
            insert_artifact({"id":str(uuid.uuid4()),"scan_id":scan_id,**a,"type":a.get("meta_type")})

        for e in arts.get("timeline",[]):
            insert_timeline({"id":str(uuid.uuid4()),"scan_id":scan_id,**e})

        _progress(scan_id,92,"findings","Creating correlated deleted-file findings.")
        for inode in deleted:
            candidates=index["names_by_inode"].get(inode.inode,[])
            jhits=j.get("candidate_hits",{}).get(inode.inode,[])
            merged=[];seen=set()
            for item in candidates+jhits:
                k=(item.get("name"),item.get("parent_inode"),item.get("source"),item.get("offset"))
                if k not in seen:seen.add(k);merged.append(item)
            name=merged[0]["name"] if merged else None
            parent=merged[0].get("parent_inode") if merged else None
            path=full_path(parent,name) if parent and name else None
            if not path and name:path=f"/*/{name}"
            score=min(1.0,.45+.2+(.1 if inode.file_type=="regular" else 0)+(.15 if name else 0)+(.1 if jhits else 0))
            fid=str(uuid.uuid4())
            insert_finding({
                "id":fid,"scan_id":scan_id,"inode":inode.inode,
                "name":name or f"deleted_inode_{inode.inode}","path":path,
                "file_type":inode.file_type,"size_bytes":inode.size,"deletion_time":inode.dtime,
                "mode":oct(inode.mode),"confidence":"high" if score>=.85 else "medium",
                "confidence_score":round(score,2),"recoverable":inode.file_type=="regular",
                "source":"+"
                .join([x for x,ok in [("directory",bool(candidates)),("journal",bool(jhits))] if ok]) or "inode",
                "metadata":{"inode_offset":inode.offset,"group":inode.group,"filesystem_offset":fs_offset,
                            "block_size":sb.block_size,"uid":inode.uid,"gid":inode.gid,
                            "mode":oct(inode.mode),"flags":f"0x{inode.flags:08x}",
                            "atime":inode.atime_iso,"mtime":inode.mtime_iso,"ctime":inode.ctime_iso,
                            "crtime":inode.crtime_iso,
                            "parent_inode":parent,
                            "name_evidence":merged,
                            "journal":j.get("evidence",[])},
                "original_name":name,"original_path":path,
                "recovery_status":"candidate","validation_reason":"Not yet recovered.",
                "journal_evidence":jhits,"original_name_candidates":merged
            })

        ledger(case_id,evidence_id,scan_id,"analysis_completed",None,None,json.dumps({
            "ext4":meta,"deleted_candidates":len(deleted),"journal_blocks":j.get("blocks_scanned",0),
            "targeted_artifacts":len(arts.get("files",[])),"pytsk3_status":arts.get("status")
        },sort_keys=True))

        if settings.post_scan_verify:
            _progress(scan_id,97,"hash_post","Re-hashing evidence image for integrity verification.")
            post=sha256_file(image);set_post_hash(evidence_id,post)
            match=pre.lower()==post.lower()
            ledger(case_id,evidence_id,scan_id,"post_scan_hash","SHA-256",post,f"Pre/post match: {match}")
            if not match:
                update_scan(scan_id,status="integrity_changed",progress=100,stage="integrity_failed",
                            message="Evidence image hash changed during analysis.",finished_at=now_iso());return

        _progress(scan_id,100,"complete",f"Scan complete. {len(deleted)} deleted inode candidates found.")
        update_scan(scan_id,status="completed",progress=100,stage="complete",finished_at=now_iso())
    except Exception as exc:
        update_scan(scan_id,status="failed",progress=100,stage="error",message=str(exc),error=repr(exc),finished_at=now_iso())

def recover_findings(scan_id,rows):
    s=get_scan(scan_id);image=Path(s["evidence_path"])
    md=json.loads(rows[0]["metadata_json"]);fs_offset=int(md["filesystem_offset"])
    reader=ReadOnlyImage(image);sb=read_superblock(_adapter(reader),fs_offset)
    futures={};results=[];outdir=settings.recovery_dir/scan_id
    with ThreadPoolExecutor(max_workers=max(1,min(int(s["io_workers"] or 2),len(rows))),thread_name_prefix="recover") as ex:
        for row in rows:
            md=json.loads(row["metadata_json"])
            if row["file_type"]!="regular":
                results.append({"finding_id":row["id"],"status":"skipped","error":"Only regular files are recoverable in v0.3."});continue
            ino=parse_inode(reader.read_at(int(md["inode_offset"]),sb.inode_size),int(row["inode"]),int(md.get("group",0)),int(md["inode_offset"]))
            name=_clean_name(row["original_name"] or row["name"],row["inode"])
            target=outdir/f"inode_{row['inode']}_{name}"
            futures[ex.submit(recover,image,fs_offset,sb,ino,target)]=row
        for fut in as_completed(futures):
            row=futures[fut]
            try:results.append({"finding_id":row["id"],"status":"recovered",**fut.result()})
            except Exception as exc:results.append({"finding_id":row["id"],"status":"failed","error":str(exc)})

    hashes=hash_files([r["path"] for r in results if r["status"]=="recovered"],int(s["hash_workers"] or 2))
    for r in results:
        row=next((x for x in rows if x["id"]==r["finding_id"]),None)
        if not row:continue
        if r["status"]!="recovered":
            update_finding(row["id"],recovery_status="failed",validation_status="recovery_failed",
                           validation_reason=r["error"],confidence="low",confidence_score=.2);continue
        digest=hashes[r["path"]];sig=r["signature"]
        update_finding(row["id"],recovered_path=r["path"],recovered_sha256=digest,
                       file_signature=sig["name"],recovery_status=r["recovery_status"],
                       recovered_size_bytes=r["bytes_written"],
                       validation_status="size_match" if r["size_verified"] else "partial",
                       validation_reason=r["validation_reason"],confidence="high" if r["size_verified"] else "medium",
                       confidence_score=.95 if r["size_verified"] else .65,
                       metadata_json=json.dumps({**json.loads(row["metadata_json"] or "{}"),"recovery":r},sort_keys=True))
        ledger(s["case_id"],s["evidence_id"],scan_id,"recovered_file_hash","SHA-256",digest,
               json.dumps({"finding_id":row["id"],"inode":row["inode"],"path":r["path"],
                           "bytes_written":r["bytes_written"],"expected_bytes":r["expected_bytes"],
                           "signature":sig},sort_keys=True))
    return results
