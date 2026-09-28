
from __future__ import annotations
import hashlib,json
from pathlib import Path
from threading import Lock
from app.core.config import settings
_lock=Lock()
def _canon(x):return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def append_event(event):
    with _lock:
        prev=""
        p=Path(settings.integrity_ledger)
        if p.exists():
            with p.open("r",encoding="utf-8",errors="replace") as f:
                for line in f:
                    if line.strip():
                        try:prev=json.loads(line).get("entry_hash",prev)
                        except json.JSONDecodeError:pass
        row=dict(event);row["previous_hash"]=prev
        row["entry_hash"]=hashlib.sha256(_canon(row)).hexdigest()
        with p.open("a",encoding="utf-8",newline="\n") as f:f.write(json.dumps(row,sort_keys=True)+"\n")
        return row
def verify_chain():
    p=Path(settings.integrity_ledger)
    if not p.exists():return True,"Ledger is empty.",0
    prev="";count=0
    with _lock,p.open("r",encoding="utf-8",errors="replace") as f:
        for n,line in enumerate(f,1):
            if not line.strip():continue
            try:r=json.loads(line)
            except json.JSONDecodeError:return False,f"Invalid JSON at line {n}.",count
            if r.get("previous_hash","")!=prev:return False,f"Broken chain at line {n}.",count
            claim=r.get("entry_hash");check=dict(r);check.pop("entry_hash",None)
            if hashlib.sha256(_canon(check)).hexdigest()!=claim:return False,f"Hash mismatch at line {n}.",count
            prev=claim;count+=1
    return True,f"Ledger verified ({count} events).",count
