
from __future__ import annotations
import os
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]

def _load_dotenv(path: Path):
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line=line.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        k,v=line.split("=",1)
        os.environ.setdefault(k.strip(),v.strip().strip('"').strip("'"))

_load_dotenv(BASE_DIR/".env")

def _int(name, default, lo=1, hi=1000000):
    try: return max(lo,min(hi,int(os.getenv(name,str(default)))))
    except ValueError: return default

def _bool(name, default):
    raw=os.getenv(name)
    return default if raw is None else raw.lower() in {"1","true","yes","on"}

def _path(name, default):
    p=Path(os.getenv(name,default))
    return p.resolve() if p.is_absolute() else (BASE_DIR/p).resolve()

@dataclass(frozen=True)
class Settings:
    app_data_dir: Path
    recovery_dir: Path
    report_dir: Path
    integrity_ledger: Path
    max_io_workers: int
    max_hash_workers: int
    max_concurrent_scans: int
    max_recovery_bytes: int
    chunk_size: int
    post_scan_verify: bool
    journal_max_blocks: int
    text_artifact_max_bytes: int

def load_settings():
    s=Settings(
        app_data_dir=_path("APP_DATA_DIR","./data"),
        recovery_dir=_path("RECOVERY_DIR","./recovered"),
        report_dir=_path("REPORT_DIR","./reports"),
        integrity_ledger=_path("INTEGRITY_LEDGER","./data/integrity-ledger.jsonl"),
        max_io_workers=_int("MAX_IO_WORKERS",2,1,8),
        max_hash_workers=_int("MAX_HASH_WORKERS",2,1,8),
        max_concurrent_scans=_int("MAX_CONCURRENT_SCANS",1,1,2),
        max_recovery_bytes=_int("MAX_RECOVERY_BYTES",10*1024**3,1,100*1024**3),
        chunk_size=_int("CHUNK_SIZE_MB",4,1,64)*1024*1024,
        post_scan_verify=_bool("POST_SCAN_VERIFY",True),
        journal_max_blocks=_int("JOURNAL_MAX_BLOCKS",8192,100,1000000),
        text_artifact_max_bytes=_int("TEXT_ARTIFACT_MAX_BYTES",1048576,4096,100*1024*1024),
    )
    for p in (s.app_data_dir,s.recovery_dir,s.report_dir,s.integrity_ledger.parent):
        p.mkdir(parents=True,exist_ok=True)
    return s

settings=load_settings()
