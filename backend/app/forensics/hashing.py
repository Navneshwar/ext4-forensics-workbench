
from __future__ import annotations
import hashlib
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from app.core.config import settings

def sha256_file(path,chunk_size=None):
    h=hashlib.sha256();size=Path(path).stat().st_size
    with Path(path).open("rb",buffering=0) as f:
        while True:
            chunk=f.read(chunk_size or settings.chunk_size)
            if not chunk:break
            h.update(chunk)
    return h.hexdigest()

def hash_files(paths,workers):
    paths=[str(Path(x)) for x in paths]
    if not paths:return {}
    def one(p):return p,sha256_file(p)
    with ThreadPoolExecutor(max_workers=max(1,workers),thread_name_prefix="hash") as ex:
        return dict(ex.map(one,paths))
