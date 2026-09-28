
from __future__ import annotations
import os,threading
from pathlib import Path
class ReadOnlyImage:
    def __init__(self,path):
        self.path=Path(path);self.local=threading.local();self.lock=threading.Lock()
    def _fh(self):
        fh=getattr(self.local,"fh",None)
        if fh is None or fh.closed: fh=self.path.open("rb",buffering=0);self.local.fh=fh
        return fh
    def read_at(self,offset,size):
        if size<=0:return b""
        fh=self._fh()
        if hasattr(os,"pread"):return os.pread(fh.fileno(),size,offset)
        with self.lock:fh.seek(offset);return fh.read(size)
    def size(self):return self.path.stat().st_size
