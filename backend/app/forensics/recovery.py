
from __future__ import annotations
import hashlib
from pathlib import Path
from app.core.config import settings
from app.forensics.ext4_structs import EXT4_EXTENTS_FL,extents,legacy_blocks,parse_inode
from app.forensics.io import ReadOnlyImage
from app.forensics.signatures import identify

def adapter(reader):
    class A:
        def __init__(self):self.off=0
        def seek(self,o):self.off=o
        def read(self,n):return reader.read_at(self.off,n)
    return A()

def recover(image_path,fs_offset,sb,inode,out):
    expected=int(inode.size)
    if expected>settings.max_recovery_bytes:raise ValueError("Recovery exceeds configured size limit.")
    reader=ReadOnlyImage(image_path);data=reader.read_at(inode.offset,sb.inode_size)
    parsed=parse_inode(data,inode.inode,inode.group,inode.offset)
    out=Path(out);out.parent.mkdir(parents=True,exist_ok=True)
    written=0;h=hashlib.sha256();sample=bytearray();unwritten=False
    def write(f,b):
        nonlocal written
        b=b[:expected-written]
        if not b:return
        f.write(b);h.update(b);sample.extend(b[:max(0,4096-len(sample))]);written+=len(b)
    with out.open("wb",buffering=0) as f:
        if parsed.flags & EXT4_EXTENTS_FL:
            for ex in extents(adapter(reader),sb,data,fs_offset):
                if ex.unwritten:unwritten=True;continue
                for i in range(ex.length):
                    if written>=expected:break
                    b=reader.read_at(fs_offset+(ex.physical+i)*sb.block_size,min(sb.block_size,expected-written))
                    if not b:break
                    write(f,b)
        else:
            for block in legacy_blocks(adapter(reader),sb,data,fs_offset):
                if written>=expected:break
                b=reader.read_at(fs_offset+block*sb.block_size,min(sb.block_size,expected-written))
                if not b:break
                write(f,b)
    sig=identify(bytes(sample));complete=(written==expected and not unwritten)
    status="complete" if complete else ("partial" if written else "not_recoverable")
    return {"path":str(out),"bytes_written":written,"expected_bytes":expected,"sha256":h.hexdigest(),
            "signature":{"name":sig.label,"extension":sig.extension,"mime":sig.mime,"confidence":sig.confidence},
            "recovery_status":status,"size_verified":complete,
            "validation_reason":"All logical bytes were recovered from retained data extents." if complete
            else ("Some bytes were recovered, but the complete logical file was not reconstructed." if written
                  else "No readable data blocks were recovered.")}
