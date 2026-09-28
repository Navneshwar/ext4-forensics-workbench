
from __future__ import annotations
import struct
from concurrent.futures import ThreadPoolExecutor,as_completed
from pathlib import Path
from threading import Lock
from app.core.config import settings
from app.forensics.ext4_structs import read_superblock,group_inode_table,parse_inode
from app.forensics.io import ReadOnlyImage
from app.forensics.partitions import detect

def adapter(reader):
    class A:
        def __init__(self):self.off=0
        def seek(self,o):self.off=o
        def read(self,n):return reader.read_at(self.off,n)
    return A()

def find_offsets(path):
    offsets=[0]+[p.start for p in detect(path)]
    valid=[]
    with Path(path).open("rb",buffering=0) as f:
        for off in sorted(set(offsets)):
            try: read_superblock(f,off);valid.append(off)
            except (OSError,ValueError,struct.error):pass
    return valid

def _group(reader,sb,fs_offset,g):
    table=group_inode_table(adapter(reader),sb,fs_offset,g)
    table_bytes=sb.inodes_per_group*sb.inode_size
    raw=reader.read_at(table,table_bytes)
    deleted=[];dirs=[]
    slots=min(sb.inodes_per_group,len(raw)//sb.inode_size);base=g*sb.inodes_per_group+1
    for i in range(slots):
        off=table+i*sb.inode_size;data=raw[i*sb.inode_size:(i+1)*sb.inode_size]
        try:ino=parse_inode(data,base+i,g,off)
        except Exception:continue
        if ino.mode and ino.file_type=="directory":dirs.append(ino)
        if ino.mode and ino.deletion_time and ino.file_type in {"regular","directory","symlink"}:deleted.append(ino)
    return deleted,dirs

def scan(path,workers,progress=None):
    path=Path(path);offs=find_offsets(path)
    if not offs:raise ValueError("No EXT4 filesystem found.")
    fs_offset=offs[0];reader=ReadOnlyImage(path);sb=read_superblock(adapter(reader),fs_offset)
    meta={"filesystem":"ext4","volume_label":sb.label,"uuid":sb.uuid,"filesystem_offset":fs_offset,
          "block_size":sb.block_size,"inode_size":sb.inode_size,"inodes_count":sb.inodes_count,
          "blocks_count":sb.blocks_count,"inodes_per_group":sb.inodes_per_group,
          "groups":sb.groups,"journal_inode":sb.journal_inum,
          "features":{"compat":f"0x{sb.feature_compat:08x}",
                      "incompat":f"0x{sb.feature_incompat:08x}",
                      "ro_compat":f"0x{sb.feature_ro_compat:08x}"}}
    deleted=[];dirs=[];done=0;lock=Lock()
    with ThreadPoolExecutor(max_workers=max(1,min(workers,sb.groups,settings.max_io_workers)),thread_name_prefix="inode") as ex:
        futs=[ex.submit(_group,reader,sb,fs_offset,g) for g in range(sb.groups)]
        for f in as_completed(futs):
            d,di=f.result();deleted.extend(d);dirs.extend(di)
            with lock:done+=1;c=done
            if progress:progress(min(78,8+c/max(1,sb.groups)*70),"inode_scan",f"Scanned inode group {c:,} / {sb.groups:,}")
    deleted.sort(key=lambda x:x.inode);dirs.sort(key=lambda x:x.inode)
    return meta,deleted,dirs,fs_offset,sb
