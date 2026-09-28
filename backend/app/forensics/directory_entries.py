
from __future__ import annotations
from dataclasses import dataclass
from app.forensics.ext4_structs import EXT4_EXTENTS_FL,extents,legacy_blocks
from app.forensics.io import ReadOnlyImage

@dataclass(frozen=True)
class Dirent:
    parent_inode:int;inode:int;name:str;offset:int;source:str

def plausible(raw):
    if not raw or len(raw)>255:return False
    bad=sum(1 for b in raw if b==0 or (b<32 and b not in (9,)))
    return bad<=max(1,len(raw)//20)

def parse_block(block,parent,base=0):
    out=[];o=0
    while o+8<=len(block):
        ino=int.from_bytes(block[o:o+4],"little");rec=int.from_bytes(block[o+4:o+6],"little")
        nlen=block[o+6]
        if rec<8 or rec%4 or o+rec>len(block):break
        if ino and 0<nlen<=rec-8:
            raw=block[o+8:o+8+nlen]
            if plausible(raw):
                out.append(Dirent(parent,ino,raw.decode("utf-8","replace"),base+o,"active_dirent"))
        o+=rec
    return out

def heuristic(block,parent,base=0):
    out=[]
    for o in range(0,max(0,len(block)-8),4):
        ino=int.from_bytes(block[o:o+4],"little");rec=int.from_bytes(block[o+4:o+6],"little");nlen=block[o+6]
        if not ino or rec<8 or rec%4 or o+rec>len(block) or not nlen or nlen>rec-8 or nlen>255:continue
        raw=block[o+8:o+8+nlen]
        name=raw.decode("utf-8","replace") if plausible(raw) else ""
        if name and name not in {".",".."}:out.append(Dirent(parent,ino,name,base+o,"slack_heuristic"))
    seen=set();u=[]
    for e in out:
        k=(e.parent_inode,e.inode,e.name,e.offset)
        if k not in seen:seen.add(k);u.append(e)
    return u

def adapter(reader):
    class A:
        def __init__(self):self.off=0
        def seek(self,o):self.off=o
        def read(self,n):return reader.read_at(self.off,n)
    return A()

def directory_content(reader,sb,fs_offset,inode,data):
    remain=max(0,inode.size);parts=[]
    if not remain:return b""
    if inode.flags & EXT4_EXTENTS_FL:
        blocks=extents(adapter(reader),sb,data,fs_offset)
        for ex in blocks:
            if ex.unwritten:continue
            for i in range(ex.length):
                if remain<=0:break
                b=reader.read_at(fs_offset+(ex.physical+i)*sb.block_size,min(sb.block_size,remain))
                if not b:break
                parts.append(b);remain-=len(b)
    else:
        for bno in legacy_blocks(adapter(reader),sb,data,fs_offset):
            if remain<=0:break
            b=reader.read_at(fs_offset+bno*sb.block_size,min(sb.block_size,remain))
            if not b:break
            parts.append(b);remain-=len(b)
    return b"".join(parts)[:inode.size]

def build_index(reader,sb,fs_offset,directories):
    names={};children_by_parent={}
    for inode in directories:
        try:
            data=reader.read_at(inode.offset,sb.inode_size)
            content=directory_content(reader,sb,fs_offset,inode,data)
        except Exception:continue
        if not content:continue
        entries=[]
        for start in range(0,len(content),sb.block_size):
            blk=content[start:start+sb.block_size]
            entries.extend(parse_block(blk,inode.inode,start))
            entries.extend(heuristic(blk,inode.inode,start))
        for e in entries:
            if e.name not in {".",".."}:
                names.setdefault(e.inode,[]).append({"name":e.name,"parent_inode":e.parent_inode,"source":e.source,"offset":e.offset})
                children_by_parent.setdefault(e.parent_inode,[]).append(e)
    return {"names_by_inode":names,"children_by_parent":children_by_parent}
