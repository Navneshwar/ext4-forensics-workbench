
from __future__ import annotations
import struct
from dataclasses import dataclass
from datetime import datetime,timezone
EXT4_MAGIC=0xEF53;EXTENT_MAGIC=0xF30A;EXT4_EXTENTS_FL=0x00080000
S_IFMT=0xF000;S_IFREG=0x8000;S_IFDIR=0x4000;S_IFLNK=0xA000
JBD2_MAGIC=0xC03B3998
JBD2_DESCRIPTOR_BLOCK=1;JBD2_COMMIT_BLOCK=2;JBD2_SUPERBLOCK_V1=3;JBD2_SUPERBLOCK_V2=4;JBD2_REVOKE_BLOCK=5
def u16(b,o):return struct.unpack_from("<H",b,o)[0]
def u32(b,o):return struct.unpack_from("<I",b,o)[0]
def u64(b,o):return struct.unpack_from("<Q",b,o)[0]
def iso(v):
    if not v:return None
    try:return datetime.fromtimestamp(v,tz=timezone.utc).isoformat()
    except (ValueError,OverflowError,OSError):return None
@dataclass(frozen=True)
class Superblock:
    offset:int;inodes_count:int;blocks_count:int;block_size:int;blocks_per_group:int;inodes_per_group:int;inode_size:int
    feature_compat:int;feature_incompat:int;feature_ro_compat:int;journal_inum:int;desc_size:int;label:str;uuid:str
    @property
    def groups(self):return (self.blocks_count+self.blocks_per_group-1)//self.blocks_per_group
def parse_superblock(data,offset=0):
    if len(data)<256 or u16(data,56)!=EXT4_MAGIC:raise ValueError("EXT4 superblock not found")
    log=u32(data,24);blocks=u32(data,4)|(u32(data,336)<<32 if len(data)>=340 else 0)
    label=data[120:136].split(b"\0",1)[0].decode("utf-8","replace")
    raw_uuid=data[104:120].hex()
    uuid=f"{raw_uuid[0:8]}-{raw_uuid[8:12]}-{raw_uuid[12:16]}-{raw_uuid[16:20]}-{raw_uuid[20:32]}"
    return Superblock(offset,u32(data,0),blocks,1024<<log,u32(data,32),u32(data,40),
                      u16(data,88) or 256,u32(data,92),u32(data,96),u32(data,100),u32(data,224),
                      max(u16(data,254) or 32,32),label,uuid)
def read_superblock(fh,offset):
    fh.seek(offset+1024);return parse_superblock(fh.read(1024),offset)
def _adapter(reader):
    class A:
        def __init__(self):self.off=0
        def seek(self,o):self.off=o
        def read(self,n):return reader.read_at(self.off,n)
    return A()
def group_inode_table(fh,sb,fs_offset,group):
    first=2 if sb.block_size==1024 else 1
    fh.seek(fs_offset+first*sb.block_size+group*sb.desc_size);d=fh.read(sb.desc_size)
    if len(d)<32:raise ValueError("Group descriptor truncated")
    return fs_offset+(u32(d,8)|(u32(d,48)<<32 if sb.desc_size>=64 and len(d)>=52 else 0))*sb.block_size
@dataclass(frozen=True)
class Inode:
    inode:int;group:int;offset:int;mode:int;size:int;deletion_time:int;links_count:int;flags:int;file_type:str
    uid:int;gid:int;atime:int;mtime:int;ctime:int;crtime:int
    @property
    def dtime(self):return iso(self.deletion_time)
    @property
    def atime_iso(self):return iso(self.atime)
    @property
    def mtime_iso(self):return iso(self.mtime)
    @property
    def ctime_iso(self):return iso(self.ctime)
    @property
    def crtime_iso(self):return iso(self.crtime)
def itype(mode):return {S_IFREG:"regular",S_IFDIR:"directory",S_IFLNK:"symlink"}.get(mode&S_IFMT,"other")
def parse_inode(data,no,group,offset):
    if len(data)<128:raise ValueError("inode truncated")
    mode=u16(data,0)
    return Inode(no,group,offset,mode,u32(data,4)|(u32(data,108)<<32 if len(data)>=112 else 0),
                 u32(data,20),u16(data,26),u32(data,32),itype(mode),u16(data,2),u16(data,24),
                 u32(data,8),u32(data,16),u32(data,12),u32(data,144) if len(data)>=148 else 0)
@dataclass(frozen=True)
class Extent:
    logical:int;length:int;physical:int;unwritten:bool=False
def extents(fh,sb,inode_data,fs_offset):
    root=inode_data[40:100]
    if len(root)<60:return []
    magic,entries,max_entries,depth=struct.unpack_from("<HHHH",root,0)
    if magic!=EXTENT_MAGIC or entries>max_entries or depth>5:return []
    out=[]
    def walk(node):
        magic,e,m,d=struct.unpack_from("<HHHH",node,0)
        if magic!=EXTENT_MAGIC or e>m:return
        for i in range(e):
            o=12+i*12
            if o+12>len(node):break
            if d==0:
                logical=u32(node,o);raw=u16(node,o+4);physical=u32(node,o+8)|(u16(node,o+6)<<32)
                out.append(Extent(logical,raw&0x7fff,physical,bool(raw&0x8000)))
            else:
                child=u32(node,o+4)|(u16(node,o+8)<<32)
                if child:
                    fh.seek(fs_offset+child*sb.block_size);b=fh.read(sb.block_size)
                    if len(b)==sb.block_size:walk(b)
    walk(root);return sorted(out,key=lambda e:e.logical)
def legacy_blocks(fh,sb,inode_data,fs_offset):
    for i in range(12):
        b=u32(inode_data,40+i*4)
        if b:yield b
    ind=u32(inode_data,88)
    if ind:
        fh.seek(fs_offset+ind*sb.block_size);raw=fh.read(sb.block_size)
        for o in range(0,len(raw)-3,4):
            b=u32(raw,o)
            if b:yield b
