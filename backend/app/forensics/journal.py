
from app.forensics.ext4_structs import (
    JBD2_MAGIC,JBD2_DESCRIPTOR_BLOCK,JBD2_COMMIT_BLOCK,JBD2_SUPERBLOCK_V1,JBD2_SUPERBLOCK_V2,JBD2_REVOKE_BLOCK,
    extents
)

def inspect(reader,sb,fs_offset,journal_inode,target_inodes,max_blocks=8192):
    if journal_inode is None:
        return {"status":"unavailable","blocks_scanned":0,"evidence":[],"candidate_hits":{}}
    class A:
        def __init__(self):self.off=0
        def seek(self,o):self.off=o
        def read(self,n):return reader.read_at(self.off,n)
    data=reader.read_at(journal_inode.offset,sb.inode_size)
    exts=extents(A(),sb,data,fs_offset);scanned=0;ev=[];hits={}
    labels={1:"descriptor",2:"commit",3:"superblock_v1",4:"superblock_v2",5:"revoke"}
    for ex in exts:
        for i in range(ex.length):
            if scanned>=max_blocks:break
            p=ex.physical+i;b=reader.read_at(fs_offset+p*sb.block_size,sb.block_size);scanned+=1
            if len(b)!=sb.block_size:continue
            if int.from_bytes(b[:4],"big")==JBD2_MAGIC and len(b)>=12:
                typ=int.from_bytes(b[4:8],"big");seq=int.from_bytes(b[8:12],"big")
                ev.append({"kind":labels.get(typ,f"type_{typ}"),"journal_block":p,"sequence":seq,
                           "message":"JBD2 transaction block detected.","inode_hits":[]})
    return {"status":"inspected","blocks_scanned":scanned,"evidence":ev,"candidate_hits":hits,
            "message":f"Inspected {scanned:,} journal blocks."}
