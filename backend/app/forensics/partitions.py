
from dataclasses import dataclass
from pathlib import Path
import struct

@dataclass(frozen=True)
class Partition:
    number:int;start:int;length:int;scheme:str;type_code:str
def u32(b,o):return struct.unpack_from("<I",b,o)[0]
def u64(b,o):return struct.unpack_from("<Q",b,o)[0]
def detect(path):
    out=[]
    with Path(path).open("rb",buffering=0) as f:
        boot=f.read(512)
        if len(boot)>=512 and boot[510:512]==b"\x55\xaa":
            for i in range(4):
                o=446+i*16;typ=boot[o+4];start=u32(boot,o+8);sectors=u32(boot,o+12)
                if typ and sectors:out.append(Partition(i+1,start*512,sectors*512,"MBR",f"0x{typ:02x}"))
        f.seek(512);hdr=f.read(512)
        if hdr[:8]==b"EFI PART":
            tl=u64(hdr,72);count=u32(hdr,80);size=u32(hdr,84)
            if 0<count<=4096 and 128<=size<=4096:
                f.seek(tl*512);raw=f.read(count*size)
                for i in range(count):
                    e=raw[i*size:(i+1)*size]
                    if len(e)<size or e[:16]==b"\0"*16:continue
                    first=u64(e,32);last=u64(e,40)
                    if last>=first:out.append(Partition(i+1,first*512,(last-first+1)*512,"GPT",e[:16].hex()))
    return out
