
from dataclasses import dataclass

@dataclass(frozen=True)
class FileSignature:
    label:str
    extension:str
    mime:str
    confidence:str

MAGICS=[
 (b"%PDF-",FileSignature("PDF document",".pdf","application/pdf","high")),
 (b"\x89PNG\r\n\x1a\n",FileSignature("PNG image",".png","image/png","high")),
 (b"\xff\xd8\xff",FileSignature("JPEG image",".jpg","image/jpeg","high")),
 (b"GIF87a",FileSignature("GIF image",".gif","image/gif","high")),
 (b"GIF89a",FileSignature("GIF image",".gif","image/gif","high")),
 (b"PK\x03\x04",FileSignature("ZIP archive / OOXML container",".zip","application/zip","high")),
 (b"\x7fELF",FileSignature("ELF executable",".elf","application/x-elf","high")),
 (b"\x1f\x8b\x08",FileSignature("GZIP archive",".gz","application/gzip","high")),
 (b"SQLite format 3\x00",FileSignature("SQLite database",".sqlite","application/vnd.sqlite3","high")),
 (b"Rar!\x1a\x07\x00",FileSignature("RAR archive",".rar","application/vnd.rar","high")),
 (b"7z\xbc\xaf'\x1c",FileSignature("7-Zip archive",".7z","application/x-7z-compressed","high")),
]

def identify(data):
    if not data:return FileSignature("Empty file","","application/octet-stream","high")
    for magic,sig in MAGICS:
        if data.startswith(magic):return sig
    sample=data[:4096]
    printable=sum(1 for b in sample if b in (9,10,13) or 32<=b<=126)
    if printable/max(1,len(sample))>.92:return FileSignature("Likely text",".txt","text/plain","medium")
    return FileSignature("Binary data",".bin","application/octet-stream","low")
