
from app.api.routes import normalize_windows_path
from app.forensics.signatures import identify_bytes
from app.forensics.directory_entries import parse_dir_block

def test_windows_path_normalization():
    assert str(normalize_windows_path('"C:\\evidence\\lab01.img"')).endswith("C:\\evidence\\lab01.img")

def test_signatures():
    assert identify_bytes(b"%PDF-1.7").extension == ".pdf"
    assert identify_bytes(b"\x89PNG\r\n\x1a\n").extension == ".png"

def test_dirent():
    name=b"report.pdf"
    rec=((8+len(name)+3)//4)*4
    b=bytearray(rec+4096-4096%rec if rec<4096 else rec)
    b[0:4]=(22).to_bytes(4,"little"); b[4:6]=rec.to_bytes(2,"little")
    b[6]=len(name); b[7]=1; b[8:8+len(name)]=name
    entries=parse_dir_block(bytes(b),2,0)
    assert any(e.inode==22 and e.name=="report.pdf" for e in entries)
