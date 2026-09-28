
from __future__ import annotations
from pathlib import Path

def cross_check_with_pytsk3(image_path: str|Path, fs_offset:int)->dict:
    try:
        import pytsk3
    except ImportError:
        return {"status":"unavailable","message":"pytsk3 is not installed."}
    try:
        img=pytsk3.Img_Info(str(image_path))
        fs=pytsk3.FS_Info(img,offset=fs_offset)
        root=fs.open_meta(2)
        return {"status":"ok","message":"pytsk3 opened the same filesystem offset.",
                "block_size":getattr(fs.info,"block_size",None),
                "root_inode":getattr(root.info,"meta_addr",2)}
    except Exception as exc:
        return {"status":"error","message":str(exc)}
