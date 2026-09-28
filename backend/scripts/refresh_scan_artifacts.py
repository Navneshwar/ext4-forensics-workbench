from __future__ import annotations
import argparse
from app.services.artifact_service import refresh_artifacts

parser=argparse.ArgumentParser(description="Refresh live filesystem artifacts for an existing scan without rescanning inodes.")
parser.add_argument("scan_id")
args=parser.parse_args()
result=refresh_artifacts(args.scan_id,force=True)
print(result["message"])
print("Artifacts:",len(result.get("files",[])))
print("Timeline events:",len(result.get("timeline",[])))
