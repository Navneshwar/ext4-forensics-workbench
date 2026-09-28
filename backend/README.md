
# Backend — EXT4 Deleted File Recovery v0.2

Windows-native friendly FastAPI backend.

### Start

```powershell
cd backend
.venv\Scripts\activate
python -m pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Main features

- SHA-256 before/after evidence hash
- local SQLite casebook
- append-only chained JSONL integrity ledger
- Windows quoted path normalization
- bounded scan/recovery/hash threads
- live CPU/RAM telemetry
- EXT4 superblock / group descriptor / inode parsing
- deleted inode candidate extraction
- deleted directory-entry parsing + slack heuristic
- conservative name/path reconstruction
- file signature identification
- complete/partial/not-recoverable classification
- targeted JBD2 journal-inode inspection and inode/name correlation
- pytsk3 independent filesystem cross-check
- recovered-file download
- JSON/CSV report export

### Scope

This is an academic capstone implementation, not a validated commercial forensic product.
Journal handling extracts evidence and correlations; it does not replay every JBD2 transaction.
