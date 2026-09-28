# EXT4 Deleted File Recovery Workbench v0.4

Windows-native friendly capstone implementation for Lab #02-style EXT4 disk forensics.

## v0.4 changes

- Robust recursive live-artifact extraction through pytsk3 `open_dir(inode=2)` + `entry.as_directory()`.
- Reads artifact contents directly from each TSK entry instead of reopening by path.
- Extracts `.bash_history`, `activity.log`, `meeting-notes.txt`, and `confidential-clients.txt` when present.
- Parses `activity.log` into semantic events: USB connect/disconnect, archive creation, file open, delete, history clear, login, etc.
- Parses shell history as sequence-only evidence when timestamps are unavailable.
- Existing scans can refresh artifact/timeline data without re-running the inode scan.
- JSON report auto-populates missing artifacts on demand.
- DOCX report is landscape-oriented to avoid the earlier wide-table wrapping problem.
- DOCX separates deleted-file findings from long SHA-256 values.
- Recovered ZIPs are inspected as archives without extracting their members to disk.
- Recovered files receive printable-string excerpts for report correlation.
- Complete Lab #02 deliverable structure, facts vs hypotheses, IOC/artefact context, and limitations.

## Windows start

```powershell
cd "D:\Important documents(studies)\Projects\ext4-forensics-capstone\backend"
.venv\Scripts\activate
python -m pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Second terminal:

```powershell
cd "D:\Important documents(studies)\Projects\ext4-forensics-capstone\frontend"
npm install
npm run dev
```

Open `http://localhost:5173`.

## Existing scan: no rescan required

For an existing scan, the report endpoint now automatically attempts to populate missing live artifacts.
You can also force-refresh them:

```powershell
curl -X POST http://127.0.0.1:8000/api/scans/<SCAN_ID>/artifacts/refresh
```

or:

```powershell
python scripts/refresh_scan_artifacts.py <SCAN_ID>
```

Then download JSON/DOCX again.

## Lab #02 evidence boundary

The application does not hard-code Synapse's answer values. It extracts filesystem artifacts from the image and places them into the report. Known-answer values may be used separately to validate a test run.

The tool should say "not extracted" when evidence is not actually present or not successfully read.

## Report contents

The DOCX includes:

1. Mandate
2. Integrity and SHA-256
3. Method + resource policy
4. Filesystem/volume metadata
5. Deleted-file findings and recovery hashes
6. All eight Lab #02 deliverables
7. Full timeline
8. Live-artifact inventory and excerpts
9. Recovered content strings and ZIP member analysis
10. Integrity ledger
11. Limitations
12. Conclusion

## Forensic limitation

This is an academic capstone implementation, not a certified forensic suite. Journal handling is targeted JBD2 evidence extraction rather than a complete transaction replay engine. A recorded USB event plus staging/deletion artifacts does not independently prove successful copying to USB or external transmission.
