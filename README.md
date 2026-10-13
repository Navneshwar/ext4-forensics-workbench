# EXT4 Forensics Workbench v0.5.2

Windows-friendly academic cyber-forensics workbench for EXT4 deleted-file analysis. The app provides a tabbed, guided examiner workflow, stores case and evidence intake metadata in SQLite, preserves the original image's read-only scanning behavior, and exports structured JSON plus a detailed DOCX examination report.

## What's new in v0.5.2

- A4 portrait DOCX report design with consistent margins, page numbering, styled evidence tables, and a visual event timeline.
- Expanded technical methodology explaining read-only source-image handling, pre/post SHA-256 checks, EXT4 metadata scanning, artifact extraction, metadata-guided deleted-file recovery, validation, and the scope limits of signature checks/JBD2 inspection.
- Timestamped activity-log events are displayed in a timeline diagram; shell commands without timestamps stay in a separate sequence-only table. Supporting artifact excerpts avoid dumping raw binary archive content.

## What's new in v0.5

- Multi-step frontend intake tabs for case details, evidence/acquisition, scan settings, findings/recovery, and report export.
- Contextual `?` help at each workflow step and next to intake fields.
- Streamlined case intake: case number and short case title.
- Evidence intake: evidence item number/type, image path, optional description, and optional source-device identifiers (device type, make/model, and serial number). Administrative, incident-context, acquisition, receipt, custody, and storage fields are intentionally omitted from the UI and generated report.
- In-place SQLite migration retains existing cases, scans, findings, and ledger records.
- Optional Groq-powered report narrative with executive summary, investigation objectives, scope/methodology, key findings, timeline assessment, interpretation, conclusion, recommendations, and limitations.
- Groq output is labelled and cached based on structured report inputs. If a key is missing or the API fails, a labelled local fallback keeps JSON/DOCX exports available.
- Report exports include recorded case/evidence details, integrity, filesystem metadata, deleted files/recovery hashes, timelines, artifact inventory, facts vs. hypotheses, and limitations.
- Report prompt specifically requires separation of observed facts and hypotheses and prohibits unsupported attribution or invented timestamps.

## Run locally

Backend terminal (Windows PowerShell):

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
# Open backend/.env and optionally set GROQ_API_KEY.
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Frontend terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Backend API documentation is available at `http://127.0.0.1:8000/docs`.

Linux/macOS can use `source .venv/bin/activate` and `cp .env.example .env` instead.

## Groq setup and data handling

Set `GROQ_API_KEY` in `backend/.env` (backend-only); the current default model is `openai/gpt-oss-20b`. To use another model, set `GROQ_MODEL` to one enabled for your account. `GROQ_TIMEOUT_SECONDS` controls the request timeout.

When enabled, the backend sends structured case/evidence intake and a bounded summary of findings, timeline entries, hashes, and artifact metadata to Groq. It does **not** send disk-image bytes or raw artifact-content bodies. Consider organizational confidentiality requirements before enabling external model processing. Without a key, a local fallback narrative is produced and its status is marked in the report. All generated narrative must be reviewed by a qualified examiner before report approval or reliance.

## Evidence and limitations

The app records a SHA-256 before scanning and rechecks it after scanning when verification is enabled. This comparison detects byte changes between the two checks; it does not independently prove that the acquisition was valid. The scanner opens the evidence image read-only. Use organization-approved write blockers, acquisition procedures, independent hash verification, and a formal chain-of-custody log as required.

This is an academic capstone implementation, not a validated commercial forensic product. Journal handling extracts targeted JBD2 evidence and correlations; it does not replay every transaction. A USB event plus archive/deletion artifacts does not prove successful copying or external transmission on its own.

## Existing data

The backend upgrades the existing SQLite schema at startup without deleting prior records. Generated reports, recovered files, evidence images, local `.env`, database files, and the integrity ledger are runtime data and should not be overwritten or committed with source-code updates.
