# EXT4 Forensics Workbench v0.5 architecture

```text
React + Vite guided examiner workflow
  | case intake / evidence intake / scan / findings / report tabs
  | JSON API
  v
FastAPI backend
  |-- SQLite casebook
  |    |-- case-level metadata
  |    |-- evidence-level acquisition / custody metadata
  |    |-- scans, findings, artifacts, timeline events
  |-- SHA-256 evidence integrity checks
  |-- append-only chained JSONL integrity ledger
  |-- resource monitor (psutil)
  |-- bounded scan/recovery thread pool
  |    |-- EXT4 superblock/group/inode parsing
  |    |-- deleted directory-entry and slack heuristics
  |    |-- targeted JBD2 journal evidence scan
  |    |-- pytsk3 cross-check and artifact extraction
  |    |-- extent/direct-block recovery and signature identification
  |-- report builder
       |-- deterministic structured evidence report
       |-- optional Groq narrative with evidence-bounded prompt
       |-- labelled local fallback and digest-keyed narrative cache
       |-- JSON and examiner-reviewable DOCX exports
```

Groq credentials remain backend-only in `.env`. Model output is a draft narrative. Evidence-derived facts and technical tables remain visible in the report, and the model is explicitly instructed not to invent timestamps or attribute intent without support. Existing SQLite casebooks are upgraded in place at backend startup.
