
# EXT4 Forensics Workbench v0.2

React UI
  |
  | localhost JSON API
  v
FastAPI backend
  |
  +-- SQLite casebook
  +-- chained integrity ledger (JSONL)
  +-- resource monitor (psutil)
  |
  +-- bounded scan thread pool
       |
       +-- streamed SHA-256
       +-- MBR/GPT partition boundary detection
       +-- EXT4 superblock/group/inode analysis
       +-- deleted directory-entry + slack heuristics
       +-- targeted journal-inode / JBD2 evidence scan
       +-- pytsk3 cross-check
       +-- extent/direct-block recovery
       +-- file signature identification
       +-- recovered-file SHA-256
