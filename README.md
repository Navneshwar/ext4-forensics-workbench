# EXT4 Deleted File Recovery Workbench

A local-first forensic workbench for analyzing Linux EXT4 disk images, identifying deleted-file candidates, recovering available file content, correlating filesystem and journal evidence, and preserving integrity information for later review.

## Overview

The project combines a Python backend with a React frontend to provide a user-friendly workflow for controlled forensic image analysis.

Typical workflow:

```text
Forensic image
     │
     ├── SHA-256 integrity hash
     │
     ├── Partition / EXT4 identification
     │
     ├── Inode analysis
     │      └── Deleted-file candidates
     │
     ├── Directory-entry analysis
     │      └── Filename / path reconstruction
     │
     ├── Journal inspection
     │      └── Supporting filesystem evidence
     │
     ├── File recovery
     │      └── Extents / block-based reconstruction
     │
     ├── File-signature identification
     │
     ├── Recovered-file SHA-256
     │
     └── JSON / DOCX forensic reporting
```

## Features

- Read-only analysis of RAW forensic images
- EXT4 superblock, group descriptor, and inode analysis
- Deleted inode candidate detection
- Deleted directory-entry and directory-slack analysis
- Conservative filename and path reconstruction
- Journal/JBD2 evidence inspection
- Metadata-based file recovery
- Extent and legacy block recovery support
- File-signature identification for common formats
- Complete vs partial recovery classification
- SHA-256 hashing for evidence and recovered files
- Pre-analysis and post-analysis evidence integrity verification
- Local SQLite case database
- Append-only hash-chained integrity ledger
- `pytsk3` filesystem cross-checking
- Live CPU/RAM monitoring
- Bounded I/O and hashing workers for laptop-friendly operation
- Windows path handling
- JSON forensic report generation
- DOCX forensic report generation
- Separate recovery and report output directories

## Technology Stack

### Backend

- Python 3.12+
- FastAPI
- Uvicorn
- SQLite
- `pytsk3`
- `python-docx`
- `psutil`

### Frontend

- React
- Vite
- JavaScript
- CSS

## Architecture

```text
React + Vite
     │
     │ HTTP / JSON
     ▼
FastAPI
     │
     ├── Case database (SQLite)
     ├── Integrity ledger (JSONL)
     ├── Resource monitor
     └── Forensic analysis services
             │
             ├── Image I/O
             ├── EXT4 parser
             ├── Directory analysis
             ├── Journal analysis
             ├── Recovery engine
             ├── File signatures
             └── pytsk3 cross-check
```

## Requirements

- Windows, Linux, or another Python-compatible environment
- Python 3.12 or newer
- Node.js 20+ recommended
- A controlled forensic disk image such as RAW
- Sufficient free storage for recovered files and generated reports

## Windows Installation

### Backend

```powershell
cd backend

python -m venv .venv
.venv\Scripts\activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Start the API:

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Frontend

In a second terminal:

```powershell
cd frontend

npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

The API documentation is available at:

```text
http://127.0.0.1:8000/docs
```

## Using the Workbench

1. Provide a forensic image path.
2. The backend calculates an initial SHA-256 hash.
3. The image is analyzed without modifying the evidence file.
4. Deleted inode candidates are identified.
5. Surviving directory metadata is examined for names and paths.
6. Journal evidence is inspected when available.
7. Select recoverable findings.
8. Recover files into the separate recovery directory.
9. Verify recovered-file hashes and recovery completeness.
10. Export the JSON or DOCX forensic report.

Windows paths may be entered with or without surrounding quotes:

```text
C:\Forensics\evidence.img
```

or

```text
"C:\Forensics\evidence.img"
```

## Resource Management

Disk-forensics workloads can generate substantial storage and CPU activity. The workbench therefore uses bounded worker pools and streaming reads rather than loading an entire image into RAM.

Default settings are intentionally conservative:

```text
I/O workers:   2
Hash workers:  2
Concurrent scans: 1
```

The UI also exposes current CPU and RAM usage and provides laptop-friendly worker settings.

For large images, increase worker counts gradually while monitoring:

- CPU utilization
- RAM usage
- storage throughput
- disk temperature
- system responsiveness

## Evidence Integrity

The application maintains two local integrity layers.

### Evidence hashes

The original image receives:

- pre-analysis SHA-256
- post-analysis SHA-256

A mismatch indicates that the evidence file changed during processing.

### Integrity ledger

Important actions are recorded in an append-only JSONL ledger.

Each ledger entry contains:

```text
previous_hash
entry_hash
event metadata
```

This creates a hash chain that makes later modification of ledger entries detectable.

## Recovery Model

The recovery engine distinguishes between several outcomes:

```text
candidate
   │
   ├── complete
   │
   ├── partial
   │
   └── not_recoverable
```

A `complete` result means the expected logical file size was reconstructed from available filesystem metadata and data blocks.

A `partial` result means some content was recovered but the complete logical file could not be reconstructed.

Recovery status should not be interpreted as proof of authenticity against an external original unless independent known-good evidence is available.

## Filename and Path Reconstruction

The workbench attempts to recover original filenames and paths using surviving filesystem metadata.

Reconstruction is deliberately conservative:

```text
Deleted inode
     │
     ├── directory entry
     ├── directory slack
     └── journal evidence
              │
              ▼
      candidate filename/path
```

When sufficient evidence does not exist, the tool retains a safe generic name instead of inventing a path.

## File Identification

Recovered content is checked against common file signatures, including formats such as:

- PDF
- PNG
- JPEG
- GIF
- ZIP
- GZIP
- ELF
- SQLite
- RAR
- 7-Zip

Unknown content is retained as binary data rather than being assigned an unsupported type.

## Reporting

### JSON

The machine-readable report can contain:

- case metadata
- evidence information
- filesystem findings
- deleted-file findings
- recovery information
- recovered-file hashes
- timeline data
- supporting artifacts
- integrity events
- limitations
- facts vs hypotheses

### DOCX

The human-readable report can contain:

- mandate
- integrity
- methodology
- filesystem findings
- deleted-file findings
- recovery results
- timeline
- supporting artifacts
- metadata recovery vs carving discussion
- facts vs hypotheses
- limitations
- conclusion

## Important Scope Notes

This project is an academic/research implementation and is not intended to replace a validated commercial forensic suite.

In particular:

- Journal analysis is evidence extraction, not a complete JBD2 replay implementation.
- Deleted-file recovery depends on surviving inode metadata and data blocks.
- Fragmented or overwritten files may be incomplete.
- Filename reconstruction is conservative and may be unavailable.
- A recovered file does not by itself establish how it was originally created, transferred, or used.
- A USB connection, archive creation, deletion event, or shell command should be interpreted in context rather than treated as independent proof of an external transfer.

## Testing

Run backend tests with:

```powershell
cd backend
pytest -q
```

The test suite covers core components such as:

- Windows path handling
- file-signature identification
- directory-entry parsing
- report-generation compatibility
- DOCX XML safety

For forensic validation, use controlled known-answer images as separate integration-test datasets. Large evidence images should not be committed to the repository.

## Project Structure

```text
.
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── db/
│   │   ├── forensics/
│   │   └── services/
│   ├── tests/
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── lib/
│   │   └── pages/
│   ├── package.json
│   └── vite.config.js
│
├── recovered/
├── reports/
├── docs/
└── scripts/
```

## Safety

Always work on a forensic copy of the source media or image.

The application is designed so that:

- evidence input is opened read-only
- recovery output is stored separately
- reports are stored separately
- integrity hashes are recorded locally

Do not run experimental recovery operations against original evidence.

## License

Choose a license appropriate for your repository before publishing. A permissive option such as MIT is suitable for many academic projects, but the final choice should reflect your intended use and any third-party dependencies.

## Contributing

Issues and pull requests are welcome.

Useful contributions include:

- additional filesystem support
- stronger EXT4 journal parsing
- more file signatures
- integration tests
- performance benchmarking
- report improvements
- cross-platform testing
