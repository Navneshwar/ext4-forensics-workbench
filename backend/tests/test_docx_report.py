from pathlib import Path
from unittest.mock import patch
from docx import Document
from app.services import docx_report

def test_docx_handles_sqlite_artifact_and_optional_recovery_fields(tmp_path):
    report = {
        "case": {
            "case_number": "CF-REPORT-1", "name": "Minimal report",
            "case_reference": "SECRET-TICKET", "investigation_type": "Old type",
            "lead_investigator": "Old examiner", "jurisdiction": "Old region",
            "incident_summary": "OLD INCIDENT SUMMARY", "scope": "OLD SCOPE",
        },
        "evidence": {
            "path": "test.raw", "size_bytes": 1024,
            "pre_scan_sha256": "a"*64, "post_scan_sha256": "a"*64,
            "integrity_match": True, "evidence_item_number": "EVD-REPORT-1",
            "evidence_type": "Disk image", "description": "Simple evidence item",
            "source_device": "HOST-1", "device_type": "Workstation",
            "device_make_model": "Vendor Model", "device_serial_number": "SERIAL-1",
            "device_owner": "OLD CUSTODIAN", "acquisition_method": "OLD ACQUISITION METHOD",
            "acquisition_tool": "OLD TOOL", "acquisition_operator": "OLD OPERATOR",
            "acquisition_datetime": "OLD ACQUISITION DATE", "received_datetime": "OLD RECEIVED DATE",
            "received_by": "OLD RECEIVED BY", "evidence_location": "OLD LOCKER",
            "chain_of_custody_notes": "OLD CUSTODY NOTES",
        },
        "tooling": {"resource_policy": {"io_workers": 1, "hash_workers": 1, "policy": "laptop"}},
        "filesystem": "ext4", "volume_label": "TEST",
        "filesystem_metadata": {"uuid": "u", "block_size": 4096, "inodes_count": 10, "blocks_count": 20},
        "deleted_files": [{
            "inode": 22, "original_name": "orion-report.pdf", "original_path": "/home/alex/Documents/orion-report.pdf",
            "size_bytes": 357, "deletion_time": "2026-06-18T07:18:33+00:00",
            "recovery_status": "complete", "validation_status": "size_match",
            "source": "directory", "recovered_size_bytes": 357,
            "recovered_sha256": "b"*64
        }],
        "lab02_deliverables": {
            "1_image_sha256": "a"*64,
            "2_filesystem_and_volume_label": {"filesystem": "ext4", "volume_label": "TEST"},
            "3_deleted_files_and_inodes": [{
                "inode": 22, "original_name": "orion-report.pdf",
                "original_path": "/home/alex/Documents/orion-report.pdf",
                "size_bytes": 357, "recovery_status": "complete"
            }],
            "4_usb_connected": None, "5_archive_created": None,
            "6_confidential_document_recovered": None,
            "7_icat_vs_carving": {"metadata_recovery": "x", "carving": "y"},
            "8_facts_and_hypotheses": {"facts": [], "hypotheses": []}
        },
        "timeline": [],
        "live_artifacts": [{
            "path": "/var/log/activity.log", "inode": 31, "size_bytes": 500,
            "mtime": None, "content_sha256": "c"*64, "content": "sample"
        }],
        "recovered_content": [],
        "recovered_archive_analysis": None,
        "integrity_ledger": {"message": "Ledger verified (1 event)."},
        "integrity_events": [],
        "limitations": []
    }
    out = tmp_path / "report.docx"
    with patch.object(docx_report, "build_report", return_value=report):
        docx_report.generate_docx("12345678-test", out)
    assert out.exists()
    assert out.stat().st_size > 0
    generated = Document(out)
    rendered = "\n".join(
        [paragraph.text for paragraph in generated.paragraphs]
        + [cell.text for table in generated.tables for row in table.rows for cell in row.cells]
    )
    assert "CF-REPORT-1" in rendered
    assert "EVD-REPORT-1" in rendered
    for omitted in ("SECRET-TICKET", "OLD INCIDENT SUMMARY", "OLD SCOPE", "OLD CUSTODIAN",
                    "OLD ACQUISITION METHOD", "OLD TOOL", "OLD OPERATOR", "OLD RECEIVED DATE",
                    "OLD RECEIVED BY", "OLD LOCKER", "OLD CUSTODY NOTES"):
        assert omitted not in rendered