from unittest.mock import patch
from app.services import docx_report

def test_docx_sanitizes_null_and_control_characters(tmp_path):
    report = {
        "evidence": {
            "path": "C:/evidence/test.raw\x00",
            "size_bytes": 48,
            "pre_scan_sha256": "a" * 64,
            "post_scan_sha256": "a" * 64,
            "integrity_match": True
        },
        "tooling": {"resource_policy": {"io_workers": 1, "hash_workers": 1, "policy": "laptop"}},
        "filesystem": "ext4\x01",
        "volume_label": "TEST\x00",
        "filesystem_metadata": {"uuid": "u", "block_size": 4096, "inodes_count": 10, "blocks_count": 20},
        "deleted_files": [{
            "inode": 22, "original_name": "orion-report.pdf",
            "original_path": "/home/alex/Documents/orion-report.pdf",
            "size_bytes": 357, "deletion_time": "2026-06-18T07:18:33+00:00",
            "recovery_status": "complete", "validation_status": "size_match",
            "source": "directory", "recovered_size_bytes": 357,
            "recovered_sha256": "b" * 64, "recovered_path": "C:/recovered/x.pdf"
        }],
        "lab02_deliverables": {
            "1_image_sha256": "a" * 64,
            "2_filesystem_and_volume_label": {"filesystem": "ext4", "volume_label": "TEST"},
            "3_deleted_files_and_inodes": [],
            "4_usb_connected": {"timestamp": "2026-06-18T09:06:41+02:00", "details": "label=TRANSFER\x00"},
            "5_archive_created": None,
            "6_confidential_document_recovered": None,
            "7_icat_vs_carving": {"metadata_recovery": "x", "carving": "y"},
            "8_facts_and_hypotheses": {"facts": ["fact\x02"], "hypotheses": ["hypothesis\x0b"]}
        },
        "timeline": [{
            "timestamp": "2026-06-18T09:06:41+02:00", "source": "activity.log",
            "event": "usb_connected", "details": "serial=SN\x00"
        }],
        "live_artifacts": [{
            "path": "/var/log/activity.log",
            "inode": 31,
            "size_bytes": 20,
            "mtime": None,
            "content_sha256": "c" * 64,
            "content": "USB\x00connected\x0bserial"
        }],
        "recovered_content": [{
            "inode": 22,
            "strings": "Project ORION\x00CONFIDENTIAL\x1f"
        }],
        "recovered_archive_analysis": None,
        "integrity_ledger": {"message": "Ledger verified."},
        "integrity_events": [],
        "limitations": ["Limit\x00"]
    }

    out = tmp_path / "safe.docx"
    with patch.object(docx_report, "build_report", return_value=report):
        docx_report.generate_docx("test-scan", out)

    assert out.exists()
    assert out.stat().st_size > 0
