from types import SimpleNamespace

from app.services import ai_report_service


def test_local_fallback_is_labelled_when_groq_is_not_configured(monkeypatch):
    monkeypatch.setattr(
        ai_report_service,
        "settings",
        SimpleNamespace(groq_api_key="", groq_model="openai/gpt-oss-20b"),
    )
    narrative = ai_report_service.generate_ai_report(
        {
            "case": {"id": "case-1", "case_number": "CF-1", "name": "Test case"},
            "evidence": {"integrity_match": True},
            "deleted_files": [{"recovery_status": "complete"}],
            "timeline": [],
            "facts": ["One fact derived from the image."],
        },
        "scan-1",
    )
    assert narrative["generation"]["status"] == "not_configured"
    assert "Groq did not generate" in " ".join(narrative["limitations"])
    assert "1 deleted-file candidate" in narrative["executive_summary"]


def test_model_input_excludes_raw_artifact_content():
    payload = ai_report_service._model_input({
        "case": {"case_number": "CF-2", "name": "Case 2"},
        "evidence": {"path": "/evidence/disk.raw", "sha256": "abc"},
        "live_artifacts": [{"path": "/var/log/activity.log", "content": "SENSITIVE RAW CONTENT", "content_sha256": "digest"}],
    })
    assert "content" not in payload["artifacts"][0]
    assert "SENSITIVE RAW CONTENT" not in str(payload)


def test_model_input_omits_unneeded_case_and_acquisition_metadata():
    payload = ai_report_service._model_input({
        "case": {
            "case_number": "CF-3", "name": "Minimal case",
            "case_reference": "TICKET-123", "investigation_type": "Internal",
            "lead_investigator": "Examiner", "requesting_organization": "Org",
            "jurisdiction": "Region", "incident_summary": "Reported incident",
            "scope": "Broad scope", "legal_authority": "Reference", "status": "Open",
        },
        "evidence": {
            "evidence_item_number": "EVD-3", "evidence_type": "Disk image",
            "device_owner": "Custodian", "acquisition_method": "Physical image",
            "acquisition_tool": "Tool v1", "acquisition_operator": "Operator",
            "acquisition_datetime": "2026-01-01T00:00:00Z", "received_datetime": "2026-01-02T00:00:00Z",
            "received_by": "Recipient", "evidence_location": "Locker", "chain_of_custody_notes": "Notes",
            "sha256": "a" * 64,
        },
    })
    assert payload["case"] == {"case_number": "CF-3", "name": "Minimal case"}
    assert payload["evidence"]["evidence_item_number"] == "EVD-3"
    assert payload["evidence"]["sha256"] == "a" * 64
    assert not any(key in str(payload) for key in (
        "TICKET-123", "Reported incident", "Physical image", "Tool v1", "Custodian", "Locker", "Operator"
    ))
