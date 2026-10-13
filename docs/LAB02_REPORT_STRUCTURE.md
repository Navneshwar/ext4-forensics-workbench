# Forensic report structure in v0.5.2

The report keeps the existing Lab #02 deliverables and adds an examiner-oriented cover and narrative:

1. Case identification and evidence intake details
2. Executive summary
3. Investigation objectives and scope/methodology overview
4. Mandate
5. Image integrity and SHA-256 comparison
6. Method and resource policy
7. Filesystem and volume findings
8. Deleted-file findings and recovered-file hashes
9. Existing Lab #02 deliverables, including USB/archive evidence, confidential-document candidates, metadata recovery versus carving, and facts versus hypotheses
10. Timeline and live artifact inventory/content excerpts
11. Recovered-content strings and recovered-ZIP member analysis
12. Integrity ledger, timeline assessment, interpretation/alternative explanations, limitations, conclusion, and recommendations

The streamlined intake captures the case number and title, evidence item/type, image path, optional description, and optional source-device identifiers. Expanded administrative, acquisition, custody, and incident-context fields are intentionally omitted from the UI and report.

## Groq narrative generation

When `GROQ_API_KEY` is configured, the backend asks the configured Groq model to draft executive summary, objectives, scope/methodology, key findings, timeline assessment, interpretation, conclusion, recommendations, and limitations from structured case data and bounded examination summaries. The disk image bytes and raw artifact-content bodies are not sent. The output is cached by the structured input digest, carries generation status/model metadata, and must be reviewed by the examiner. With no key or on an API error, the report contains a labelled local fallback narrative and the export still succeeds.

## Evidence boundary

The model prompt instructs it not to invent timestamps, identities, or actions; to distinguish facts from hypotheses; and not to describe USB/archive correlations as proof of successful exfiltration. A timestamp-free shell-history row remains sequence evidence. Narrative statements do not replace the technical evidence tables.

## Implementation note

Artifact extraction uses pytsk3's root-directory traversal and reads file contents directly from each directory entry. An artifact refresh that cannot access filesystem analysis metadata reports an unavailable status rather than breaking report export.


## Report layout and methodology improvements in v0.5.2

The DOCX export uses A4 portrait pages with consistent margins, branded section headings, repeating table headers, a case/evidence summary, integrity status, and page numbering. The timestamped activity-log events are visualized as a timeline diagram; shell-history commands without timestamps appear in a separate sequence-only table and are never assigned inferred times. Evidence tables use readable field-specific widths, with raw binary archive data omitted from narrative excerpts.

The method section documents the examination stages: (1) input handling and SHA-256 baseline hashing; (2) read-only streamed access and EXT4 filesystem/superblock discovery; (3) inode, directory-entry and name/path reconstruction; (4) targeted artifact extraction, activity-log parsing and shell-history sequencing; (5) metadata-based deleted-file recovery, file-signature identification and recovered-output validation; and (6) post-scan hash comparison, cross-checks and integrity-ledger recording. It also explains the difference between metadata-based recovery and signature carving, and states the limitations of the JBD2 inspection and lack of proof of a successful USB write.
