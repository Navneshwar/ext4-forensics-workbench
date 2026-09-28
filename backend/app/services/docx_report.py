from __future__ import annotations
import json
from pathlib import Path
from docx import Document
from docx.enum.section import WD_ORIENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.shared import Inches,Pt
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from app.core.config import settings
from app.services.report_builder import build_report

def xml_safe(value) -> str:
    """Return XML 1.0-compatible text for python-docx/OpenXML."""
    text = str(value if value is not None else "")
    out = []
    for ch in text:
        code = ord(ch)
        if code in (0x09, 0x0A, 0x0D) or 0x20 <= code <= 0xD7FF or 0xE000 <= code <= 0xFFFD or 0x10000 <= code <= 0x10FFFF:
            out.append(ch)
        elif code <= 0x1F:
            out.append(f"[0x{code:02X}]")
        elif 0xD800 <= code <= 0xDFFF:
            out.append("[invalid-surrogate]")
        else:
            out.append("[invalid-xml-char]")
    return "".join(out)

def shade(cell,fill):
    tcPr=cell._tc.get_or_add_tcPr();shd=OxmlElement("w:shd");shd.set(qn("w:fill"),fill);tcPr.append(shd)

def repeat_header(row):
    trPr=row._tr.get_or_add_trPr();el=OxmlElement("w:tblHeader");el.set(qn("w:val"),"true");trPr.append(el)

def cell_text(cell,text,bold=False,size=8.5):
    cell.text="";p=cell.paragraphs[0];r=p.add_run(xml_safe(text));r.bold=bold;r.font.size=Pt(size);cell.vertical_alignment=WD_CELL_VERTICAL_ALIGNMENT.CENTER

def add_table(doc,headers,rows,sizes=None):
    t=doc.add_table(rows=1,cols=len(headers));t.style="Table Grid";t.alignment=WD_TABLE_ALIGNMENT.CENTER
    repeat_header(t.rows[0])
    for i,h in enumerate(headers):cell_text(t.rows[0].cells[i],h,True);shade(t.rows[0].cells[i],"DCE6F1")
    for row in rows:
        cells=t.add_row().cells
        for i,v in enumerate(row):cell_text(cells[i],v)
    if sizes:
        for row in t.rows:
            for i,w in enumerate(sizes):row.cells[i].width=Inches(w)
    return t

def bullet(doc,text):doc.add_paragraph(xml_safe(text),style="List Bullet")

def generate_docx(scan_id,output_path=None):
    report=build_report(scan_id)
    out=Path(output_path or settings.report_dir/f"ext4-report-{scan_id[:8]}.docx");out.parent.mkdir(parents=True,exist_ok=True)
    doc=Document();sec=doc.sections[0];sec.orientation=WD_ORIENT.LANDSCAPE;sec.page_width,sec.page_height=sec.page_height,sec.page_width
    sec.top_margin=Inches(.55);sec.bottom_margin=Inches(.55);sec.left_margin=Inches(.6);sec.right_margin=Inches(.6)
    doc.styles["Normal"].font.name="Aptos";doc.styles["Normal"].font.size=Pt(9)
    doc.styles["Title"].font.name="Aptos Display";doc.styles["Title"].font.size=Pt(24)
    doc.styles["Heading 1"].font.name="Aptos Display";doc.styles["Heading 1"].font.size=Pt(16)
    doc.styles["Heading 2"].font.name="Aptos";doc.styles["Heading 2"].font.size=Pt(11)

    p=doc.add_paragraph(style="Title");p.alignment=WD_ALIGN_PARAGRAPH.CENTER;p.add_run("EXT4 Deleted File Recovery Report")
    p=doc.add_paragraph();p.alignment=WD_ALIGN_PARAGRAPH.CENTER;r=p.add_run(xml_safe("Lab #02 · Project ORION · Machine-generated forensic work product"));r.bold=True;r.font.size=Pt(11)

    doc.add_heading("1. Mandate",1);doc.add_paragraph("Scope: preserve and analyze the supplied RAW image, identify EXT4, recover deleted files, reconstruct a defensible chronology from artifacts, and clearly separate facts from hypotheses.")
    doc.add_heading("2. Integrity",1)
    add_table(doc,["Item","Value"],[("Evidence path",report["evidence"]["path"]),("Size",f'{report["evidence"]["size_bytes"]:,} bytes'),("Pre-scan SHA-256",report["evidence"]["pre_scan_sha256"]),("Post-scan SHA-256",report["evidence"]["post_scan_sha256"] or "Pending"),("Integrity result","MATCH" if report["evidence"]["integrity_match"] else "NOT VERIFIED / CHANGED")],[1.8,8.4])
    doc.add_heading("3. Method",1);doc.add_paragraph("The workbench uses streamed read-only image access, bounded I/O/hash workers, EXT4 superblock/group/inode analysis, directory metadata reconstruction, targeted JBD2 inspection, pytsk3 cross-checking, metadata-based recovery, file-signature detection, recovered-file SHA-256, and a local chained integrity ledger.")
    p=doc.add_paragraph();p.add_run(xml_safe("Resource policy: ")).bold=True;p.add_run(xml_safe(json.dumps(report["tooling"]["resource_policy"])))

    doc.add_heading("4. Filesystem findings",1)
    fs=report.get("filesystem_metadata") or {};add_table(doc,["Filesystem","Volume label","UUID","Block size","Inodes","Blocks"],[(report["filesystem"] or "Not extracted",report["volume_label"] or "Not extracted",fs.get("uuid","—"),fs.get("block_size","—"),fs.get("inodes_count","—"),fs.get("blocks_count","—"))],[1.5,1.7,3.0,1.2,1.0,1.0])

    doc.add_heading("5. Deleted-file findings",1)
    add_table(doc,["Inode","Name","Original path","Size","Deleted UTC","Recovery","Validation","Source"],[(f["inode"],f["original_name"] or "—",f["original_path"] or "—",f["size_bytes"],f["deletion_time"] or "—",f["recovery_status"],f["validation_status"] or "—",f["source"]) for f in report["deleted_files"]],[.65,1.8,3.2,.75,1.4,1.0,1.0,1.2])
    doc.add_heading("5.1 Recovered-file hashes",2)
    add_table(doc,["Inode","Recovered file","Bytes","SHA-256"],[(f.get("inode","—"),f.get("recovered_path") or "—",f.get("recovered_size_bytes") or "—",f.get("recovered_sha256") or "—") for f in report["deleted_files"]],[.65,4.5,1.0,4.8])

    d=report["lab02_deliverables"]
    doc.add_heading("6. Required Lab #02 deliverables",1)
    doc.add_heading("6.1 Image SHA-256",2);doc.add_paragraph(d["1_image_sha256"])
    doc.add_heading("6.2 Filesystem and volume label",2);doc.add_paragraph(f'Filesystem: {d["2_filesystem_and_volume_label"]["filesystem"] or "Not extracted"}; Volume label: {d["2_filesystem_and_volume_label"]["volume_label"] or "Not extracted"}.')
    doc.add_heading("6.3 Deleted files and inodes",2)
    for f in d["3_deleted_files_and_inodes"]:bullet(doc,f'Inode {f.get("inode","—")}: {f.get("original_name") or "unnamed"} · {f.get("original_path") or "path not reconstructed"} · {f.get("size_bytes","—")} bytes · {f.get("recovery_status","—")}.')
    doc.add_heading("6.4 USB connection",2);doc.add_paragraph(xml_safe(json.dumps(d["4_usb_connected"],indent=2)) if d["4_usb_connected"] else xml_safe("No USB connection event was extracted from the image."))
    doc.add_heading("6.5 Archive creation",2);doc.add_paragraph(xml_safe(json.dumps(d["5_archive_created"],indent=2)) if d["5_archive_created"] else xml_safe("No archive creation event was extracted from the image."))
    doc.add_heading(xml_safe("6.6 Confidential document recovery"),2)
    if d["6_confidential_document_recovered"]:
        for f in d["6_confidential_document_recovered"]["candidates"]:bullet(doc,f'Inode {f.get("inode","—")}: {f.get("original_name") or "—"} · {f.get("original_path") or "—"} · {f.get("size_bytes","—")} bytes · SHA-256 {f.get("recovered_sha256") or "—"}.')
    else:doc.add_paragraph("No PDF recovery candidate was identified.")
    doc.add_heading("6.7 Metadata recovery vs carving",2);doc.add_paragraph("Metadata recovery: "+d["7_icat_vs_carving"]["metadata_recovery"]);doc.add_paragraph("Carving: "+d["7_icat_vs_carving"]["carving"])
    doc.add_heading("6.8 Facts vs hypotheses",2)
    doc.add_paragraph("Facts",style="Heading 2")
    for x in d["8_facts_and_hypotheses"]["facts"]:bullet(doc,x)
    doc.add_paragraph("Hypotheses / interpretation",style="Heading 2")
    for x in d["8_facts_and_hypotheses"]["hypotheses"]:bullet(doc,x)

    doc.add_heading("7. Timeline",1)
    rows=[]
    for e in report["timeline"]:
        ts=e.get("timestamp") or (f'order #{e.get("sequence")}' if e.get("sequence") else "—")
        rows.append((ts,e.get("source") or "—",e.get("event") or "—",e.get("details") or "—"))
    add_table(doc,["Timestamp / order","Source","Event","Details"],rows,[1.7,2.6,1.7,5.4])

    doc.add_heading("8. Live artifact inventory",1)
    add_table(doc,["Path","Inode","Size","Mtime UTC","SHA-256"],[(a.get("path","—"),a.get("inode","—"),a.get("size",a.get("size_bytes",0)),a.get("mtime") or "—",a.get("content_sha256") or "—") for a in report.get("live_artifacts",[])],[4.0,.7,1.0,1.6,4.2])
    for a in report.get("live_artifacts",[]):
        if a.get("content"):
            doc.add_heading(a["path"],2);p=doc.add_paragraph();r=p.add_run(xml_safe((a.get("content") or "")[:4000]));r.font.name="Consolas";r.font.size=Pt(7.7)

    doc.add_heading("9. Recovered content and archive analysis",1)
    for x in report.get("recovered_content",[]):
        doc.add_heading(f'Inode {x["inode"]} · recovered content strings',2);p=doc.add_paragraph();r=p.add_run(xml_safe(x.get("strings","")));r.font.name="Consolas";r.font.size=Pt(7.7)
    archive=report.get("recovered_archive_analysis")
    if archive:
        doc.add_heading("Recovered ZIP members",2)
        add_table(doc,["Member","Size","Compressed","SHA-256"],[(m.get("name"),m.get("size_bytes"),m.get("compressed_size_bytes"),m.get("sha256","—")) for m in archive.get("members",[])],[5.0,1.2,1.4,4.0])

    doc.add_heading("10. Integrity ledger",1);doc.add_paragraph(report["integrity_ledger"]["message"])
    for e in report.get("integrity_events",[]):doc.add_paragraph(f'{e["created_at"]} · {e["event_type"]} · {e.get("algorithm") or ""} · {e.get("value") or ""}')
    doc.add_heading("11. Limitations",1)
    for x in report.get("limitations",[]):bullet(doc,x)
    doc.add_heading("12. Conclusion",1)
    doc.add_paragraph("The image and its recoverable EXT4 artefacts establish the filesystem structure, deleted files, recovered content, and recorded timeline events shown above. Interpretive statements are kept separate: a USB connection, staged archive, deleted files or shell-history clearing may support an exfiltration hypothesis, but these artefacts alone do not prove successful copying to the USB device or external transmission.")

    foot=sec.footer.paragraphs[0];foot.alignment=WD_ALIGN_PARAGRAPH.CENTER;foot.add_run(xml_safe("EXT4 Forensics Workbench v0.4.3 · Local forensic work product"))
    doc.save(out)
    return str(out)
