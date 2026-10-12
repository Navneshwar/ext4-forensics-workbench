import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import Pill from "../components/Pill";
import Progress from "../components/Progress";
import Metric from "../components/Metric";

const savedPath = localStorage.getItem("lastEvidencePath") || "";
const savedScan = localStorage.getItem("lastScanId") || "";
const initialForm = {
  caseNumber: "",
  caseName: "Cyber forensic examination",
  evidenceItemNumber: "EVD-001",
  evidenceType: "Disk image",
  evidenceDescription: "",
  imagePath: savedPath,
  sourceDevice: "",
  deviceType: "",
  deviceMakeModel: "",
  deviceSerialNumber: "",
};

const steps = [
  { title: "Case details", short: "CASE", help: "Enter the case number used to identify this examination and a short case title. Keep the title factual and concise." },
  { title: "Evidence intake", short: "EVIDENCE", help: "Identify the evidence item and provide the image path as seen by the backend machine. Source-device details are optional. The scanner accesses the image read-only and records its SHA-256 hash." },
  { title: "Scan & verify", short: "ANALYSIS", help: "The backend records a pre-scan SHA-256 and rechecks evidence integrity after analysis. Use conservative worker counts on laptops. A hash match indicates the image bytes matched across those checks; it does not prove the acquisition itself was correct." },
  { title: "Findings & recovery", short: "FINDINGS", help: "Review the filesystem-derived candidates before recovery. Names and paths can be reconstructed or uncertain. Recover only where authorized, then review recovery status, validation, and recovered-file hashes." },
  { title: "Forensic report", short: "REPORT", help: "The report includes the case number, evidence identifiers, image integrity, methods, filesystem findings, deleted files, timelines, limitations, and the generated narrative. Verify all interpretation against the underlying evidence." },
];

function tone(value) {
  const v = String(value || "").toLowerCase();
  if (["completed", "complete", "high", "size_match", "recovered", "match", "generated"].includes(v)) return "good";
  if (["running", "candidate", "medium", "partial", "pending", "not_configured", "fallback"].includes(v)) return "info";
  if (["failed", "integrity_changed", "low", "not_recoverable", "recovery_failed", "changed", "error"].includes(v)) return "bad";
  return "neutral";
}

function Field({ id, label, help, activeHelp, setActiveHelp, required = false, children }) {
  const open = activeHelp === id;
  return (
    <div className="field">
      <div className="field-label-row">
        <label htmlFor={id}>{label}{required && <span className="required"> *</span>}</label>
        <button type="button" className="help-dot" aria-label={`Help for ${label}`} aria-expanded={open} onClick={() => setActiveHelp(open ? "" : id)}>?</button>
      </div>
      {children}
      {open && <div className="field-help">{help}</div>}
    </div>
  );
}

export default function Dashboard() {
  const [form, setForm] = useState(initialForm);
  const [workers, setWorkers] = useState({ io: 1, hash: 2 });
  const [scanId, setScanId] = useState(savedScan);
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [resources, setResources] = useState(null);
  const [integrity, setIntegrity] = useState(null);
  const [aiStatus, setAiStatus] = useState(null);
  const [selected, setSelected] = useState(new Set());
  const [activeStep, setActiveStep] = useState(savedScan ? 3 : 0);
  const [stepHelpOpen, setStepHelpOpen] = useState(false);
  const [activeHelp, setActiveHelp] = useState("");
  const [busy, setBusy] = useState(false);
  const [recovering, setRecovering] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  function setValue(key, value) {
    setForm((old) => ({ ...old, [key]: value }));
  }

  useEffect(() => {
    let cancelled = false;
    let timer;
    async function pollResources() {
      try {
        const data = await api.resources();
        if (!cancelled) setResources(data);
      } catch { /* Backend may still be starting. */ }
      try {
        const status = await api.aiStatus();
        if (!cancelled) setAiStatus(status);
      } catch { /* Report exports still explain the local fallback state. */ }
      if (!cancelled) timer = window.setTimeout(pollResources, 5000);
    }
    pollResources();
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, []);

  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;
    let timer;
    async function pollScan() {
      try {
        const current = await api.scan(scanId);
        if (cancelled) return;
        setScan(current);
        const rows = await api.findings(scanId);
        if (cancelled) return;
        setFindings(rows);
        try {
          const integrityData = await api.integrity(current.case_id);
          if (!cancelled) setIntegrity(integrityData);
        } catch { /* Keep results visible if the ledger endpoint is temporarily unavailable. */ }
        if (!["completed", "failed", "integrity_changed"].includes(current.status)) {
          timer = window.setTimeout(pollScan, 1500);
        }
      } catch (e) {
        if (!cancelled) setError(e.message);
        timer = window.setTimeout(pollScan, 2200);
      }
    }
    pollScan();
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [scanId]);

  const recoverable = useMemo(
    () => findings.filter((item) => Boolean(item.recoverable) && item.file_type === "regular" && item.recovery_status !== "complete"),
    [findings]
  );
  const final = scan && ["completed", "failed", "integrity_changed"].includes(scan.status);
  const hashMatch = Boolean(scan?.post_scan_sha256) && scan.pre_scan_sha256 === scan.post_scan_sha256;

  function validateStep(step) {
    if (step === 0) {
      if (!form.caseNumber.trim()) return "Enter the assigned case number before continuing.";
      if (!form.caseName.trim()) return "Enter a case title.";
    }
    if (step === 1 && !form.imagePath.trim()) return "Enter the evidence image path accessible to the backend machine.";
    return "";
  }

  function goNext() {
    const issue = validateStep(activeStep);
    if (issue) { setError(issue); return; }
    setError("");
    setStepHelpOpen(false);
    setActiveHelp("");
    setActiveStep((current) => Math.min(steps.length - 1, current + 1));
  }

  function goToStep(index) {
    if ((index >= 3 && !scanId) || (index === 4 && !final)) return;
    setActiveStep(index);
    setStepHelpOpen(false);
    setActiveHelp("");
    setError("");
  }

  async function startScan() {
    const caseIssue = validateStep(0);
    const evidenceIssue = validateStep(1);
    if (caseIssue || evidenceIssue) {
      setError(caseIssue || evidenceIssue);
      setActiveStep(caseIssue ? 0 : 1);
      return;
    }
    setBusy(true);
    setError("");
    setMessage("");
    setSelected(new Set());
    try {
      const result = await api.createScan({
        image_path: form.imagePath,
        case_name: form.caseName,
        case_number: form.caseNumber,
        evidence_item_number: form.evidenceItemNumber,
        evidence_type: form.evidenceType,
        evidence_description: form.evidenceDescription,
        source_device: form.sourceDevice,
        device_type: form.deviceType,
        device_make_model: form.deviceMakeModel,
        device_serial_number: form.deviceSerialNumber,
        io_workers: workers.io,
        hash_workers: workers.hash,
        resource_policy: workers.io === 1 ? "laptop" : "balanced",
      });
      localStorage.setItem("lastEvidencePath", form.imagePath);
      localStorage.setItem("lastScanId", result.scan_id);
      setScanId(result.scan_id);
      setScan(null);
      setFindings([]);
      setMessage(`Scan queued for case ${result.case_number || form.caseNumber} · evidence item ${result.evidence_item_number}.`);
      setActiveStep(3);
    } catch (e) {
      setError(e.message);
      setActiveStep(e.message.toLowerCase().includes("case number") ? 0 : 1);
    } finally {
      setBusy(false);
    }
  }

  function selectAll() { setSelected(new Set(recoverable.map((item) => item.id))); }
  function toggle(id) {
    setSelected((old) => {
      const next = new Set(old);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  async function recoverSelected() {
    if (!selected.size || !scanId) return;
    setRecovering(true); setMessage(""); setError("");
    try {
      const result = await api.recover(scanId, [...selected]);
      const ok = result.results.filter((item) => item.status === "recovered" || item.recovery_status === "complete").length;
      const partial = result.results.filter((item) => item.recovery_status === "partial").length;
      setMessage(`${ok} file(s) recovered or processed successfully; ${partial} partial result(s).`);
      setFindings(await api.findings(scanId));
      if (scan?.case_id) setIntegrity(await api.integrity(scan.case_id));
      setSelected(new Set());
    } catch (e) { setError(e.message); }
    finally { setRecovering(false); }
  }

  async function refreshArtifacts() {
    if (!scanId) return;
    setRefreshing(true); setMessage(""); setError("");
    try {
      const result = await api.refreshArtifacts(scanId);
      setMessage(`Artifact refresh ${result.status || "finished"}: ${result.message || "review the updated report output."}`);
    } catch (e) { setError(e.message); }
    finally { setRefreshing(false); }
  }

  function renderField(key, label, help, options = {}) {
    const id = key;
    const baseProps = {
      id,
      value: form[key] ?? "",
      onChange: (e) => setValue(key, e.target.value),
      required: Boolean(options.required),
      placeholder: options.placeholder || "",
      maxLength: options.maxLength || 6000,
    };
    const control = options.textarea ? (
      <textarea {...baseProps} rows={options.rows || 3} />
    ) : options.select ? (
      <select {...baseProps}>
        {options.select.map((opt) => <option key={opt} value={opt}>{opt}</option>)}
      </select>
    ) : (
      <input {...baseProps} type={options.type || "text"} />
    );
    return <Field key={id} id={id} label={label} help={help} required={options.required} activeHelp={activeHelp} setActiveHelp={setActiveHelp}>{control}</Field>;
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">FX</div>
          <div><div className="brand-title">FORENSIC WORKBENCH</div><div className="brand-subtitle">EXT4 evidence examination · Local-first workflow</div></div>
        </div>
        <div className="topbar-status"><span className="online-dot" />{aiStatus?.configured ? `Groq enabled · ${aiStatus.model}` : "Local analysis · Groq not configured"}</div>
      </header>

      <main className="content">
        <section className="hero">
          <div>
            <div className="eyebrow">DIGITAL EVIDENCE · CASE-BASED EXAMINATION</div>
            <h1>Record. Examine. Report.</h1>
            <p>Guided case intake, evidence integrity checks, deleted-file analysis, and a structured cyber-forensic report with clearly separated observations and interpretation.</p>
          </div>
          <div className="hero-symbol"><span>SHA</span><strong>256</strong></div>
        </section>

        <nav className="wizard-nav" aria-label="Forensic workflow steps">
          {steps.map((step, index) => {
            const locked = (index >= 3 && !scanId) || (index === 4 && !final);
            const complete = index === 0 ? Boolean(form.caseNumber.trim()) : index === 1 ? Boolean(form.imagePath.trim()) : index === 2 ? Boolean(scanId) : index === 3 ? Boolean(final) : false;
            return (
              <button type="button" key={step.title} className={`wizard-step ${activeStep === index ? "active" : ""} ${complete ? "complete" : ""}`} disabled={locked} onClick={() => goToStep(index)}>
                <span className="step-number">{complete ? "✓" : String(index + 1).padStart(2, "0")}</span>
                <span className="step-copy"><strong>{step.title}</strong><small>{step.short}</small></span>
                <span className="step-arrow">{index < steps.length - 1 ? "›" : ""}</span>
              </button>
            );
          })}
        </nav>

        <section className="panel workflow-panel">
          <div className="section-head">
            <div>
              <div className="kicker">STEP {String(activeStep + 1).padStart(2, "0")} / 05 · {steps[activeStep].short}</div>
              <h2>{steps[activeStep].title}</h2>
              <p>Complete the required fields, use ? for help, and move through each stage in order.</p>
            </div>
            <button type="button" className={`help-trigger ${stepHelpOpen ? "is-open" : ""}`} onClick={() => setStepHelpOpen((open) => !open)} aria-expanded={stepHelpOpen} aria-label={`Help for ${steps[activeStep].title}`}>? <span>Step help</span></button>
          </div>
          {stepHelpOpen && <div className="step-help"><strong>Guidance for this step</strong><p>{steps[activeStep].help}</p></div>}
          {error && <div className="alert bad" role="alert">{error}</div>}
          {message && <div className="alert good" role="status">{message}</div>}

          {activeStep === 0 && (
            <>
              <div className="safety"><strong>Case identification</strong><span>Only the case number and a short title are needed here. Detailed administrative intake fields are omitted.</span></div>
              <div className="form-grid">
                {renderField("caseNumber", "Case number", "The identifier assigned to this examination. It is included in the report and must be unique in the local casebook.", { required: true, placeholder: "e.g. CF-2026-00124" })}
                {renderField("caseName", "Case title", "A short, neutral title for the examination. Avoid placing conclusions in the title.", { required: true, placeholder: "e.g. EXT4 disk image examination" })}
              </div>
              <div className="wizard-actions"><span className="note">Both fields are required.</span><button className="primary" type="button" onClick={goNext}>Continue to evidence intake <span>→</span></button></div>
            </>
          )}

          {activeStep === 1 && (
            <>
              <div className="safety"><strong>Evidence preservation</strong><span>The original image is opened read-only by the scanner. The path must be valid on the machine running the backend, not just on the browser machine.</span></div>
              <div className="form-grid">
                {renderField("evidenceItemNumber", "Evidence item number", "Identifier for this evidence item. It appears in the report.", { required: true, placeholder: "EVD-001" })}
                {renderField("evidenceType", "Evidence type", "Choose the broad type of item submitted for examination.", { select: ["Disk image", "Removable media image", "Physical device", "Logical collection", "Memory image", "Other"] })}
                {renderField("imagePath", "Evidence image path", "Absolute path to the disk image on the backend machine. Example: C:\\Forensics\\evidence-01.raw. The UI does not upload the image over HTTP.", { required: true, placeholder: "C:\\Forensics\\evidence-01.raw" })}
                {renderField("evidenceDescription", "Evidence description (optional)", "A brief description of the submitted item. Do not include unrelated personal data or credentials.", { textarea: true, rows: 3 })}
                {renderField("sourceDevice", "Source device / asset ID (optional)", "Host name, asset tag, or device inventory identifier when known.", { placeholder: "Asset tag / host ID" })}
                {renderField("deviceType", "Device type (optional)", "For example: laptop, workstation, server, external HDD, SSD, or USB device.", { placeholder: "Laptop, USB drive, server…" })}
                {renderField("deviceMakeModel", "Make and model (optional)", "Manufacturer and model when known.", { placeholder: "Manufacturer / model" })}
                {renderField("deviceSerialNumber", "Serial number (optional)", "Serial number or device asset identifier, if known.", { placeholder: "Serial / asset identifier" })}
              </div>
              <div className="wizard-actions"><button className="ghost" type="button" onClick={() => setActiveStep(0)}>← Back to case</button><button className="primary" type="button" onClick={goNext}>Continue to scan settings <span>→</span></button></div>
            </>
          )}

          {activeStep === 2 && (
            <>
              <div className="safety"><strong>Hash first, analyze second</strong><span>A SHA-256 digest is recorded before scanning. The backend rechecks integrity afterward when post-scan verification is enabled.</span></div>
              <div className="two-col inner-two-col">
                <div>
                  <h3>Resource policy</h3>
                  <p className="field-description">Worker counts are capped by backend configuration.</p>
                  <div className="mode-row">
                    <button type="button" className={`mode ${workers.io === 1 ? "active" : ""}`} onClick={() => setWorkers({ io: 1, hash: 2 })}>Laptop safe</button>
                    <button type="button" className={`mode ${workers.io > 1 ? "active" : ""}`} onClick={() => setWorkers({ io: 2, hash: 2 })}>Balanced</button>
                  </div>
                  <div className="workers">
                    <Field id="ioWorkers" label="I/O workers" help="Parallel inode and image I/O tasks. Fewer workers reduce resource pressure on small machines." activeHelp={activeHelp} setActiveHelp={setActiveHelp}><input id="ioWorkers" type="number" min="1" max="4" value={workers.io} onChange={(e) => setWorkers({ ...workers, io: Math.max(1, Math.min(4, Number(e.target.value) || 1)) })} /></Field>
                    <Field id="hashWorkers" label="Hash workers" help="Parallel hashing tasks. Higher counts can increase memory and storage I/O consumption." activeHelp={activeHelp} setActiveHelp={setActiveHelp}><input id="hashWorkers" type="number" min="1" max="4" value={workers.hash} onChange={(e) => setWorkers({ ...workers, hash: Math.max(1, Math.min(4, Number(e.target.value) || 1)) })} /></Field>
                  </div>
                </div>
                <div className="resource-box">
                  <h3>Live system resources</h3>
                  <div className="resource-line"><span>CPU</span><Progress value={resources?.cpu_percent} /></div>
                  <div className="resource-line"><span>RAM</span><Progress value={resources?.ram_percent} /></div>
                  <div className="recommend">Recommended: I/O {resources?.recommended_io_workers ?? "—"} · Hash {resources?.recommended_hash_workers ?? "—"}</div>
                  <div className="resource-facts"><span>CPU cores <strong>{resources?.cpu_count ?? "—"}</strong></span><span>Available RAM <strong>{resources ? `${(resources.ram_available_bytes / 1024 ** 3).toFixed(1)} GB` : "—"}</strong></span></div>
                </div>
              </div>
              <div className="review-grid">
                <div><span>CASE</span><strong>{form.caseNumber || "Not entered"}</strong><small>{form.caseName}</small></div>
                <div><span>EVIDENCE</span><strong>{form.evidenceItemNumber || "Not assigned"}</strong><small>{form.evidenceType}</small></div>
                <div className="review-path"><span>IMAGE PATH</span><strong>{form.imagePath || "Not entered"}</strong><small>Validated by the backend before scanning</small></div>
              </div>
              <div className="wizard-actions"><button className="ghost" type="button" onClick={() => setActiveStep(1)}>← Back to evidence</button><button className="primary" type="button" disabled={busy} onClick={startScan}>{busy ? "Registering evidence & starting scan…" : "Hash evidence & start scan →"}</button></div>
            </>
          )}

          {activeStep === 3 && (
            <>
              {!scan && <div className="empty"><strong>Waiting for an analysis</strong><span>Enter the case number and evidence image path, then start a scan.</span><button type="button" className="ghost" onClick={() => setActiveStep(0)}>Go to case intake</button></div>}
              {scan && (
                <>
                  <section className="metric-grid result-metrics">
                    <Metric label="Scan status" value={<Pill value={scan.status} tone={tone(scan.status)} />} hint={scan.stage} />
                    <Metric label="Progress" value={`${Number(scan.progress).toFixed(1)}%`} hint={scan.message || "Waiting for scanner status"} />
                    <Metric label="Evidence size" value={`${(Number(scan.size_bytes || 0) / 1024 / 1024).toFixed(1)} MB`} hint={`${scan.io_workers} I/O · ${scan.hash_workers} hash workers`} />
                    <Metric label="Deleted candidates" value={findings.length} hint={`${recoverable.length} currently marked recoverable`} />
                  </section>
                  <section className="result-panel">
                    <div className="section-head"><div><div className="kicker">EXAMINATION PIPELINE</div><h3>Scan progress</h3></div><span className="mono">{scan.stage}</span></div>
                    <Progress value={scan.progress} />
                    <div className="pipeline">{["hash_pre", "inode_scan", "directory_scan", "journal", "artifacts", "findings", "hash_post", "complete"].map((stage) => <div key={stage} className={`pipeline-step ${scan.stage === stage ? "active" : ""}`}><span className="dot" />{stage.replaceAll("_", " ")}</div>)}</div>
                    <div className="status-message">{scan.message || "Waiting for scan status…"}</div>
                    {scan.error && <div className="alert bad">{scan.error}</div>}
                  </section>
                  {final && <>
                    <section className="result-panel">
                      <div className="section-head"><div><div className="kicker">RECOVERY REVIEW</div><h3>Deleted-file candidates</h3><p>Verify each candidate and authorization before performing recovery.</p></div><div className="actions"><button className="ghost" type="button" onClick={selectAll}>Select recoverable</button><button className="ghost" type="button" onClick={() => setSelected(new Set())}>Clear</button><button className="primary small" type="button" disabled={!selected.size || recovering || scan.status !== "completed"} onClick={recoverSelected}>{recovering ? "Recovering…" : `Recover ${selected.size}`}</button></div></div>
                      <div className="table-wrap"><table><thead><tr><th aria-label="Select"/><th>Inode</th><th>Name / path</th><th>Type</th><th>Size</th><th>Recovery</th><th>Validation</th><th>File</th></tr></thead><tbody>
                        {findings.map((f) => <tr key={f.id}><td><input aria-label={`Select inode ${f.inode}`} type="checkbox" checked={selected.has(f.id)} onChange={() => toggle(f.id)} disabled={!f.recoverable || f.recovery_status === "complete" || scan.status !== "completed"} /></td><td className="mono">{f.inode}</td><td><strong>{f.original_name || f.name || "Unnamed candidate"}</strong><small>{f.original_path || f.path || "Path not reconstructed"}</small></td><td>{f.file_signature || f.file_type || "Unknown"}</td><td>{Number(f.size_bytes || 0).toLocaleString()} B</td><td><Pill value={f.recovery_status || "candidate"} tone={tone(f.recovery_status)} /></td><td><Pill value={f.validation_status || "pending"} tone={tone(f.validation_status)} /></td><td>{f.recovered_path ? <a className="download" href={api.download(f.id)}>Download</a> : "—"}</td></tr>)}
                      </tbody></table></div>
                      {!findings.length && <div className="empty">No deleted inode candidates were found by this scan.</div>}
                    </section>
                    <div className="two-col result-two-col">
                      <section className="result-panel"><div className="section-head"><div><div className="kicker">INTEGRITY</div><h3>Evidence hash verification</h3></div><Pill value={scan.post_scan_sha256 ? (hashMatch ? "MATCH" : "CHANGED") : "PENDING"} tone={scan.post_scan_sha256 ? (hashMatch ? "good" : "bad") : "info"} /></div><div className="hash-box"><label>Pre-scan SHA-256</label><code>{scan.pre_scan_sha256 || "—"}</code></div><div className="hash-box"><label>Post-scan SHA-256</label><code>{scan.post_scan_sha256 || "Pending"}</code></div><div className="integrity-state">{integrity?.message || "Integrity ledger pending."}</div></section>
                      <section className="result-panel"><div className="section-head"><div><div className="kicker">NEXT STEP</div><h3>Generate the examination report</h3></div></div><p className="note">The report includes case intake, evidence handling details, methods, findings, timelines, limitations, and an examiner-reviewable narrative.</p><button type="button" className="primary" onClick={() => setActiveStep(4)} disabled={!final}>Continue to report →</button></section>
                    </div>
                  </>}
                </>
              )}
              <div className="wizard-actions"><button className="ghost" type="button" onClick={() => setActiveStep(2)}>← Scan settings</button>{final && <button className="primary" type="button" onClick={() => setActiveStep(4)}>Continue to report →</button>}</div>
            </>
          )}

          {activeStep === 4 && (
            <>
              {!final && <div className="empty"><strong>Report becomes available after scanning</strong><span>Finish a scan before exporting a report.</span><button className="ghost" type="button" onClick={() => setActiveStep(3)}>View findings</button></div>}
              {final && <>
                <div className="report-summary">
                  <div><div className="kicker">REPORT READY</div><h3>{form.caseNumber || scan.case_number || "Case"} · Examination report</h3><p>The DOCX report is structured for review; the JSON export preserves structured evidence and generated narrative fields.</p></div>
                  <Pill value={scan.status} tone={tone(scan.status)} />
                </div>
                <div className="ai-config-panel">
                  <div className="ai-icon">AI</div>
                  <div><strong>{aiStatus?.configured ? `Groq narrative enabled · ${aiStatus.model}` : "Groq narrative not configured"}</strong><p>{aiStatus?.message || "Configure GROQ_API_KEY in backend/.env. A labelled local fallback is used until it is configured."}</p></div>
                  <Pill value={aiStatus?.configured ? "CONFIGURED" : "LOCAL FALLBACK"} tone={aiStatus?.configured ? "good" : "info"} />
                </div>
                <div className="privacy-note"><strong>External processing notice</strong><span>When Groq is configured, the backend sends case metadata and structured examination summaries to Groq to draft narrative sections. It does not send the disk-image bytes or raw artifact-content bodies. Review your organization’s handling policy before enabling this feature.</span></div>
                <div className="report-downloads">
                  <a className="report-download primary-download" href={api.reportDocx(scan.id)}><span className="file-mark">DOCX</span><span><strong>Cyber forensic report</strong><small>Editable Word report · narrative + technical sections</small></span><span className="download-arrow">↓</span></a>
                  <a className="report-download" href={api.reportJson(scan.id)}><span className="file-mark json-mark">JSON</span><span><strong>Structured report data</strong><small>Case metadata, findings, timeline, hashes, and AI report fields</small></span><span className="download-arrow">↓</span></a>
                  <button className="report-download" type="button" disabled={refreshing} onClick={refreshArtifacts}><span className="file-mark refresh-mark">↻</span><span><strong>{refreshing ? "Refreshing artifacts…" : "Refresh artifacts and timeline"}</strong><small>Re-run targeted artifact extraction before exporting the latest report</small></span><span className="download-arrow">→</span></button>
                </div>
                <div className="report-checklist"><h3>Before signing or sharing</h3><div>✓ Confirm the case and evidence identifiers</div><div>✓ Verify the pre-scan and post-scan SHA-256 values</div><div>✓ Review findings, recovery validation, and timestamp sources</div><div>✓ Treat AI-written interpretations as drafts and confirm each statement against underlying evidence</div><div>✓ Add examiner approval, signature, and any required lab quality-assurance details</div></div>
                <div className="wizard-actions"><button className="ghost" type="button" onClick={() => setActiveStep(3)}>← Back to findings</button></div>
              </>}
            </>
          )}
        </section>
      </main>
      <footer>EXT4 Forensics Workbench v0.5 · Local casebook · Evidence image accessed read-only · AI narrative requires examiner review</footer>
    </div>
  );
}
