
import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import Pill from "../components/Pill";
import Progress from "../components/Progress";
import Metric from "../components/Metric";

const savedPath = localStorage.getItem("lastEvidencePath") || "";
const savedScan = localStorage.getItem("lastScanId") || "";

function tone(value) {
  const v = String(value || "").toLowerCase();
  if (["completed", "complete", "high", "size_match", "recovered", "match"].includes(v)) return "good";
  if (["running", "candidate", "medium", "partial", "pending"].includes(v)) return "info";
  if (["failed", "integrity_changed", "low", "not_recoverable", "recovery_failed", "changed"].includes(v)) return "bad";
  return "neutral";
}

export default function Dashboard() {
  const [form, setForm] = useState({
    caseName: "EXT4 recovery case",
    imagePath: savedPath,
  });
  const [workers, setWorkers] = useState({ io: 1, hash: 2 });
  const [scanId, setScanId] = useState(savedScan);
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [resources, setResources] = useState(null);
  const [integrity, setIntegrity] = useState(null);
  const [selected, setSelected] = useState(new Set());
  const [busy, setBusy] = useState(false);
  const [recovering, setRecovering] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  useEffect(() => {
    let cancelled = false;
    let timer;

    async function pollResources() {
      try {
        const data = await api.resources();
        if (!cancelled) setResources(data);
      } catch {
        // Backend may be temporarily unavailable while the UI starts.
      }
      timer = window.setTimeout(pollResources, 2000);
    }

    pollResources();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
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
        } catch {
          // Keep scan page usable even if integrity endpoint is temporarily unavailable.
        }

        if (!["completed", "failed", "integrity_changed"].includes(current.status)) {
          timer = window.setTimeout(pollScan, 1500);
        }
      } catch (e) {
        if (!cancelled) setError(e.message);
        timer = window.setTimeout(pollScan, 1800);
      }
    }

    pollScan();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [scanId]);

  const recoverable = useMemo(
    () => findings.filter((item) => Boolean(item.recoverable) && item.file_type === "regular"),
    [findings]
  );

  function selectAll() {
    setSelected(new Set(recoverable.map((item) => item.id)));
  }

  async function startScan(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setMessage("");
    setSelected(new Set());

    try {
      const result = await api.createScan({
        image_path: form.imagePath,
        case_name: form.caseName,
        io_workers: workers.io,
        hash_workers: workers.hash,
        resource_policy: "laptop",
      });

      localStorage.setItem("lastEvidencePath", form.imagePath);
      localStorage.setItem("lastScanId", result.scan_id);
      setScanId(result.scan_id);
      setScan(null);
      setFindings([]);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  function toggle(id) {
    setSelected((old) => {
      const next = new Set(old);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function recoverSelected() {
    if (!selected.size) return;

    setRecovering(true);
    setMessage("");
    try {
      const result = await api.recover(scanId, [...selected]);
      const ok = result.results.filter((item) => item.status === "recovered").length;
      const partial = result.results.filter((item) => item.recovery_status === "partial").length;
      setMessage(`${ok} file(s) processed. ${partial} partial result(s).`);
      setFindings(await api.findings(scanId));
      if (scan?.case_id) setIntegrity(await api.integrity(scan.case_id));
    } catch (e) {
      setMessage(e.message);
    } finally {
      setRecovering(false);
    }
  }

  const final = scan && ["completed", "failed", "integrity_changed"].includes(scan.status);
  const hashMatch =
    Boolean(scan?.post_scan_sha256) &&
    scan.pre_scan_sha256 === scan.post_scan_sha256;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark">✓</div>
          <div>
            <div className="brand-title">EXT4 FORENSICS</div>
            <div className="brand-subtitle">Deleted File Recovery Workbench</div>
          </div>
        </div>
        <div className="topbar-status">
          <span className="online-dot" />
          Local analysis · Windows
        </div>
      </header>

      <main className="content">
        <section className="hero">
          <div>
            <div className="eyebrow">CYBER FORENSICS CAPSTONE · LAB #02</div>
            <h1>Recover. Correlate. Validate.</h1>
            <p>
              Analyze EXT4 metadata, recover deleted content, preserve evidence
              integrity, and export a forensic report.
            </p>
          </div>
          <div className="hero-symbol">EXT4</div>
        </section>

        <section className="two-col">
          <section className="panel">
            <div className="section-head">
              <div>
                <div className="kicker">01 · EVIDENCE</div>
                <h2>Start a forensic analysis</h2>
              </div>
              <Pill value="READ-ONLY" tone="good" />
            </div>

            <div className="safety">
              <strong>Evidence protection</strong>
              <span>The original image is not modified. Recovered files and reports are stored separately.</span>
            </div>

            <form className="form" onSubmit={startScan}>
              <label>
                Case name
                <input
                  value={form.caseName}
                  onChange={(e) => setForm({ ...form, caseName: e.target.value })}
                />
              </label>

              <label>
                RAW image path
                <input
                  required
                  value={form.imagePath}
                  onChange={(e) => setForm({ ...form, imagePath: e.target.value })}
                  placeholder={"C:\\Forensics\\synapse-lab-01.raw"}
                />
                <small>Quoted Windows paths are accepted.</small>
              </label>

              <button className="primary" disabled={busy}>
                {busy ? "Starting…" : "Hash & start scan"}
              </button>
            </form>

            {error && <div className="alert bad">{error}</div>}
          </section>

          <section className="panel">
            <div className="section-head">
              <div>
                <div className="kicker">02 · RESOURCES</div>
                <h2>Laptop-safe controls</h2>
              </div>
            </div>

            <div className="mode-row">
              <button className="mode active" onClick={() => setWorkers({ io: 1, hash: 2 })}>
                Laptop
              </button>
              <button className="mode" onClick={() => setWorkers({ io: 2, hash: 2 })}>
                Balanced
              </button>
            </div>

            <div className="workers">
              <label>
                I/O workers
                <input
                  type="number"
                  min="1"
                  max="4"
                  value={workers.io}
                  onChange={(e) => setWorkers({ ...workers, io: Math.max(1, Math.min(4, Number(e.target.value) || 1)) })}
                />
              </label>
              <label>
                Hash workers
                <input
                  type="number"
                  min="1"
                  max="4"
                  value={workers.hash}
                  onChange={(e) => setWorkers({ ...workers, hash: Math.max(1, Math.min(4, Number(e.target.value) || 1)) })}
                />
              </label>
            </div>

            <div className="resource-box">
              <div className="resource-line">
                <span>CPU</span>
                <Progress value={resources?.cpu_percent} />
              </div>
              <div className="resource-line">
                <span>RAM</span>
                <Progress value={resources?.ram_percent} />
              </div>
              <div className="recommend">
                Recommended now: I/O {resources?.recommended_io_workers ?? "—"} · Hash {resources?.recommended_hash_workers ?? "—"}
              </div>
            </div>
          </section>
        </section>

        {scan && (
          <>
            <section className="metric-grid">
              <Metric label="Status" value={<Pill value={scan.status} tone={tone(scan.status)} />} hint={scan.stage} />
              <Metric label="Progress" value={`${Number(scan.progress).toFixed(1)}%`} hint={scan.message} />
              <Metric label="Evidence" value={`${(Number(scan.size_bytes || 0) / 1024 / 1024).toFixed(1)} MB`} hint={`${scan.io_workers} I/O · ${scan.hash_workers} hash`} />
              <Metric label="Deleted candidates" value={findings.length} hint={`${recoverable.length} regular files`} />
            </section>

            <section className="panel">
              <div className="section-head">
                <div>
                  <div className="kicker">03 · ANALYSIS</div>
                  <h2>Pipeline</h2>
                </div>
                <span className="mono">{scan.stage}</span>
              </div>

              <Progress value={scan.progress} />

              <div className="pipeline">
                {["hash_pre", "inode_scan", "directory_scan", "journal", "artifacts", "findings", "hash_post", "complete"].map((stage) => (
                  <div key={stage} className={`pipeline-step ${scan.stage === stage ? "active" : ""}`}>
                    <span className="dot" />
                    {stage.replaceAll("_", " ")}
                  </div>
                ))}
              </div>

              <div className="status-message">{scan.message || "Waiting…"}</div>
            </section>

            {final && (
              <section className="panel">
                <div className="section-head">
                  <div>
                    <div className="kicker">04 · RECOVERY</div>
                    <h2>Deleted files</h2>
                    <p>Recovered names and paths are conservative evidence-derived values.</p>
                  </div>

                  <div className="actions">
                    <button className="ghost" onClick={selectAll}>Select recoverable</button>
                    <button className="ghost" onClick={() => setSelected(new Set())}>Clear</button>
                    <button
                      className="primary small"
                      disabled={!selected.size || recovering || scan.status !== "completed"}
                      onClick={recoverSelected}
                    >
                      {recovering ? "Recovering…" : `Recover ${selected.size}`}
                    </button>
                  </div>
                </div>

                {message && <div className="alert good">{message}</div>}

                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th />
                        <th>Inode</th>
                        <th>Name / path</th>
                        <th>Type</th>
                        <th>Size</th>
                        <th>Recovery</th>
                        <th>Validation</th>
                        <th />
                      </tr>
                    </thead>
                    <tbody>
                      {findings.map((f) => (
                        <tr key={f.id}>
                          <td>
                            <input
                              type="checkbox"
                              checked={selected.has(f.id)}
                              onChange={() => toggle(f.id)}
                              disabled={!f.recoverable || f.recovery_status === "complete"}
                            />
                          </td>
                          <td className="mono">{f.inode}</td>
                          <td>
                            <strong>{f.original_name || f.name}</strong>
                            <small>{f.original_path || "Path not reconstructed"}</small>
                          </td>
                          <td>{f.file_signature || f.file_type}</td>
                          <td>{Number(f.size_bytes || 0).toLocaleString()} B</td>
                          <td><Pill value={f.recovery_status || "candidate"} tone={tone(f.recovery_status)} /></td>
                          <td><Pill value={f.validation_status || "pending"} tone={tone(f.validation_status)} /></td>
                          <td>
                            {f.recovered_path ? (
                              <a className="download" href={api.download(f.id)}>Download</a>
                            ) : "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {!findings.length && <div className="empty">No deleted inode candidates were found.</div>}
              </section>
            )}

            <section className="two-col">
              <section className="panel">
                <div className="section-head">
                  <div>
                    <div className="kicker">05 · INTEGRITY</div>
                    <h2>Evidence hashes</h2>
                  </div>
                </div>

                <div className="hash-box">
                  <label>Pre-scan SHA-256</label>
                  <code>{scan.pre_scan_sha256 || "—"}</code>
                </div>
                <div className="hash-box">
                  <label>Post-scan SHA-256</label>
                  <code>{scan.post_scan_sha256 || "Pending"}</code>
                </div>

                <div className="integrity-state">
                  <Pill
                    value={scan.post_scan_sha256 ? (hashMatch ? "MATCH" : "CHANGED") : "PENDING"}
                    tone={scan.post_scan_sha256 ? (hashMatch ? "good" : "bad") : "info"}
                  />
                  <span>{integrity?.message || "Integrity ledger pending."}</span>
                </div>
              </section>

              <section className="panel">
                <div className="section-head">
                  <div>
                    <div className="kicker">06 · REPORT</div>
                    <h2>Export Lab #02 report</h2>
                  </div>
                </div>

                <div className="reports">
                  <button
                    className="report"
                    disabled={refreshing}
                    onClick={async () => {
                      setRefreshing(true);
                      setMessage("");
                      try {
                        await api.refreshArtifacts(scan.id);
                        setMessage("Live artifacts and timeline refreshed. Generate the reports again.");
                      } catch (e) {
                        setMessage(e.message);
                      } finally {
                        setRefreshing(false);
                      }
                    }}
                  >
                    {refreshing ? "Refreshing live artifacts…" : "Refresh live artifacts / timeline"}
                  </button>
                  <a className="report" href={api.reportJson(scan.id)}>JSON report</a>
                  <a className="report" href={api.reportDocx(scan.id)}>DOCX report</a>
                </div>

                <p className="note">
                  The report contains integrity, filesystem findings, deleted files,
                  timeline/live-artifact sections, Lab #02 deliverables, metadata-vs-carving,
                  facts vs hypotheses, limitations and conclusion.
                </p>
              </section>
            </section>
          </>
        )}
      </main>

      <footer>
        EXT4 Forensics Workbench v0.3.1 · Local-first · Evidence image remains read-only
      </footer>
    </div>
  );
}
