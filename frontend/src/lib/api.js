const BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000/api";

async function req(path, opt = {}) {
  const response = await fetch(BASE + path, {
    headers: { "Content-Type": "application/json", ...(opt.headers || {}) },
    ...opt,
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
  return body;
}

export const api = {
  resources: () => req("/system/resources"),
  aiStatus: () => req("/system/ai-status"),
  createScan: (payload) => req("/scans", { method: "POST", body: JSON.stringify(payload) }),
  scan: (id) => req(`/scans/${id}`),
  case: (id) => req(`/cases/${id}`),
  findings: (id) => req(`/scans/${id}/findings`),
  artifacts: (id) => req(`/scans/${id}/artifacts`),
  refreshArtifacts: (id) => req(`/scans/${id}/artifacts/refresh`, { method: "POST" }),
  integrity: (id) => req(`/cases/${id}/integrity`),
  recover: (id, ids) => req(`/scans/${id}/recover`, { method: "POST", body: JSON.stringify({ finding_ids: ids }) }),
  reportJson: (id) => `${BASE}/scans/${id}/report.json`,
  reportDocx: (id) => `${BASE}/scans/${id}/report.docx`,
  download: (id) => `${BASE}/findings/${id}/download`,
};
