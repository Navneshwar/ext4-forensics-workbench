export default function StatusPill({ status }) {
  const key = String(status || "").toLowerCase();
  return <span className={`pill pill-${key}`}>{status || "unknown"}</span>;
}
