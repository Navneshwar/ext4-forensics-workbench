export default function Metric({ label, value, hint }) {
  return (
    <div className="metric">
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      {hint != null && <div className="metric-hint">{hint}</div>}
    </div>
  );
}