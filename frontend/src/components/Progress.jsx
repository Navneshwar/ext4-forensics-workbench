export default function Progress({ value }) {
  const p = Math.max(0, Math.min(100, Number(value || 0)));
  return (
    <div className="progress-row">
      <div
        className="progress-track"
        role="progressbar"
        aria-valuenow={p}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`Progress ${p.toFixed(1)}%`}
      >
        <div className="progress-fill" style={{ width: `${p}%` }} />
      </div>
      <span>{p.toFixed(1)}%</span>
    </div>
  );
}