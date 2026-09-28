export default function ProgressBar({ value }) {
  const clamped = Math.max(0, Math.min(100, Number(value || 0)));
  return (
    <div className="progress-shell" aria-label={`Progress ${clamped.toFixed(1)}%`}>
      <div className="progress-fill" style={{ width: `${clamped}%` }} />
    </div>
  );
}
