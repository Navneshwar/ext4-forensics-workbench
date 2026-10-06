export default function Pill({ value, tone = "neutral" }) {
  return <span className={`pill pill-${tone}`}>{value || "—"}</span>;
}