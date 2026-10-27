import "../styles/cards.css";

function StatCard({ label, value, sub, tone }) {
  return (
    <div className="stat-card">
      <span className="eyebrow">{label}</span>

      <div className={`stat-value ${tone ? `tone-${tone}` : ""}`}>{value}</div>

      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

export default StatCard;
