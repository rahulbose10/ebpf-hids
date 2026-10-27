import "../styles/cards.css";
function StatCard({ label, value, sub }) {
  return (
    <div className="stat-card">
      <div className="stat-header">
        <span className="eyebrow">{label}</span>
      </div>

      <div className="stat-value">
        {value}
      </div>

      {sub && (
        <div className="stat-sub">
          {sub}
        </div>
      )}
    </div>
  );
}

export default StatCard;