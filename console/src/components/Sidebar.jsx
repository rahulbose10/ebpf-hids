import "../styles/sidebar.css";

function Sidebar({ nav, active, setActive, onLogout }) {
  return (
    <aside className="side">
      <div className="side-brand">
        <div className="side-name">eBPF-HIDS</div>
        <div className="side-tag">Host intrusion sensor</div>
      </div>

      <nav className="side-nav">
        {nav.map((item) => {
          const isActive = active === item.id;
          const tone = item.ml ? "ml" : "signal";

          return (
            <button
              key={item.id}
              type="button"
              className={`side-item ${isActive ? `active ${tone}` : ""}`}
              onClick={() => setActive(item.id)}
              aria-current={isActive ? "page" : undefined}
            >
              <span className="side-glyph" aria-hidden="true">
                {item.glyph}
              </span>
              <span className="side-label">{item.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="side-foot">
        <button
          type="button"
          className="side-item side-logout"
          onClick={onLogout}
        >
          <span className="side-glyph" aria-hidden="true">
            ⏻
          </span>
          <span className="side-label">Log out</span>
        </button>
      </div>
    </aside>
  );
}

export default Sidebar;