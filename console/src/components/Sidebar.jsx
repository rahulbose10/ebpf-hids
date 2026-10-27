import "../styles/sidebar.css";

function Sidebar({ nav, active, setActive, onLogout }) {
  return (
    <div className="sidebar">

      <div className="logo">
        <h3>🛡 eBPF-HIDS</h3>
        <p>HOST INTRUSION SENSOR</p>
      </div>

      <nav className="menu sidebar-nav">

        {nav.map((item) => (
          <button
            key={item.id}
            className={`menu-item ${active === item.id ? "active" : ""}`}
            onClick={() => setActive(item.id)}
          >
            <span className="menu-icon">
              {item.glyph}
            </span>

            <span className="menu-label">
              {item.label}
            </span>
          </button>
        ))}

      </nav>

      <div className="sidebar-footer">

        <button
          className="logout-btn"
          onClick={onLogout}
        >
          ⏻ Logout
        </button>

      </div>

    </div>
  );
}

export default Sidebar;