import "../styles/login.css";

function Login({ onLogin }) {
  return (
    <div className="login-container">

      <div className="login-card">

        <div className="logo">
          🛡️
        </div>

        <h1>eBPF-HIDS</h1>

        <div className="console-tagline">
            <span>HOST INTRUSION SENSOR</span>
            <span className="divider">•</span>
            <span>SOC CONSOLE</span>
                </div>

        <div className="input-group">
          <span className="icon">👤</span>

          <input
            type="text"
            placeholder="Username"
          />
        </div>

        <div className="input-group">
          <span className="icon">🔒</span>

          <input
            type="password"
            placeholder="Password"
          />
        </div>

        <button onClick={onLogin}>
                  Sign In
        </button>

      </div>

    </div>
  );
}

export default Login;