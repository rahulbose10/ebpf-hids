import { useState } from "react";
import { api } from "../api";
import "../styles/login.css";

function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      await api.login(username, password);
      onLogin();
    } catch (err) {
      setError(err?.unauth ? "Invalid username or password" : err?.error || "Backend unreachable");
      setBusy(false);
    }
  };

  return (
    <div className="login-container">

      <form className="login-card" onSubmit={submit}>

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
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>

        <div className="input-group">
          <span className="icon">🔒</span>

          <input
            type="password"
            placeholder="Password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        {error && <div className="login-error" role="alert">{error}</div>}

        <button type="submit" disabled={busy || !username || !password}>
                  {busy ? "Signing in" : "Sign In"}
        </button>

      </form>

    </div>
  );
}

export default Login;
