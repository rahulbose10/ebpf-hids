import { useEffect, useState } from "react";

import { api } from "./api";

import Login from "./pages/Login";
import Overview from "./pages/Overview";
import Detection from "./pages/Detection";
import Processes from "./pages/Processes";
import ProcessGraph from "./pages/ProcessGraph";
import Rules from "./pages/Rules";
import Incidents from "./pages/Incidents";
import ThreatIntel from "./pages/ThreatIntel";
import Enforcement from "./pages/Enforcement";
import Analytics from "./pages/Analytics";
import AttackMap from "./pages/AttackMap";
import AttackRange from "./pages/AttackRange";
import Evaluation from "./pages/Evaluation";
import Settings from "./pages/Settings";

import Sidebar from "./components/Sidebar";
import TopBar from "./components/Topbar";

import "./styles/dashboard.css";
import "./styles/topbar.css";

const NAV = [
  { id: "overview", label: "Overview", glyph: "◈", view: Overview },
  { id: "detection", label: "Detection", glyph: "◉", view: Detection },
  { id: "processes", label: "Processes", glyph: "≡", view: Processes },
  { id: "process-graph", label: "Process Graph", glyph: "⌘", view: ProcessGraph },
  { id: "rules", label: "Rules", glyph: "◆", view: Rules },
  { id: "incidents", label: "Incidents", glyph: "!", view: Incidents },
  { id: "threat-intel", label: "Threat Intel", glyph: "◇", view: ThreatIntel },
  { id: "enforcement", label: "Enforcement", glyph: "⊙", view: Enforcement },
  { id: "analytics", label: "Analytics", glyph: "▥", view: Analytics },
  { id: "attack-map", label: "ATT&CK Map", glyph: "▦", view: AttackMap },
  { id: "attack-range", label: "Attack Range", glyph: "△", view: AttackRange },
  { id: "evaluation", label: "Evaluation", glyph: "▤", view: Evaluation, ml: true },
  { id: "settings", label: "Settings", glyph: "⚙", view: Settings },
];

function App() {
  const [session, setSession] = useState("checking");
  const [active, setActive] = useState("overview");

  useEffect(() => {
    let alive = true;
    api
      .me()
      .then(() => alive && setSession("in"))
      .catch(() => alive && setSession("out"));
    const onUnauth = () => setSession("out");
    window.addEventListener("hids:unauth", onUnauth);
    return () => {
      alive = false;
      window.removeEventListener("hids:unauth", onUnauth);
    };
  }, []);

  const logout = () => {
    api
      .logout()
      .catch(() => null)
      .finally(() => setSession("out"));
  };

  if (session === "checking") {
    return null;
  }

  if (session !== "in") {
    return <Login onLogin={() => setSession("in")} />;
  }

  const activeItem = NAV.find((item) => item.id === active);
  const ActiveView = activeItem ? activeItem.view : Overview;

  return (
    <div className="dashboard">
      <Sidebar
        nav={NAV}
        active={active}
        setActive={setActive}
        onLogout={logout}
      />

      <div className="main-content">
        <TopBar />
        <ActiveView />
      </div>
    </div>
  );
}

export default App;