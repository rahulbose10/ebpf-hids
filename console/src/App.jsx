import { useState } from "react";

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
import TopBar from "./components/TopBar";

import "./styles/dashboard.css";
import "./styles/topbar.css";

function Phase2ShellView({ title }) {
  return (
    <main className="page-shell">
      <div className="panel">
        <div className="panel-eyebrow">SOC CONSOLE</div>

        <h1>{title}</h1>

        <p>
          {title} view is connected to the Person 5 navigation shell.
          The full analyst view will be built in its dedicated phase.
        </p>
      </div>
    </main>
  );
}


const NAV = [
  {
    id: "overview",
    label: "Overview",
    glyph: "◈",
    view: Overview,
  },
  {
    id: "detection",
    label: "Detection",
    glyph: "◉",
    view: Detection,
  },
  {
  id: "processes",
  label: "Processes",
  glyph: "⌘",
  view: Processes,
  },
  {
    id: "process-graph",
    label: "Process Graph",
    glyph: "⌘",
     view: ProcessGraph,
  },
  {
    id: "rules",
    label: "Rules",
    glyph: "◆",
    view: Rules,
  },
  {
    id: "incidents",
    label: "Incidents",
    glyph: "!",
    view: Incidents,
  },
  {
  id: "threat-intel",
  label: "Threat Intel",
  glyph: "◇",
  view: ThreatIntel,
},
  {
    id: "enforcement",
    label: "Enforcement",
    glyph: "⊙",
      view: Enforcement,
  },
  {
    id: "analytics",
    label: "Analytics",
    glyph: "▥",
    view: Analytics,
  },
  {
    id: "attack-map",
    label: "ATT&CK Map",
    glyph: "▦",
    view: AttackMap,
  },
  {
    id: "attack-range",
    label: "Attack Range",
    glyph: "△",
      view: AttackRange,
  },
  {
    id: "evaluation",
    label: "Evaluation",
    glyph: "▤",
      view: Evaluation,
  },
  {
    id: "settings",
    label: "Settings",
    glyph: "⚙",
      view: Settings,
  },
];


function App() {
  const [loggedIn, setLoggedIn] = useState(false);

  const [active, setActive] = useState("overview");


  if (!loggedIn) {
    return (
      <Login
        onLogin={() => setLoggedIn(true)}
      />
    );
  }


  const activeItem = NAV.find(
    (item) => item.id === active
  );


  const ActiveView = activeItem
    ? activeItem.view
    : Overview;


  return (
    <div className="dashboard">

      <Sidebar
        nav={NAV}
        active={active}
        setActive={setActive}
        onLogout={() => setLoggedIn(false)}
      />

      <div className="main-content">

        <TopBar />

        <ActiveView />

      </div>

    </div>
  );
}


export default App;