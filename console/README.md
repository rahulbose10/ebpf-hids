# eBPF-HIDS console (L5)

The SOC console for the eBPF-HIDS project: a React single page app that reads the backend API and shows events, alerts, processes, rules and incidents. It does not decide anything. The server detects and responds, the console only shows what the server says.

## Credit

The console was built by Anit Chakraborty (React, Vite, Tailwind, Recharts, 13 views and a login page). Rahul Bose imported it into this repository, restyled it to a compact layout, wired the last views to the API and fixed places where it did not match the API contract or showed invented data as real. `git log -- console/` shows who wrote what.

## Run it

You need Node 20.19 or newer, or 22.12 or newer, because Vite 8 refuses older versions. The build and lint were run on Ubuntu with Node 22.23.4.

```
cd console
npm ci
npm run dev
```

Open http://localhost:5173. In dev mode Vite forwards every request that starts with /api to http://127.0.0.1:5000, so the backend has to listen on that address. Without a backend the top bar says "backend unreachable" and most pages show an error or an empty state. That is the intended behaviour.

For the demo there is no dev server. `npm run build` writes console/dist and the Flask server serves it at http://127.0.0.1:5000. dist is not in git, so build again on the machine after every pull, or Flask serves the old build.

Other commands:

```
npm run build     production build into dist/
npm run lint      eslint over the whole project
npm run preview   serve the built files
```

Use `npm ci`, not `npm install`. It installs exactly what package-lock.json says. Never copy node_modules between Windows and Linux.

## Login and roles

The login page posts to /api/login and the server sets a session cookie. On load the console asks /api/me who is signed in and with which role. Any 401 from the API sends you back to the login page. Sign out calls /api/logout.

Roles are viewer, analyst and admin. Buttons that need a higher role than yours are greyed out, but that is only so nobody clicks something that will fail. The server checks the role on every route and answers 403, and tests/test_endpoints.py calls every route as anonymous, viewer, analyst and admin.

## What each view reads

| View | Reads | Notes |
|-|-|-|
| Overview | /api/health, /api/events, /api/alerts, /api/anomaly | the event tape stops while the mouse is over it, click a row for the full detail |
| Detection | /api/health, /api/alerts, /api/anomaly | |
| Processes | /api/processes | |
| Process Graph | /api/processes, /api/alerts | |
| Analytics | /api/health, /api/alerts | counts the latest 300 alerts only, the server sends no more |
| Evaluation | /api/health, /api/anomaly, /api/evaluation | |
| Rules | /api/rules, POST /api/rules/&lt;id&gt;/toggle | if /api/rules fails, shows a copy of server/rules/*.yml with unknown state |
| ATT&CK Map | /api/mitre, /api/navigator/download | |
| Attack Range | POST /api/sim/&lt;name&gt; | the server only starts names on its whitelist |
| Incidents | /api/incidents, /api/incidents/&lt;id&gt;, /api/reports/* | |
| Threat Intel | /api/iocs | |
| Enforcement | /api/enforcement, /api/enforcement/action, /api/enforcement/clear | |
| Settings | /api/users, /api/apikeys, /api/alerting | |

Enforcement and alerting settings live in the server's memory and last until it restarts.

## Things to know

Two clocks. Events, alerts, incidents and anomaly rows carry the sensor's `ts`, kernel time in seconds since boot, and the console shows it with formatKts without ever turning it into a wall-clock time. Enforcement decisions, IOCs, users, API keys and alert deliveries are stamped by the server with wall-clock time and shown with formatWallTime. The top bar clock is the browser's clock.

The Rules cards take their on and where lines from a copy of the rule files inside Rules.jsx, because /api/rules does not send conditions. The copy was generated from server/rules/*.yml at main 50d91d3, and no rule file has changed since. If one changes, the copy is out of date until it is regenerated.

The three-state ML light reads ml_alerting, not ml_ready. Loaded but not allowed to alert shows as "gauge only".

The Detection gauge is the autoencoder reconstruction error of the latest scored row divided by ae_threshold. The bar runs from 0 to twice the threshold and turns red only when the autoencoder flagged that row. A row can also be flagged by the isolation forest or by the feature limits, so the two cards under the bar say which check fired. The second card keeps the newest flagged row seen since the page opened, because /api/anomaly only returns the last 300 scores and on a busy host a flagged row leaves that window within seconds.

The "Raised on the VM" lists on Attack Range are fixed text, measured by clicking each button once on 2026-11-03 with ML alerting off. The page does not ask the server what fired.

## Checked

On the Ubuntu VM at 2cd5f7f: `npm run lint` clean, `npm run build` 988 ms, `python3 -m pytest` 325 passed.

Live with the sensor on 2026-11-03: every Attack Range button raised the rules listed on that page and Benign exec chain raised none, the Enforcement page refused to act on the server's own pid (guard_blocked, "guard: that is the responder itself"), and the layer from Download layer JSON opened on mitre-attack.github.io with the alerted techniques coloured.

## What is not done

- There are no tests for the React code. Lint and build are the only checks. tests/test_simulation_scripts.py covers the simulation scripts behind Attack Range.
- A row flagged by the isolation forest alone has not been seen on the Detection page live, only autoencoder flags.
- Only the test alert was watched arriving at a webhook from this side. A real alert delivered by webhook was seen in L4's own run.
- The replay fallback in docs/DEMO_SCRIPT.md has not been run on the VM yet.
- `npm audit` reports 12 vulnerabilities (7 moderate, 5 high), all in build and dev tools. `npm audit --omit=dev`, which checks only what ships to the browser, reports 0. Measured on the VM on 2026-11-03, not fixed.

## Layout

```
src/App.jsx          shell, sidebar, view switch
src/api.jsx          fetch helper, api object, usePoll
src/format.js        formatKts, formatWallTime, formatEvent
src/components/      Sidebar, Topbar, StatCard, SeverityChip, SeverityChart, GaugeBar, Panel
src/pages/           one file per view, plus Login
src/styles/          css for the shell, cards, sidebar, top bar, login
```

usePoll(fn, ms) calls fn at once, then every ms milliseconds, and returns `{data, error, refresh}`. Polling is used instead of websockets because the data is a few JSON documents every few seconds.
