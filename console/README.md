# eBPF-HIDS console (L5)

The SOC console for the eBPF-HIDS project: a React single page app that reads the backend API and shows events, alerts, processes, rules and incidents. It does not decide anything. The server detects and responds, the console only shows what the server says.

## Credit

The console was built by Anit Chakraborty (React, Vite, Tailwind, Recharts, 13 views and a login page). Rahul Bose imported it into this repository, restyled it to a compact layout, and fixed places where it did not match the API contract or showed invented data as real. `git log -- console/` shows who wrote what.

## Run it

You need Node 20.19 or newer, or 22.12 or newer, because Vite 8 refuses older versions. The build and lint were run on Ubuntu with Node 22.23.4.

```
cd console
npm ci
npm run dev
```

Open http://localhost:5173. In dev mode Vite forwards every request that starts with /api to http://127.0.0.1:5000, so the backend has to listen on that address. Without a backend the top bar says "backend unreachable" and most pages show an error or an empty state. That is the intended behaviour.

Other commands:

```
npm run build     production build into dist/
npm run lint      eslint over the whole project
npm run preview   serve the built files
```

Use `npm ci`, not `npm install`. It installs exactly what package-lock.json says. Never copy node_modules between Windows and Linux.

## Login

The login page accepts any input. It does not call /api/login yet. Do not treat it as a security control.

## What each view reads

| View | Reads | State |
|-|-|-|
| Overview | /api/health, /api/events, /api/alerts, /api/anomaly | live |
| Detection | /api/health, /api/alerts, /api/anomaly | live |
| Processes | /api/processes | live |
| Process Graph | /api/processes, /api/alerts | live |
| Analytics | /api/health, /api/alerts | live, counts the latest 300 alerts only |
| Evaluation | /api/health, /api/alerts, /api/anomaly | live |
| Rules | /api/rules | live; if it fails, shows a copy of server/rules/*.yml with unknown state |
| ATT&CK Map | /api/mitre | shape not in the contract, see below |
| Attack Range | POST /api/sim/&lt;id&gt; | ids not checked against the server whitelist |
| Incidents | mock.js | demo data, not the API |
| Threat Intel | mock.js | browser only, nothing is sent |
| Enforcement | none | browser only, audit log empty |
| Settings | none | browser only |

Pages that only keep state in the browser say so in an amber bar at the top.

## Things to know

The sensor timestamp `ts` is kernel time in seconds since boot. The console shows it as it is and never turns it into a wall-clock time. The top bar clock is the browser's clock.

The Rules cards take their on and where lines from a copy of the rule files inside Rules.jsx, because /api/rules does not send conditions. The copy is generated from server/rules/*.yml at main 1f3506c. If a rule file changes, the copy is out of date until it is regenerated.

The three-state ML light reads ml_alerting, not ml_ready. Loaded but not allowed to alert shows as "gauge only".

## What is not done

- Incidents lists mock incidents, but its status buttons call the real POST /api/incidents/&lt;id&gt;/status. Against a real backend the ids will not match.
- Threat Intel, Enforcement and Settings need /api/iocs, /api/enforcement, /api/users, /api/apikeys and /api/alerting, which are not wired.
- /api/mitre has no agreed response shape. The ATT&CK Map page accepts several guesses.
- Attack Range sends ids like reverse-shell. The server accepts only names on its own whitelist, and the simulation scripts are not written.
- Login does not check anything, and a 401 from the API is not handled.
- There are no tests.
- Never run against the real L4 backend or the live sensor. Everything was checked against a small stub backend and made-up test responses in the contract shape.
- npm audit reports 6 findings, all in build and dev tools. `npm audit --omit=dev` reports none.

## Layout

```
src/App.jsx          shell, sidebar, view switch
src/api.jsx          fetch helper, api object, usePoll
src/format.js        formatKts, kernel time formatting
src/components/      Sidebar, Topbar, StatCard, SeverityChip, GaugeBar, Panel
src/pages/           one file per view
src/styles/          css for the shell, cards, sidebar, top bar, login
src/mock.js          demo data for Incidents and Threat Intel
```

usePoll(fn, ms) calls fn at once, then every ms milliseconds, and returns `{data, error, refresh}`. Polling is used instead of websockets because the data is a few JSON documents every few seconds.
