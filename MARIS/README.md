# MARIS — Maritime AI Security Response

Hackathon prototype. A simulated maritime cyber incident is investigated by an
agentic workflow (PLAN → TOOL → OBSERVE → CORRELATE → ASSESS) that correlates
evidence and produces an explainable risk assessment. Simulated data only — no
real ships, networks, or credentials.

## Stack
Plain HTML/CSS/JS frontend + FastAPI (Python) backend. No database, no build
step. The backend serves the frontend, so it runs as one process.

## Folder structure
```
MARIS/
├── frontend/         index.html, style.css, app.js  (login + dashboard)
├── backend/          app.py                          (FastAPI API + static serving)
├── agent/            maris_agent.py, risk_assessment.py
├── tools/            log_analyzer, device_checker, network_analyzer, threat_analyzer
├── data/             incidents.json                  (simulated incidents)
├── requirements.txt
└── README.md
```

## Install
```
cd MARIS
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Run
```
cd MARIS
uvicorn backend.app:app --reload --port 8000
```
Open http://127.0.0.1:8000

## Demo credentials
| Vessel   | Password |
|----------|----------|
| OCEAN07  | MARIS07  |
| OCEAN12  | MARIS12  |
| OCEAN21  | MARIS21  |

## Demo sequence
1. Login as `OCEAN07` / `MARIS07`.
2. Dashboard shows OCEAN-07's incidents.
3. Select **INC-1047** (Unknown Device).
4. Click **RUN INVESTIGATION**.
5. Watch tools complete → evidence correlate → **HIGH RISK** + recommended action.
6. Logout → login as `OCEAN12` / `MARIS12` → see OCEAN-12's incidents.

## API
| Method | Path | Notes |
|--------|------|-------|
| GET  | `/api/health` | service status |
| GET  | `/api/incidents?vessel_id=OCEAN07` | list incidents for a vessel |
| GET  | `/api/incidents/{incident_id}` | single incident |
| POST | `/api/investigate` | body `{"incident_id":"INC-1047"}` → full result |
| POST | `/api/login` | body `{"vessel_id":"OCEAN07","password":"MARIS07"}` |

Vessel IDs are normalized (`OCEAN-07` and `OCEAN07` both work).
