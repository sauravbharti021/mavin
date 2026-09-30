"""MARIS backend API (FastAPI).

Endpoints:
    GET  /api/health
    GET  /api/incidents?vessel_id=OCEAN07
    GET  /api/incidents/{incident_id}
    POST /api/investigate     body: {"incident_id": "INC-1047"} or full incident object
    POST /api/login           body: {"vessel_id": "OCEAN07", "password": "MARIS07"}

Also serves the static frontend at /.
No database -- incidents load from data/incidents.json.
"""

import json
import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agent import investigate

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_FILE = os.path.join(BASE_DIR, "data", "incidents.json")
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

# Demo-only hardcoded credentials (hackathon prototype).
CREDENTIALS = {
    "OCEAN07": "MARIS07",
    "OCEAN12": "MARIS12",
    "OCEAN21": "MARIS21",
}

app = FastAPI(title="MARIS -- Maritime AI Security Response", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def load_incidents():
    with open(DATA_FILE, "r") as f:
        return json.load(f)["incidents"]


def find_incident(incident_id):
    for inc in load_incidents():
        if inc["incident_id"] == incident_id:
            return inc
    return None


class LoginRequest(BaseModel):
    vessel_id: str
    password: str


class InvestigateRequest(BaseModel):
    incident_id: str | None = None
    vessel_id: str | None = None
    incident: dict | None = None


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "MARIS", "incidents_loaded": len(load_incidents())}


@app.post("/api/login")
def login(req: LoginRequest):
    vid = req.vessel_id.replace("-", "").upper()
    if CREDENTIALS.get(vid) == req.password:
        return {"authenticated": True, "vessel_id": vid}
    raise HTTPException(status_code=401, detail="Invalid Vessel ID or Password.")


@app.get("/api/incidents")
def incidents(vessel_id: str | None = None):
    data = load_incidents()
    if vessel_id:
        vid = vessel_id.replace("-", "").upper()
        data = [i for i in data if i["vessel_id"] == vid]
    return {"count": len(data), "incidents": data}


@app.get("/api/incidents/{incident_id}")
def incident_by_id(incident_id: str):
    inc = find_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


@app.post("/api/investigate")
def run_investigation(req: InvestigateRequest):
    incident = req.incident
    if incident is None:
        if not req.incident_id:
            raise HTTPException(status_code=400, detail="Provide incident_id or incident object")
        incident = find_incident(req.incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

    result = investigate(incident)
    return {
        "incident": incident,
        "investigation_status": result["status"],
        "tool_results": result["tool_results"],
        "evidence": result["evidence"],
        "correlated_findings": result["correlated_findings"],
        "reasoning": result["reasoning"],
        "risk_level": result["risk_level"],
        "risk_score": result["risk_score"],
        "explanation": result["summary"],
        "recommended_action": result["recommended_action"],
    }


# Serve the frontend last so /api/* routes take precedence.
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
