import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import agents
import graph_algos

from trace_agents import correlate, run_agents, evaluate, device_reaches_critical

# Credentials come from the project-root .env first, then backend/.env.
HERE = Path(__file__).resolve().parent
load_dotenv(HERE.parent / ".env")
load_dotenv(HERE / ".env")

app = FastAPI(title="TRACE Graph API", version="1.1.0")

# Include the deployed Vercel origin and local development origins.
# Additional origins can be supplied in Render as a comma-separated CORS_ORIGINS value.
_default_origins = [
    "https://frontend-na92m3b04-unknowns-projects-5f81c6b2.vercel.app",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]
_env_origins = [
    origin.strip().rstrip("/")
    for origin in os.getenv("CORS_ORIGINS", "").split(",")
    if origin.strip()
]
_allowed_origins = list(dict.fromkeys(_default_origins + _env_origins))

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Every label has its own primary key. Using one shared list of keys made
# Evidence/Memory/Task/Action nodes collide with Alert/Incident ids.
ID_KEY = {"User": "user_id", "Device": "device_id", "Service": "service_id",
          "Alert": "alert_id", "Incident": "incident_id", "Evidence": "evidence_id",
          "Memory": "memory_id", "Task": "task_id", "Action": "action_id"}


@lru_cache(maxsize=1)
def _graph():
    from falkordb import FalkorDB
    kwargs = {}
    if os.getenv("FALKOR_USER"):
        kwargs["username"] = os.getenv("FALKOR_USER")
    if os.getenv("FALKOR_PASS"):
        kwargs["password"] = os.getenv("FALKOR_PASS")
    db = FalkorDB(host=os.getenv("FALKOR_HOST", "localhost"),
                  port=int(os.getenv("FALKOR_PORT", "6379")),
                  socket_connect_timeout=10, socket_timeout=30, **kwargs)
    return db.select_graph(os.getenv("FALKOR_GRAPH", "trace"))


def graph():
    try:
        return _graph()
    except Exception as e:
        _graph.cache_clear()
        raise HTTPException(503, f"Could not connect to FalkorDB: {e}")


def run(q: str, params: dict | None = None):
    try:
        return graph().query(q, params=params or {}).result_set
    except HTTPException:
        raise
    except Exception as e:
        _graph.cache_clear()  # reconnect next time
        raise HTTPException(500, f"Graph query failed: {e}")


def plain(v: Any):
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    if isinstance(v, dict):
        return {str(k): plain(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [plain(x) for x in v]
    if hasattr(v, "properties"):
        return plain(v.properties)
    return str(v)


def nid(label: str, props: dict) -> str:
