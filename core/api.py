"""
api.py — Minimal FastAPI backend for the agent.

Only 3 endpoints:
  POST /session/new            → create a session
  POST /session/{id}/message   → send message, get response + intel
  GET  /health                 → confirm the agent is running

MongoDB is optional (see core/database.py + USE_DB in .env).
With USE_DB=false (the default), everything runs in-memory and
intel logs are written to data/intel_logs/ as JSON.

Run:
    python api.py
    # → http://localhost:8000/docs  (auto-generated interactive docs)
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core.session_manager import registry, _USE_DB

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ── Startup / shutdown ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    if _USE_DB:
        from core.database import db
        try:
            await db.connect()
            logger.info("MongoDB connected.")
        except Exception as e:
            logger.warning(f"MongoDB unavailable ({e}) — running in-memory only.")
    yield
    if _USE_DB:
        try:
            from core.database import db
            await db.disconnect()
        except Exception:
            pass


app = FastAPI(
    title="Agentic Honeypot",
    description="AI-powered scambaiting agent — AI Builder phase",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request schema ────────────────────────────────────────────────────────────

class MessageRequest(BaseModel):
    message: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    """Confirm the agent is running and show active session count."""
    return {
        "status": "online",
        "active_sessions": registry.active_count(),
        "db_enabled": _USE_DB,
    }


@app.post("/session/new")
async def new_session():
    """Create a new honeypot session. Returns the session_id."""
    session = await registry.create_session()
    return {
        "session_id": session.session_id,
        "message": f"Session {session.session_id} ready.",
    }


@app.post("/session/{session_id}/message")
async def send_message(session_id: str, body: MessageRequest):
    """
    Feed one scammer message to the honeypot.

    Returns bot response + scam classification + harvested intel.
    Call this repeatedly with the same session_id for a multi-turn conversation.
    """
    if not body.message or not body.message.strip():
        raise HTTPException(status_code=422, detail="message cannot be empty.")

    session = await registry.get_or_create(session_id)

    if not session.is_active:
        raise HTTPException(
            status_code=410,
            detail=f"Session {session_id} is closed. Create a new one.",
        )

    result = await session.process_message(body.message)

    if "error" in result:
        # LLM failure → 503 so the caller knows to retry
        if "hint" in result:
            raise HTTPException(status_code=503, detail=result)
        raise HTTPException(status_code=500, detail=result["error"])

    return result


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)