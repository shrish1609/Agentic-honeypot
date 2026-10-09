"""
core/session_manager.py

Manages multi-turn honeypot conversations.

MongoDB is OPTIONAL — set USE_DB=false in .env (or just don't set MONGODB_URI)
and the session manager runs purely in-memory, writing intel logs to
data/intel_logs/ as JSON files instead.

This means the agent works with only API keys — no MongoDB required
for the AI Builder phase demo.
"""

import os
import json
import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path

from langchain_core.messages import HumanMessage

from core.graph import honeypot_graph
from core.state import HoneypotState, ExtractedIntel

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────

_USE_DB  = os.getenv("USE_DB", "true").lower() == "true"
_LOG_DIR = Path("data/intel_logs")
_LOG_DIR.mkdir(parents=True, exist_ok=True)

# Lazy-import DB only when enabled
if _USE_DB:
    try:
        from core.database import db, TurnDocument, IntelEventDocument
        logger.info("MongoDB persistence enabled.")
    except ImportError:
        _USE_DB = False
        logger.warning("motor/pymongo not installed — falling back to JSON logs.")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ═══════════════════════════════════════════════════════════════════════════════
# HoneypotSession
# ═══════════════════════════════════════════════════════════════════════════════

class HoneypotSession:
    """
    One active scam conversation.

    Call:
        session = HoneypotSession()
        result  = await session.process_message("scammer text")

    result is always a plain dict — never raises.
    """

    def __init__(self, session_id: str = None):
        self.session_id = session_id or str(uuid.uuid4())[:8].upper()
        self.thread_id  = f"session_{self.session_id}"
        self.created_at = _now()
        self.is_active  = True
        self._prev_intel: ExtractedIntel = ExtractedIntel()
        self._turn_log: list[dict] = []

    # ── Public API ─────────────────────────────────────────────────────────────

    async def process_message(self, scammer_message: str) -> dict:
        """
        Feed one scammer message through the LangGraph pipeline.

        Returns a flat dict:
            session_id, bot_response, turn, strategy, persona,
            scam_type, threat_level, intel (dict), intel_yield,
            session_active, termination_reason, model_used

        Never raises — all errors become {"error": "..."} in the return dict.
        """
        if not self.is_active:
            return {"error": "Session is already closed.",
                    "session_id": self.session_id, "session_active": False}

        if not scammer_message or not scammer_message.strip():
            return {"error": "Empty message received.",
                    "session_id": self.session_id, "session_active": True}

        config      = {"configurable": {"thread_id": self.thread_id}}
        input_state = {
            "current_scammer_message": scammer_message.strip(),
            "session_id": self.session_id,
            "messages":   [HumanMessage(content=scammer_message.strip())],
        }

        # ── Run the graph ──────────────────────────────────────────────────────
        try:
            result = honeypot_graph.invoke(input_state, config=config)
        except RuntimeError as e:
            return {"error": str(e),
                    "hint": "Check GEMINI_API_KEY and GROQ_API_KEY in your .env",
                    "session_id": self.session_id, "session_active": True}
        except Exception as e:
            logger.error(f"Graph error [{self.session_id}]: {e}", exc_info=True)
            return {"error": f"Internal error: {type(e).__name__}",
                    "session_id": self.session_id, "session_active": True}

        # ── Unpack (LangGraph always returns plain dict) ───────────────────────
        bot_response       = result.get("bot_response", "")
        should_continue    = result.get("should_continue", True)
        turn_count         = result.get("turn_count", 0)
        scam_type          = result.get("scam_type", "unknown")
        threat_level       = result.get("threat_level", "low")
        strategy           = result.get("engagement_strategy", "play_dumb")
        persona            = result.get("persona", "naive_victim")
        intel_yield        = result.get("intel_yield_score", 0.0)
        model_used         = result.get("model_used", "unknown")
        termination_reason = result.get("termination_reason", "")

        raw_intel = result.get("intel", {})
        if isinstance(raw_intel, ExtractedIntel):
            intel_obj = raw_intel
        elif isinstance(raw_intel, dict) and raw_intel:
            intel_obj = ExtractedIntel(**raw_intel)
        else:
            intel_obj = ExtractedIntel()

        intel_dict = intel_obj.model_dump()
        new_intel  = self._delta(intel_obj)

        # ── Local turn log ─────────────────────────────────────────────────────
        self._turn_log.append({
            "turn": turn_count, "timestamp": _now(),
            "scammer_message": scammer_message, "bot_response": bot_response,
            "strategy": strategy, "persona": persona,
            "scam_type": scam_type, "threat_level": threat_level,
            "intel_yield": intel_yield, "model_used": model_used,
        })
        self._prev_intel = intel_obj

        # ── Persist ────────────────────────────────────────────────────────────
        await self._persist(
            turn_count, scammer_message, bot_response, strategy, persona,
            scam_type, threat_level, intel_yield, new_intel, intel_dict, model_used,
        )

        # ── Close if done ──────────────────────────────────────────────────────
        if not should_continue:
            self.is_active = False
            await self._finalize(scam_type, threat_level, turn_count,
                                 intel_yield, termination_reason, intel_dict, model_used)

        return {
            "session_id":         self.session_id,
            "bot_response":       bot_response,
            "turn":               turn_count,
            "strategy":           strategy,
            "persona":            persona,
            "scam_type":          scam_type,
            "threat_level":       threat_level,
            "intel":              intel_dict,
            "intel_yield":        intel_yield,
            "session_active":     self.is_active,
            "termination_reason": termination_reason,
            "model_used":         model_used,
            "report_path":        result.get("report_path", ""),
            "report_sent":        result.get("report_sent", False),
            "email_recipient_count": result.get("email_recipient_count", 0),
            "report_status":      result.get("report_status", "awaiting_evidence"),
            "report_error":       result.get("report_error", ""),
            "last_reported_fp":   result.get("last_reported_fp", ""),
        }

    # ── Persistence ────────────────────────────────────────────────────────────

    async def _persist(self, turn_count, scammer_message, bot_response,
                       strategy, persona, scam_type, threat_level,
                       intel_yield, new_intel, intel_dict, model_used):
        if not _USE_DB:
            return
        try:
            from core.database import db, TurnDocument, IntelEventDocument
            await db.append_turn(self.session_id, TurnDocument(
                turn_number=turn_count, timestamp=_now(),
                scammer_message=scammer_message, bot_response=bot_response,
                strategy_used=strategy, persona_used=persona,
                scam_type=scam_type, threat_level=threat_level,
                intel_yield_at_turn=intel_yield, new_intel_found=new_intel,
            ))
            await db.update_session(self.session_id, {
                "scam_type": scam_type, "threat_level": threat_level,
                "intel_yield_score": intel_yield, "intel": intel_dict,
                "model_used": model_used,
            })
            if any(v for v in new_intel.values() if isinstance(v, list) and v):
                await db.log_intel_event(IntelEventDocument(
                    session_id=self.session_id, turn_number=turn_count,
                    scam_type=scam_type,
                    upi_ids_found=new_intel.get("upi_ids", []),
                    phones_found=new_intel.get("phone_numbers", []),
                    accounts_found=new_intel.get("account_numbers", []),
                    bank_names_found=new_intel.get("bank_names", []),
                    raw_snippets=new_intel.get("raw_snippets", []),
                ))
        except Exception as e:
            logger.error(f"DB persist error [{self.session_id} t{turn_count}]: {e}")

    async def _finalize(self, scam_type, threat_level, total_turns,
                        intel_yield, termination_reason, intel_dict, model_used):
        # Always write JSON file — works with and without DB
        self._save_json(scam_type, threat_level, total_turns,
                        intel_yield, termination_reason, intel_dict)
        if not _USE_DB:
            return
        try:
            from core.database import db
            await db.close_session(self.session_id, {
                "scam_type": scam_type, "threat_level": threat_level,
                "total_turns": total_turns, "intel_yield_score": intel_yield,
                "termination_reason": termination_reason,
                "intel": intel_dict, "model_used": model_used,
            })
            await db.archive_intel(self.session_id, scam_type, intel_dict)
        except Exception as e:
            logger.error(f"DB finalize error [{self.session_id}]: {e}")

    def _save_json(self, scam_type, threat_level, total_turns,
                   intel_yield, termination_reason, intel_dict):
        path = _LOG_DIR / f"session_{self.session_id}.json"
        try:
            with open(path, "w") as f:
                json.dump({
                    "session_id": self.session_id, "created_at": self.created_at,
                    "closed_at": _now(), "scam_type": scam_type,
                    "threat_level": threat_level, "total_turns": total_turns,
                    "intel_yield_score": intel_yield,
                    "termination_reason": termination_reason,
                    "intel": intel_dict, "turns": self._turn_log,
                }, f, indent=2)
            logger.info(f"Intel log saved → {path}")
        except Exception as e:
            logger.error(f"JSON log write failed [{self.session_id}]: {e}")

    def _delta(self, current: ExtractedIntel) -> dict:
        prev = self._prev_intel
        return {
            k: [x for x in getattr(current, k) if x not in getattr(prev, k)]
            for k in ("upi_ids", "phone_numbers", "account_numbers",
                      "bank_names", "ifsc_codes", "urls", "names", "raw_snippets")
        }

    def get_summary(self) -> dict:
        latest = self._turn_log[-1] if self._turn_log else {}
        return {
            "session_id":       self.session_id,
            "is_active":        self.is_active,
            "turns":            len(self._turn_log),
            "created_at":       self.created_at,
            "latest_strategy":  latest.get("strategy", "none"),
            "latest_scam_type": latest.get("scam_type", "unknown"),
            "intel_yield":      latest.get("intel_yield", 0.0),
            "intel":            self._prev_intel.model_dump(),
            "report_path":      getattr(self, "report_path", ""),
            "report_sent":      getattr(self, "report_sent", False),
            "report_error":     getattr(self, "report_error", ""),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# SessionRegistry
# ═══════════════════════════════════════════════════════════════════════════════

class SessionRegistry:
    """
    In-memory store of active sessions.
    Closed sessions drop from memory — history is in JSON files or MongoDB.
    """

    def __init__(self):
        self._sessions: dict[str, HoneypotSession] = {}

    async def create_session(self) -> HoneypotSession:
        session = HoneypotSession()
        self._sessions[session.session_id] = session
        if _USE_DB:
            try:
                from core.database import db
                await db.create_session(session.session_id)
            except Exception as e:
                logger.warning(f"DB create_session skipped: {e}")
        logger.info(f"Session created: {session.session_id}")
        return session

    async def get_or_create(self, session_id: str) -> HoneypotSession:
        if session_id not in self._sessions:
            session = HoneypotSession(session_id=session_id)
            self._sessions[session_id] = session
            if _USE_DB:
                try:
                    from core.database import db
                    await db.create_session(session_id)
                except Exception:
                    pass
        return self._sessions[session_id]

    def get_session(self, session_id: str) -> HoneypotSession | None:
        return self._sessions.get(session_id)

    def list_active(self) -> list[dict]:
        return [s.get_summary() for s in self._sessions.values() if s.is_active]

    def active_count(self) -> int:
        return sum(1 for s in self._sessions.values() if s.is_active)

    def remove_closed(self):
        closed = [k for k, s in self._sessions.items() if not s.is_active]
        for k in closed:
            del self._sessions[k]


# Module singleton
registry = SessionRegistry()