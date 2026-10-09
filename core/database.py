"""
core/database.py — MongoDB integration for the Agentic Honeypot.

Uses Motor (async MongoDB driver) so it works natively with FastAPI's
async request handlers without blocking the event loop.

Collections:
  sessions     — one document per honeypot session (full lifecycle)
  intel_events — one document per turn where new intelligence was found
  scam_archive — deduplicated master list of harvested scammer identifiers

Schema is defined as Pydantic models for validation on write and
typed access on read. All documents use MongoDB _id = session_id
(not ObjectId) for human-readable lookup.

Usage:
    from core.database import db
    await db.connect()
    await db.save_session(session_doc)
    await db.upsert_intel(session_id, intel_dict)
"""

import os
import logging
from datetime import datetime, timezone
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

# ── MongoDB Document Schemas ─────────────────────────────────────────────────
# These mirror exactly what gets stored. Pydantic validates on write.

class TurnDocument(BaseModel):
    """One conversation turn stored inside a SessionDocument."""
    turn_number: int
    timestamp: str
    scammer_message: str
    bot_response: str
    strategy_used: str
    persona_used: str
    scam_type: str
    threat_level: str
    intel_yield_at_turn: float
    new_intel_found: dict          # Only the delta found this turn


class SessionDocument(BaseModel):
    """
    Top-level document stored in the `sessions` collection.
    _id = session_id (string) for human-readable lookups.
    """
    session_id: str                # Used as MongoDB _id
    status: str = "active"         # active | closed
    created_at: str = Field(default_factory=lambda: _now())
    closed_at: Optional[str] = None
    scam_type: str = "unknown"
    threat_level: str = "low"
    total_turns: int = 0
    intel_yield_score: float = 0.0
    termination_reason: str = ""
    model_used: str = ""
    intel: dict = Field(default_factory=dict)   # Final ExtractedIntel snapshot
    turns: list[TurnDocument] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


class IntelEventDocument(BaseModel):
    """
    One row in `intel_events` — written every turn that yields new intel.
    Useful for time-series analysis of scam activity.
    """
    session_id: str
    turn_number: int
    timestamp: str = Field(default_factory=lambda: _now())
    scam_type: str
    upi_ids_found: list[str] = Field(default_factory=list)
    phones_found: list[str] = Field(default_factory=list)
    accounts_found: list[str] = Field(default_factory=list)
    bank_names_found: list[str] = Field(default_factory=list)
    raw_snippets: list[str] = Field(default_factory=list)


class ScamArchiveDocument(BaseModel):
    """
    Master deduplicated record in `scam_archive`.
    One document per unique scammer identifier (UPI ID / phone / account).
    Updated (not duplicated) when seen in multiple sessions.
    """
    identifier: str                # The UPI ID / phone / account number
    identifier_type: str           # "upi_id" | "phone" | "account_number" | "url"
    first_seen: str = Field(default_factory=lambda: _now())
    last_seen: str = Field(default_factory=lambda: _now())
    times_seen: int = 1
    session_ids: list[str] = Field(default_factory=list)
    scam_types_seen: list[str] = Field(default_factory=list)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Database Client ──────────────────────────────────────────────────────────

class HoneypotDB:
    """
    Async MongoDB client wrapping all database operations.

    Designed for FastAPI — call await db.connect() in app startup,
    await db.disconnect() in app shutdown.

    All methods are async and safe to call from FastAPI route handlers.
    """

    def __init__(self):
        self._client: Optional[AsyncIOMotorClient] = None
        self._db: Optional[AsyncIOMotorDatabase] = None

    # ── Lifecycle ────────────────────────────────────────────────────────────

    async def connect(self):
        """Connect to MongoDB. Call once at application startup."""
        uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
        db_name = os.getenv("MONGODB_DB", "agentic_honeypot")

        self._client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=5000)
        self._db = self._client[db_name]

        # Ensure indexes exist (idempotent — safe to call on every startup)
        await self._ensure_indexes()

        try:
            await self._client.admin.command("ping")
            logger.info(f"MongoDB connected: {uri} / {db_name}")
        except Exception as e:
            logger.error(f"MongoDB connection failed: {e}")
            raise

    async def disconnect(self):
        """Gracefully close the MongoDB connection."""
        if self._client:
            self._client.close()
            logger.info("MongoDB connection closed.")

    async def _ensure_indexes(self):
        """Create indexes for common query patterns. Idempotent."""
        sessions = self._db["sessions"]
        intel_events = self._db["intel_events"]
        scam_archive = self._db["scam_archive"]

        # sessions: look up by status (list active sessions) + created_at (sort)
        await sessions.create_index("status")
        await sessions.create_index("created_at")
        await sessions.create_index("scam_type")
        await sessions.create_index("intel_yield_score")

        # intel_events: look up by session or time range
        await intel_events.create_index("session_id")
        await intel_events.create_index("timestamp")

        # scam_archive: look up by identifier (UPI ID etc.) — must be unique
        await scam_archive.create_index("identifier", unique=True)
        await scam_archive.create_index("identifier_type")
        await scam_archive.create_index("times_seen")

        logger.info("MongoDB indexes verified.")

    # ── Sessions Collection ──────────────────────────────────────────────────

    async def create_session(self, session_id: str) -> bool:
        """
        Insert a new session document with status=active.
        Returns True on success, False if session_id already exists.
        """
        doc = SessionDocument(session_id=session_id)
        try:
            await self._db["sessions"].insert_one(
                {"_id": session_id, **doc.model_dump()}
            )
            return True
        except Exception as e:
            if "duplicate key" in str(e).lower() or "E11000" in str(e):
                logger.warning(f"Session {session_id} already exists in DB.")
                return False
            logger.error(f"create_session failed: {e}")
            raise

    async def update_session(self, session_id: str, update_fields: dict) -> bool:
        """
        Partial update of a session document (upsert-safe).
        Called after every turn to keep DB in sync with in-memory state.
        """
        try:
            result = await self._db["sessions"].update_one(
                {"_id": session_id},
                {"$set": update_fields},
                upsert=True,
            )
            return result.acknowledged
        except Exception as e:
            logger.error(f"update_session {session_id} failed: {e}")
            return False

    async def append_turn(self, session_id: str, turn: TurnDocument) -> bool:
        """Push one turn document into the session's turns array."""
        try:
            result = await self._db["sessions"].update_one(
                {"_id": session_id},
                {
                    "$push": {"turns": turn.model_dump()},
                    "$inc": {"total_turns": 1},
                },
            )
            return result.acknowledged
        except Exception as e:
            logger.error(f"append_turn {session_id} turn {turn.turn_number} failed: {e}")
            return False

    async def close_session(self, session_id: str, final_fields: dict) -> bool:
        """Mark session as closed and write final state snapshot."""
        update = {
            "status": "closed",
            "closed_at": _now(),
            **final_fields,
        }
        return await self.update_session(session_id, update)

    async def get_session(self, session_id: str) -> Optional[dict]:
        """Fetch one session document by ID."""
        return await self._db["sessions"].find_one({"_id": session_id})

    async def list_sessions(
        self,
        status: Optional[str] = None,
        limit: int = 50,
        skip: int = 0,
    ) -> list[dict]:
        """
        List sessions, optionally filtered by status.
        Returns newest-first (sorted by created_at descending).
        """
        query = {}
        if status:
            query["status"] = status

        cursor = (
            self._db["sessions"]
            .find(query, {"turns": 0})  # Exclude turns array for list views
            .sort("created_at", -1)
            .skip(skip)
            .limit(limit)
        )
        return await cursor.to_list(length=limit)

    async def count_sessions(self, status: Optional[str] = None) -> int:
        query = {"status": status} if status else {}
        return await self._db["sessions"].count_documents(query)

    # ── Intel Events Collection ──────────────────────────────────────────────

    async def log_intel_event(self, event: IntelEventDocument) -> bool:
        """Log a turn-level intelligence event. Only called when new intel found."""
        has_intel = any([
            event.upi_ids_found,
            event.phones_found,
            event.accounts_found,
            event.bank_names_found,
        ])
        if not has_intel:
            return True  # Nothing to log

        try:
            await self._db["intel_events"].insert_one(event.model_dump())
            return True
        except Exception as e:
            logger.error(f"log_intel_event failed: {e}")
            return False

    async def get_intel_events(
        self,
        session_id: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict]:
        query = {"session_id": session_id} if session_id else {}
        cursor = (
            self._db["intel_events"]
            .find(query)
            .sort("timestamp", -1)
            .limit(limit)
        )
        return await cursor.to_list(length=limit)

    # ── Scam Archive Collection ──────────────────────────────────────────────

    async def archive_intel(
        self,
        session_id: str,
        scam_type: str,
        intel: dict,
    ) -> int:
        """
        Upsert all harvested identifiers into the scam archive.
        Returns the number of new unique identifiers added.
        """
        new_count = 0
        items: list[tuple[str, str]] = []

        for uid in intel.get("upi_ids", []):
            items.append((uid, "upi_id"))
        for phone in intel.get("phone_numbers", []):
            items.append((phone, "phone"))
        for acc in intel.get("account_numbers", []):
            items.append((acc, "account_number"))
        for url in intel.get("urls", []):
            items.append((url, "url"))

        for identifier, id_type in items:
            if not identifier:
                continue
            try:
                result = await self._db["scam_archive"].update_one(
                    {"identifier": identifier},
                    {
                        "$set": {
                            "identifier_type": id_type,
                            "last_seen": _now(),
                        },
                        "$inc": {"times_seen": 1},
                        "$addToSet": {
                            "session_ids": session_id,
                            "scam_types_seen": scam_type,
                        },
                        "$setOnInsert": {
                            "identifier": identifier,
                            "first_seen": _now(),
                        },
                    },
                    upsert=True,
                )
                if result.upserted_id is not None:
                    new_count += 1
            except Exception as e:
                logger.error(f"archive_intel upsert failed for {identifier}: {e}")

        return new_count

    async def get_archive(
        self,
        identifier_type: Optional[str] = None,
        limit: int = 200,
    ) -> list[dict]:
        """Fetch scam archive, sorted by most frequently seen first."""
        query = {"identifier_type": identifier_type} if identifier_type else {}
        cursor = (
            self._db["scam_archive"]
            .find(query)
            .sort("times_seen", -1)
            .limit(limit)
        )
        return await cursor.to_list(length=limit)

    async def search_archive(self, query_str: str) -> list[dict]:
        """Search archive by partial identifier match (regex)."""
        cursor = self._db["scam_archive"].find(
            {"identifier": {"$regex": query_str, "$options": "i"}}
        ).limit(50)
        return await cursor.to_list(length=50)

    # ── Analytics ────────────────────────────────────────────────────────────

    async def get_stats(self) -> dict:
        """Aggregate dashboard statistics across all collections."""
        sessions_col = self._db["sessions"]
        archive_col = self._db["scam_archive"]

        total = await sessions_col.count_documents({})
        active = await sessions_col.count_documents({"status": "active"})
        closed = await sessions_col.count_documents({"status": "closed"})
        total_upi = await archive_col.count_documents({"identifier_type": "upi_id"})
        total_phones = await archive_col.count_documents({"identifier_type": "phone"})

        # Scam type breakdown
        pipeline = [
            {"$group": {"_id": "$scam_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        scam_breakdown_cursor = sessions_col.aggregate(pipeline)
        scam_breakdown = {
            doc["_id"]: doc["count"]
            async for doc in scam_breakdown_cursor
        }

        # Average intel yield for closed sessions
        avg_pipeline = [
            {"$match": {"status": "closed"}},
            {"$group": {"_id": None, "avg_yield": {"$avg": "$intel_yield_score"}}},
        ]
        avg_cursor = sessions_col.aggregate(avg_pipeline)
        avg_docs = await avg_cursor.to_list(length=1)
        avg_yield = avg_docs[0]["avg_yield"] if avg_docs else 0.0

        return {
            "total_sessions": total,
            "active_sessions": active,
            "closed_sessions": closed,
            "unique_upi_ids": total_upi,
            "unique_phone_numbers": total_phones,
            "avg_intel_yield": round(avg_yield, 3),
            "scam_type_breakdown": scam_breakdown,
        }


# ── Module singleton ─────────────────────────────────────────────────────────

db = HoneypotDB()