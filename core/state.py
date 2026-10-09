"""
core/state.py — Canonical state schema for the Agentic Honeypot pipeline.

This is the SINGLE SOURCE OF TRUTH that flows through every LangGraph node.
Every field is optional/defaulted so partial node updates work correctly.

Pydantic v2 compatible — use .model_dump() not .dict()
"""

from typing import Annotated, Literal, Optional
from pydantic import BaseModel, Field
from langgraph.graph.message import add_messages


# ── Enum-like Literals ───────────────────────────────────────────────────────

ScamType = Literal[
    "upi_fraud",
    "phishing",
    "fake_lottery",
    "job_scam",
    "romance_scam",
    "tech_support",
    "unknown",
]

ThreatLevel = Literal["low", "medium", "high", "critical"]

EngagementStrategy = Literal[
    "play_dumb",      # Feign confusion, ask basic questions
    "stall",          # Delay with real-sounding excuses
    "request_info",   # Actively fish for scammer's UPI/bank details
    "escalate",       # Push scammer to confirm receiving payment details
    "terminate",      # End conversation gracefully
]

PersonaState = Literal[
    "naive_victim",           # Elderly/low-literacy Indian user
    "cautiously_interested",  # Curious but hesitant
    "eager_victim",           # Appears ready to send money
]


# ── Intelligence Container ───────────────────────────────────────────────────

class ExtractedIntel(BaseModel):
    """All criminal intelligence harvested from one session."""
    upi_ids: list[str] = Field(default_factory=list)
    phone_numbers: list[str] = Field(default_factory=list)
    bank_names: list[str] = Field(default_factory=list)
    account_numbers: list[str] = Field(default_factory=list)
    ifsc_codes: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    names: list[str] = Field(default_factory=list)
    raw_snippets: list[str] = Field(default_factory=list)

    def is_empty(self) -> bool:
        return not any([
            self.upi_ids, self.phone_numbers, self.bank_names,
            self.account_numbers, self.ifsc_codes, self.urls, self.names,
        ])

    def summary(self) -> str:
        parts = []
        if self.upi_ids:       parts.append(f"UPI: {self.upi_ids}")
        if self.phone_numbers: parts.append(f"Phones: {self.phone_numbers}")
        if self.bank_names:    parts.append(f"Banks: {self.bank_names}")
        if self.account_numbers: parts.append(f"Accounts: {self.account_numbers}")
        if self.ifsc_codes:    parts.append(f"IFSC: {self.ifsc_codes}")
        return " | ".join(parts) if parts else "None yet"


# ── Main Graph State ─────────────────────────────────────────────────────────

class HoneypotState(BaseModel):
    """
    Complete state object passed between all LangGraph nodes.
    LangGraph merges node return dicts into this via field name matching.

    NOTE: LangGraph returns state as a plain dict after .invoke()
    Always use result.get('field', default) in session_manager, never attribute access.
    """

    # --- Identity ---
    session_id: str = ""

    # --- Conversation (add_messages enables safe list merging across turns) ---
    messages: Annotated[list, add_messages] = Field(default_factory=list)
    current_scammer_message: str = ""
    turn_count: int = 0
    max_turns: int = 20

    # --- Classification (set by intake_node) ---
    scam_type: ScamType = "unknown"
    threat_level: ThreatLevel = "low"
    confidence_score: float = 0.0
    scam_indicators: list[str] = Field(default_factory=list)

    # --- Strategy (set by strategy_node) ---
    engagement_strategy: EngagementStrategy = "play_dumb"
    strategy_reasoning: str = ""
    persona: PersonaState = "naive_victim"

    # --- Response (set by persona_node) ---
    bot_response: str = ""

    # --- Intelligence (updated by extractor_node, accumulates across turns) ---
    intel: dict = Field(default_factory=dict)
    intel_yield_score: float = 0.0

    # --- Reporting (set by reporter_node) ---
    report_path: str = ""
    report_sent: bool = False
    email_recipient_count: int = 0
    report_error: str = ""
    last_reported_fp: str = ""

    # --- Session Control (set by guard_node) ---
    should_continue: bool = True
    termination_reason: str = ""

    # --- Telemetry ---
    model_used: str = ""
    total_time_wasted_seconds: float = 0.0

    model_config = {"arbitrary_types_allowed": True}