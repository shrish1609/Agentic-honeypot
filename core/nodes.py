"""
core/nodes.py — All 5 LangGraph nodes for the Agentic Honeypot pipeline.

Each node:
  - Receives the full HoneypotState (as a dict from LangGraph)
  - Does EXACTLY ONE job
  - Returns a dict of ONLY the fields it changed

Node execution order:
  intake → strategy → persona → extractor → guard

Bug fixes from v1:
  - Phone regex no longer matches digits inside longer account number strings
  - Account numbers are filtered to exclude phone numbers
  - All LLM calls use the new chat_json() API
  - All Pydantic calls use model_dump() not dict()
  - _format_recent_messages handles both LangChain message objects and plain strings
"""

import re
import uuid
import logging
from datetime import datetime
from langchain_core.messages import AIMessage

from core.state import (
    HoneypotState,
    ExtractedIntel,
)
from core.llm_client import llm
from core.prompts import (
    INTAKE_PROMPT    as _INTAKE_SYSTEM,
    STRATEGY_PROMPT  as _STRATEGY_SYSTEM,
    PERSONA_PROMPT   as _PERSONA_SYSTEM,
    EXTRACTOR_PROMPT as _EXTRACTOR_SYSTEM,
)

logger = logging.getLogger(__name__)


def _to_dict(state) -> dict:
    """
    Normalize LangGraph state to a plain dict.

    LangGraph >=1.0 passes the state as the compiled Pydantic model object;
    older versions and test mocks pass a plain dict.
    This helper handles both so every node works regardless of LG version.
    """
    if isinstance(state, dict):
        return state
    if hasattr(state, "model_dump"):
        return state.model_dump()
    return {}


# ═══════════════════════════════════════════════════════════════════════════════
# NODE 1 — INTAKE
# Classifies the scammer's message: type, threat level, confidence, red flags
# ═══════════════════════════════════════════════════════════════════════════════




def intake_node(state: dict) -> dict:
    """
    NODE 1: Classify the scammer's message.
    Input fields used: current_scammer_message
    Output fields set: scam_type, threat_level, confidence_score, scam_indicators, session_id, model_used
    """
    state = _to_dict(state)
    message = state.get("current_scammer_message", "")
    if not message:
        logger.warning("intake_node: empty scammer message received")
        return {}

    data, model = llm.chat_json(_INTAKE_SYSTEM, message)

    # Validate and sanitise LLM output with safe fallbacks
    valid_scam_types = {"upi_fraud","phishing","fake_lottery","job_scam","romance_scam","tech_support","unknown"}
    valid_threat_levels = {"low","medium","high","critical"}

    scam_type = data.get("scam_type", "unknown")
    if scam_type not in valid_scam_types:
        scam_type = "unknown"

    threat_level = data.get("threat_level", "low")
    if threat_level not in valid_threat_levels:
        threat_level = "low"

    try:
        confidence = float(data.get("confidence_score", 0.5))
        confidence = max(0.0, min(1.0, confidence))
    except (TypeError, ValueError):
        confidence = 0.5

    indicators = data.get("scam_indicators", [])
    if not isinstance(indicators, list):
        indicators = []

    return {
        "scam_type": scam_type,
        "threat_level": threat_level,
        "confidence_score": confidence,
        "scam_indicators": indicators,
        "model_used": model,
        # Assign session_id if not already set
        "session_id": state.get("session_id") or str(uuid.uuid4())[:8].upper(),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# NODE 2 — STRATEGY
# Decides HOW to respond based on full conversation context
# ═══════════════════════════════════════════════════════════════════════════════




def strategy_node(state: dict) -> dict:
    """
    NODE 2: Decide the engagement strategy.
    Input fields used: scam_type, threat_level, turn_count, max_turns, intel, intel_yield_score, messages
    Output fields set: engagement_strategy, persona, strategy_reasoning
    """
    state = _to_dict(state)
    turn = state.get("turn_count", 0)
    max_turns = state.get("max_turns", 20)
    intel_yield = state.get("intel_yield_score", 0.0)

    # Hard overrides before calling LLM (saves tokens)
    if turn >= max_turns:
        return {"engagement_strategy": "terminate", "strategy_reasoning": "max turns reached", "persona": state.get("persona", "naive_victim")}
    if intel_yield >= 0.85:
        return {"engagement_strategy": "terminate", "strategy_reasoning": "intel yield target met", "persona": state.get("persona", "eager_victim")}

    intel = state.get("intel", {})
    if isinstance(intel, ExtractedIntel):
        intel_summary = intel.summary()
    elif isinstance(intel, dict):
        intel_summary = str({k: v for k, v in intel.items() if v})
    else:
        intel_summary = "none"

    context = f"""Scam Type: {state.get("scam_type", "unknown")}
Threat Level: {state.get("threat_level", "low")}
Turn Number: {turn} / {max_turns}
Intel Yield Score: {intel_yield:.2f}
Intel Collected: {intel_summary}
Last Scammer Message: {state.get("current_scammer_message", "")}
Recent Conversation:
{_format_recent_messages(state.get("messages", []), n=6)}"""

    data, _ = llm.chat_json(_STRATEGY_SYSTEM, context)

    valid_strategies = {"play_dumb","stall","request_info","escalate","terminate"}
    valid_personas = {"naive_victim","cautiously_interested","eager_victim"}

    strategy = data.get("strategy", "play_dumb")
    if strategy not in valid_strategies:
        strategy = "play_dumb"

    persona = data.get("persona", state.get("persona", "naive_victim"))
    if persona not in valid_personas:
        persona = "naive_victim"

    return {
        "engagement_strategy": strategy,
        "persona": persona,
        "strategy_reasoning": data.get("reasoning", ""),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# NODE 3 — PERSONA
# Generates the in-character victim response text
# ═══════════════════════════════════════════════════════════════════════════════




def persona_node(state: dict) -> dict:
    """
    NODE 3: Generate the in-character honeypot response.
    Input fields used: engagement_strategy, persona, scam_type, current_scammer_message, messages
    Output fields set: bot_response, turn_count
    """
    state = _to_dict(state)
    user_prompt = f"""Strategy: {state.get("engagement_strategy", "play_dumb")}
Persona: {state.get("persona", "naive_victim")}
Scam type: {state.get("scam_type", "unknown")}
Scammer's message: {state.get("current_scammer_message", "")}
Recent conversation:
{_format_recent_messages(state.get("messages", []), n=4)}

Generate only the victim's reply (1-3 sentences):"""

    response_text, _ = llm.chat(_PERSONA_SYSTEM, user_prompt)

    # Safety: strip any accidental meta-commentary the LLM might add
    response_text = response_text.strip()
    if response_text.startswith('"') and response_text.endswith('"'):
        response_text = response_text[1:-1]

    return {
        "bot_response": response_text,
        "turn_count": state.get("turn_count", 0) + 1,
        "messages": [AIMessage(content=response_text)],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# NODE 4 — EXTRACTOR
# Harvests UPI IDs, phone numbers, bank details from the scammer's message
# ═══════════════════════════════════════════════════════════════════════════════

# Bug fix: phone regex now uses lookahead/lookbehind to avoid matching
# digits that are embedded inside longer account number strings
_UPI_RE = re.compile(
    r"[\w.\-+]+@(?:okaxis|oksbi|okicici|okhdfcbank|paytm|ybl|ibl|upi|gpay|phonepe|apl|axl|waicici)",
    re.IGNORECASE,
)
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+91|91)?([6-9]\d{9})(?!\d)"
)
_ACCOUNT_RE = re.compile(r"\b(\d{9,18})\b")
_IFSC_RE = re.compile(r"\b([A-Z]{4}0[A-Z0-9]{6})\b")
_URL_RE = re.compile(r"https?://[^\s]+")




def extractor_node(state: dict) -> dict:
    """
    NODE 4: Extract criminal intelligence from the scammer's message.
    Input fields used: current_scammer_message, intel (existing)
    Output fields set: intel (merged with existing), intel_yield_score
    """
    state = _to_dict(state)
    message = state.get("current_scammer_message", "")
    if not message:
        return {}

    # --- Fast regex pass ---
    upi_regex = _UPI_RE.findall(message)
    phone_regex = _PHONE_RE.findall(message)  # returns capture group (the 10-digit number)
    account_regex = _ACCOUNT_RE.findall(message)
    ifsc_regex = _IFSC_RE.findall(message)
    url_regex = _URL_RE.findall(message)

    # Bug fix: filter account numbers to exclude phone numbers (they overlap)
    phone_set = set(phone_regex)
    account_filtered = [a for a in account_regex if a not in phone_set and len(a) > 10]

    # --- LLM pass for names, bank names, contextual intel ---
    llm_data, _ = llm.chat_json(_EXTRACTOR_SYSTEM, message)

    # --- Merge regex + LLM ---
    all_upi = list(set(upi_regex + llm_data.get("upi_ids", [])))
    all_phones = list(set(phone_regex + llm_data.get("phone_numbers", [])))
    all_accounts = list(set(account_filtered + llm_data.get("account_numbers", [])))
    all_ifsc = list(set(ifsc_regex))
    all_urls = list(set(url_regex + llm_data.get("urls", [])))
    all_banks = llm_data.get("bank_names", [])
    all_names = llm_data.get("names", [])
    all_snippets = llm_data.get("raw_snippets", [])

    # --- Accumulate with existing session intel ---
    existing_raw = state.get("intel", {})
    if isinstance(existing_raw, ExtractedIntel):
        existing = existing_raw
    elif isinstance(existing_raw, dict):
        existing = ExtractedIntel(**existing_raw) if existing_raw else ExtractedIntel()
    else:
        existing = ExtractedIntel()

    updated = ExtractedIntel(
        upi_ids=list(set(existing.upi_ids + all_upi)),
        phone_numbers=list(set(existing.phone_numbers + all_phones)),
        bank_names=list(set(existing.bank_names + all_banks)),
        account_numbers=list(set(existing.account_numbers + all_accounts)),
        ifsc_codes=list(set(existing.ifsc_codes + all_ifsc)),
        urls=list(set(existing.urls + all_urls)),
        names=list(set(existing.names + all_names)),
        raw_snippets=existing.raw_snippets + all_snippets,
    )

    yield_score = _score_intel(updated)

    return {
        "intel": updated.model_dump(),   # plain dict — safe for LG checkpoint serialization
        "intel_yield_score": yield_score,
    }


def _score_intel(intel: ExtractedIntel) -> float:
    """
    Score 0.0–1.0 based on intelligence collected.
    UPI IDs are highest value (actionable for police).
    """
    score = 0.0
    score += min(len(intel.upi_ids) * 0.30, 0.60)
    score += min(len(intel.phone_numbers) * 0.15, 0.30)
    score += min(len(intel.account_numbers) * 0.10, 0.20)
    score += min(len(intel.ifsc_codes) * 0.10, 0.10)
    score += min(len(intel.bank_names) * 0.05, 0.10)
    return min(round(score, 3), 1.0)


# ═══════════════════════════════════════════════════════════════════════════════
# NODE 5 — GUARD
# Decides if the session should continue or terminate
# ═══════════════════════════════════════════════════════════════════════════════

def guard_node(state: dict) -> dict:
    """
    NODE 5: Session lifecycle control.
    Input fields used: turn_count, max_turns, engagement_strategy, intel_yield_score,
                       threat_level, confidence_score
    Output fields set: should_continue, termination_reason
    """
    state = _to_dict(state)
    turn = state.get("turn_count", 0)
    max_turns = state.get("max_turns", 20)
    intel_yield = state.get("intel_yield_score", 0.0)
    strategy = state.get("engagement_strategy", "play_dumb")
    threat = state.get("threat_level", "low")
    confidence = state.get("confidence_score", 0.5)

    reasons = []

    if turn >= max_turns:
        reasons.append(f"Reached max turns ({max_turns})")

    if strategy == "terminate":
        reasons.append("Strategy node decided to terminate")

    if intel_yield >= 0.85:
        reasons.append(f"Intel yield target reached ({intel_yield:.0%})")

    # If confidence is very low after several turns, this might not be a real scammer
    if threat == "low" and confidence < 0.25 and turn > 5:
        reasons.append(f"Low-confidence non-scam conversation after {turn} turns")

    should_continue = len(reasons) == 0
    return {
        "should_continue": should_continue,
        "termination_reason": "; ".join(reasons) if reasons else "",
    }


# ── LangGraph routing function ───────────────────────────────────────────────

def route_after_guard(state: dict) -> str:
    """Conditional edge: 'continue' loops the conversation, 'end' closes the session."""
    state = _to_dict(state)
    return "continue" if state.get("should_continue", True) else "end"


# ── Shared helper ────────────────────────────────────────────────────────────

def _format_recent_messages(messages: list, n: int = 6) -> str:
    """
    Format last N messages for LLM context injection.
    Handles both LangChain message objects (with .type and .content)
    and plain dicts (from LangGraph serialization).
    """
    recent = messages[-n:] if len(messages) > n else messages
    lines = []
    for msg in recent:
        if hasattr(msg, "type") and hasattr(msg, "content"):
            # LangChain message object
            role = "SCAMMER" if msg.type == "human" else "BOT"
            content = msg.content
        elif isinstance(msg, dict):
            # Serialized form
            role = "SCAMMER" if msg.get("type") == "human" else "BOT"
            content = msg.get("content", "")
        else:
            continue
        lines.append(f"{role}: {content}")
    return "\n".join(lines) if lines else "(conversation just started)"