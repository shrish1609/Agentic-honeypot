"""
tests/test_core.py — Unit + integration tests for the Agentic Honeypot core.

Run with:
    pytest tests/ -v
    pytest tests/ -v --tb=short     # concise tracebacks

Tests are structured into 5 classes mirroring the architecture:
  TestState         — Pydantic schemas and field defaults
  TestLLMClient     — JSON parsing, fallback logic (no real API calls)
  TestNodes         — Regex extraction, scoring, routing, node output shapes
  TestGraph         — Graph compilation and state flow (no LLM)
  TestDatabase      — MongoDB document schema validation (no real DB)
  TestSessionManager— Session lifecycle logic (mocked graph + DB)

All tests run WITHOUT needing real API keys or a running MongoDB.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))


# ══════════════════════════════════════════════════════════════════════════════
# TestState
# ══════════════════════════════════════════════════════════════════════════════

class TestState:
    def test_honeypot_state_defaults(self):
        from core.state import HoneypotState
        s = HoneypotState()
        assert s.session_id == ""
        assert s.turn_count == 0
        assert s.max_turns == 20
        assert s.should_continue is True
        assert s.scam_type == "unknown"
        assert s.threat_level == "low"
        assert s.intel_yield_score == 0.0
        assert s.email_recipient_count == 0

    def test_extracted_intel_defaults(self):
        from core.state import ExtractedIntel
        e = ExtractedIntel()
        assert e.upi_ids == []
        assert e.phone_numbers == []
        assert e.is_empty() is True

    def test_extracted_intel_is_not_empty(self):
        from core.state import ExtractedIntel
        e = ExtractedIntel(upi_ids=["test@oksbi"])
        assert e.is_empty() is False

    def test_extracted_intel_summary(self):
        from core.state import ExtractedIntel
        e = ExtractedIntel(upi_ids=["a@oksbi"], phone_numbers=["9876543210"])
        summary = e.summary()
        assert "a@oksbi" in summary
        assert "9876543210" in summary

    def test_extracted_intel_summary_empty(self):
        from core.state import ExtractedIntel
        assert ExtractedIntel().summary() == "None yet"

    def test_honeypot_state_model_dump(self):
        from core.state import HoneypotState
        d = HoneypotState().model_dump()
        assert "session_id" in d
        assert "intel" in d
        assert "messages" in d

    def test_extracted_intel_model_dump(self):
        from core.state import ExtractedIntel
        d = ExtractedIntel().model_dump()
        expected_keys = {"upi_ids","phone_numbers","bank_names","account_numbers",
                         "ifsc_codes","urls","names","raw_snippets"}
        assert expected_keys.issubset(set(d.keys()))

    def test_state_intel_field_is_dict(self):
        from core.state import HoneypotState
        s = HoneypotState()
        assert isinstance(s.intel, dict)


# ══════════════════════════════════════════════════════════════════════════════
# TestLLMClient
# ══════════════════════════════════════════════════════════════════════════════

class TestLLMClient:
    """Test JSON parsing and error handling — no real API calls."""

    def _get_client(self):
        from core.llm_client import LLMClient
        return LLMClient()

    def test_parse_json_clean(self):
        client = self._get_client()
        result = client._parse_json('{"key": "value", "num": 42}')
        assert result == {"key": "value", "num": 42}

    def test_parse_json_with_markdown_fences(self):
        client = self._get_client()
        text = '```json\n{"scam_type": "upi_fraud"}\n```'
        result = client._parse_json(text)
        assert result["scam_type"] == "upi_fraud"

    def test_parse_json_with_plain_fences(self):
        client = self._get_client()
        text = '```\n{"key": "val"}\n```'
        result = client._parse_json(text)
        assert result["key"] == "val"

    def test_parse_json_empty_string(self):
        client = self._get_client()
        assert client._parse_json("") == {}

    def test_parse_json_whitespace_only(self):
        client = self._get_client()
        assert client._parse_json("   ") == {}

    def test_parse_json_invalid(self):
        client = self._get_client()
        assert client._parse_json("this is not json at all") == {}

    def test_parse_json_array_returns_empty(self):
        # We expect a dict — arrays should return {}
        client = self._get_client()
        result = client._parse_json("[1, 2, 3]")
        assert result == {}

    def test_parse_json_nested(self):
        client = self._get_client()
        text = '{"intel": {"upi_ids": ["a@oksbi"], "phones": []}}'
        result = client._parse_json(text)
        assert result["intel"]["upi_ids"] == ["a@oksbi"]

    def test_chat_raises_when_no_providers(self):
        from core.llm_client import LLMClient
        client = LLMClient()
        client._gemini_client = None
        client._groq_api_key = None
        with pytest.raises(RuntimeError, match="All LLM providers failed"):
            client.chat("system", "user")

    def test_chat_falls_back_to_groq(self):
        from core.llm_client import LLMClient
        client = LLMClient()

        # Make Gemini raise
        mock_gemini = MagicMock()
        mock_gemini.models.generate_content.side_effect = Exception("Gemini down")
        client._gemini_client = mock_gemini

        # Mock Groq to succeed
        with patch.object(client, "_groq_chat", return_value="groq response") as mock_groq:
            client._groq_api_key = "fake_key"
            text, model = client.chat("system", "user")
            assert text == "groq response"
            assert "gpt-oss" in model
            mock_groq.assert_called_once()


# ══════════════════════════════════════════════════════════════════════════════
# TestNodes
# ══════════════════════════════════════════════════════════════════════════════

class TestNodes:

    # ── Regex patterns ────────────────────────────────────────────────────────

    def test_upi_regex_matches_standard(self):
        from core.nodes import _UPI_RE
        assert _UPI_RE.findall("pay to john@oksbi now") == ["john@oksbi"]

    def test_upi_regex_case_insensitive(self):
        from core.nodes import _UPI_RE
        assert _UPI_RE.findall("pay JOHN@PAYTM") == ["JOHN@PAYTM"]

    def test_upi_regex_multiple(self):
        from core.nodes import _UPI_RE
        results = _UPI_RE.findall("send to a@oksbi or b@gpay or c@phonepe")
        assert len(results) == 3

    def test_upi_regex_ignores_non_upi_emails(self):
        from core.nodes import _UPI_RE
        # gmail.com is not a UPI handle
        assert _UPI_RE.findall("contact me at test@gmail.com") == []

    def test_phone_regex_standard(self):
        from core.nodes import _PHONE_RE
        assert _PHONE_RE.findall("call 9876543210") == ["9876543210"]

    def test_phone_regex_with_country_code(self):
        from core.nodes import _PHONE_RE
        assert _PHONE_RE.findall("call +919876543210") == ["9876543210"]

    def test_phone_regex_not_inside_account(self):
        from core.nodes import _PHONE_RE
        # 12-digit account number should NOT yield a phone number
        assert _PHONE_RE.findall("account 567812345678") == []

    def test_phone_regex_only_mobile_numbers(self):
        from core.nodes import _PHONE_RE
        # Landline starting with 1 should not match
        assert _PHONE_RE.findall("call 1234567890") == []

    def test_phone_regex_multiple(self):
        from core.nodes import _PHONE_RE
        results = _PHONE_RE.findall("call 9876543210 or 8765432109")
        assert set(results) == {"9876543210", "8765432109"}

    def test_ifsc_regex(self):
        from core.nodes import _IFSC_RE
        assert _IFSC_RE.findall("IFSC: SBIN0001234") == ["SBIN0001234"]
        assert _IFSC_RE.findall("HDFC0002345") == ["HDFC0002345"]
        assert _IFSC_RE.findall("not an ifsc") == []

    def test_url_regex(self):
        from core.nodes import _URL_RE
        assert _URL_RE.findall("visit http://scam.fake/win") == ["http://scam.fake/win"]
        assert _URL_RE.findall("go to https://bit.ly/abc123") == ["https://bit.ly/abc123"]

    # ── Intel scoring ─────────────────────────────────────────────────────────

    def test_score_empty(self):
        from core.nodes import _score_intel
        from core.state import ExtractedIntel
        assert _score_intel(ExtractedIntel()) == 0.0

    def test_score_one_upi(self):
        from core.nodes import _score_intel
        from core.state import ExtractedIntel
        assert _score_intel(ExtractedIntel(upi_ids=["a@oksbi"])) == 0.3

    def test_score_upi_capped_at_060(self):
        from core.nodes import _score_intel
        from core.state import ExtractedIntel
        # Even 10 UPI IDs max out at 0.60
        assert _score_intel(ExtractedIntel(upi_ids=["a@oksbi"] * 10)) == 0.6

    def test_score_full_intel_reaches_1(self):
        from core.nodes import _score_intel
        from core.state import ExtractedIntel
        full = ExtractedIntel(
            upi_ids=["a@oksbi", "b@paytm"],
            phone_numbers=["9876543210", "8765432109"],
            account_numbers=["12345678901"],
            bank_names=["SBI", "HDFC"],
        )
        assert _score_intel(full) == 1.0

    def test_score_never_exceeds_1(self):
        from core.nodes import _score_intel
        from core.state import ExtractedIntel
        massive = ExtractedIntel(
            upi_ids=["a@oksbi"] * 20,
            phone_numbers=["9876543210"] * 20,
            account_numbers=["12345678901"] * 20,
            bank_names=["SBI"] * 20,
            ifsc_codes=["SBIN0001234"] * 20,
        )
        assert _score_intel(massive) == 1.0

    # ── Guard routing ──────────────────────────────────────────────────────────

    def test_route_continue(self):
        from core.nodes import route_after_guard
        assert route_after_guard({"should_continue": True}) == "continue"

    def test_route_end(self):
        from core.nodes import route_after_guard
        assert route_after_guard({"should_continue": False}) == "end"

    def test_route_default_continue(self):
        from core.nodes import route_after_guard
        # Missing key should default to continue
        assert route_after_guard({}) == "continue"

    # ── guard_node logic ─────────────────────────────────────────────────────

    def test_guard_terminates_at_max_turns(self):
        from core.nodes import guard_node
        state = {"turn_count": 20, "max_turns": 20, "engagement_strategy": "play_dumb",
                 "intel_yield_score": 0.1, "threat_level": "low", "confidence_score": 0.8}
        result = guard_node(state)
        assert result["should_continue"] is False
        assert "max turns" in result["termination_reason"].lower()

    def test_guard_terminates_on_high_yield(self):
        from core.nodes import guard_node
        state = {"turn_count": 5, "max_turns": 20, "engagement_strategy": "escalate",
                 "intel_yield_score": 0.9, "threat_level": "high", "confidence_score": 0.9}
        result = guard_node(state)
        assert result["should_continue"] is False

    def test_guard_terminates_on_strategy(self):
        from core.nodes import guard_node
        state = {"turn_count": 5, "max_turns": 20, "engagement_strategy": "terminate",
                 "intel_yield_score": 0.1, "threat_level": "low", "confidence_score": 0.8}
        result = guard_node(state)
        assert result["should_continue"] is False

    def test_guard_continues_normally(self):
        from core.nodes import guard_node
        state = {"turn_count": 3, "max_turns": 20, "engagement_strategy": "play_dumb",
                 "intel_yield_score": 0.2, "threat_level": "medium", "confidence_score": 0.7}
        result = guard_node(state)
        assert result["should_continue"] is True
        assert result["termination_reason"] == ""

    def test_guard_terminates_low_confidence_non_scam(self):
        from core.nodes import guard_node
        state = {"turn_count": 6, "max_turns": 20, "engagement_strategy": "play_dumb",
                 "intel_yield_score": 0.0, "threat_level": "low", "confidence_score": 0.1}
        result = guard_node(state)
        assert result["should_continue"] is False

    # ── intake_node validation ────────────────────────────────────────────────

    def test_intake_handles_invalid_scam_type(self):
        from core.nodes import intake_node
        with patch("core.nodes.llm") as mock_llm:
            mock_llm.chat_json.return_value = (
                {"scam_type": "INVALID_TYPE", "threat_level": "low",
                 "confidence_score": 0.5, "scam_indicators": []},
                "test-model",
            )
            result = intake_node({"current_scammer_message": "test"})
            assert result["scam_type"] == "unknown"

    def test_intake_handles_invalid_threat_level(self):
        from core.nodes import intake_node
        with patch("core.nodes.llm") as mock_llm:
            mock_llm.chat_json.return_value = (
                {"scam_type": "phishing", "threat_level": "EXTREME",
                 "confidence_score": 0.5, "scam_indicators": []},
                "test-model",
            )
            result = intake_node({"current_scammer_message": "test"})
            assert result["threat_level"] == "low"

    def test_intake_empty_message_returns_empty(self):
        from core.nodes import intake_node
        result = intake_node({"current_scammer_message": ""})
        assert result == {}

    def test_persona_stores_reply_and_uses_conversation_context(self):
        from core.nodes import persona_node
        from langchain_core.messages import AIMessage

        state = {
            "engagement_strategy": "play_dumb",
            "persona": "naive_victim",
            "scam_type": "upi_fraud",
            "current_scammer_message": "Send 500 rupees to ramesh@oksbi",
            "messages": [
                {"type": "human", "content": "I will send the payment now"},
                {"type": "ai", "content": "Which UPI ID should I use?"},
                {"type": "human", "content": "Send 500 rupees to ramesh@oksbi"},
            ],
            "turn_count": 1,
        }
        with patch("core.nodes.llm") as mock_llm:
            mock_llm.chat.return_value = ("Acha, ramesh@oksbi par 500 bhejna hai?", "test-model")
            result = persona_node(state)

        prompt = mock_llm.chat.call_args.args[1]
        assert "Which UPI ID should I use?" in prompt
        assert "Send 500 rupees to ramesh@oksbi" in prompt
        assert result["messages"] == [AIMessage(content=result["bot_response"])]

    def test_cli_prints_draft_status(self, capsys):
        from core.run_cli import _print_report_status

        with patch.dict("os.environ", {"AUTO_REPORT": "draft"}):
            _print_report_status({"report_path": "reports/report_TEST.txt", "report_sent": False})

        output = capsys.readouterr().out
        assert "Report saved" in output
        assert "Email not sent: AUTO_REPORT is set to draft." in output

    def test_cli_explains_when_no_report_was_generated(self, capsys):
        from core.run_cli import _print_report_status

        _print_report_status({"report_path": "", "report_sent": False})

        assert "No report generated" in capsys.readouterr().out

    def test_cli_prints_email_recipient_count(self, capsys):
        from core.run_cli import _print_report_status

        _print_report_status({
            "report_path": "reports/report_TEST.txt",
            "report_sent": True,
            "email_recipient_count": 2,
        })

        assert "Report emailed to 2 recipient(s)" in capsys.readouterr().out

    def test_intake_confidence_clamped(self):
        from core.nodes import intake_node
        with patch("core.nodes.llm") as mock_llm:
            mock_llm.chat_json.return_value = (
                {"scam_type": "phishing", "threat_level": "high",
                 "confidence_score": 99.0, "scam_indicators": []},
                "test-model",
            )
            result = intake_node({"current_scammer_message": "test"})
            assert result["confidence_score"] == 1.0

    # ── _format_recent_messages ───────────────────────────────────────────────

    def test_format_empty_messages(self):
        from core.nodes import _format_recent_messages
        result = _format_recent_messages([])
        assert "(conversation just started)" in result

    def test_format_langchain_message_objects(self):
        from core.nodes import _format_recent_messages
        from langchain_core.messages import HumanMessage, AIMessage
        msgs = [HumanMessage(content="hello scammer"), AIMessage(content="acha bhai")]
        result = _format_recent_messages(msgs)
        assert "SCAMMER: hello scammer" in result
        assert "BOT: acha bhai" in result

    def test_format_dict_messages(self):
        from core.nodes import _format_recent_messages
        msgs = [
            {"type": "human", "content": "send me money"},
            {"type": "ai", "content": "acha ji"},
        ]
        result = _format_recent_messages(msgs)
        assert "SCAMMER" in result
        assert "BOT" in result

    def test_format_limits_to_n_messages(self):
        from core.nodes import _format_recent_messages
        from langchain_core.messages import HumanMessage
        msgs = [HumanMessage(content=f"msg {i}") for i in range(20)]
        result = _format_recent_messages(msgs, n=4)
        # Should only contain last 4 messages
        assert "msg 16" in result
        assert "msg 19" in result
        assert "msg 0" not in result


# ══════════════════════════════════════════════════════════════════════════════
# TestGraph
# ══════════════════════════════════════════════════════════════════════════════

class TestGraph:

    def test_graph_compiles_with_memory(self):
        from core.graph import build_graph
        g = build_graph(use_memory=True)
        assert g is not None

    def test_graph_compiles_without_memory(self):
        from core.graph import build_graph
        g = build_graph(use_memory=False)
        assert g is not None

    def test_graph_has_all_nodes(self):
        from core.graph import build_graph
        g = build_graph(use_memory=False)
        expected = {"__start__", "intake", "strategy", "persona", "extractor", "guard"}
        assert expected.issubset(set(g.nodes))

    def test_graph_singleton_imported(self):
        from core.graph import honeypot_graph
        assert honeypot_graph is not None


# ══════════════════════════════════════════════════════════════════════════════
# TestDatabase
# ══════════════════════════════════════════════════════════════════════════════

class TestDatabase:
    """Test document schema validation — no real MongoDB needed."""

    def test_session_document_defaults(self):
        from core.database import SessionDocument
        doc = SessionDocument(session_id="TEST01")
        assert doc.status == "active"
        assert doc.total_turns == 0
        assert doc.intel == {}
        assert doc.turns == []

    def test_session_document_round_trip(self):
        from core.database import SessionDocument
        doc = SessionDocument(session_id="TEST01")
        dumped = doc.model_dump()
        restored = SessionDocument(**dumped)
        assert restored.session_id == "TEST01"
        assert restored.status == "active"

    def test_turn_document_validates(self):
        from core.database import TurnDocument
        t = TurnDocument(
            turn_number=1, timestamp="2026-01-01T00:00:00",
            scammer_message="hello", bot_response="acha",
            strategy_used="play_dumb", persona_used="naive_victim",
            scam_type="upi_fraud", threat_level="high",
            intel_yield_at_turn=0.3, new_intel_found={"upi_ids": ["a@oksbi"]},
        )
        assert t.turn_number == 1
        assert t.strategy_used == "play_dumb"

    def test_intel_event_document_validates(self):
        from core.database import IntelEventDocument
        ev = IntelEventDocument(
            session_id="TEST01", turn_number=2, scam_type="phishing",
            upi_ids_found=["x@gpay"], phones_found=["9876543210"],
        )
        assert ev.session_id == "TEST01"
        assert ev.upi_ids_found == ["x@gpay"]

    def test_scam_archive_document_validates(self):
        from core.database import ScamArchiveDocument
        doc = ScamArchiveDocument(identifier="scam@oksbi", identifier_type="upi_id")
        assert doc.times_seen == 1
        assert doc.session_ids == []

    def test_score_intel_called_in_database_context(self):
        # Ensure the _score_intel function works with the intel dict format DB uses
        from core.nodes import _score_intel
        from core.state import ExtractedIntel
        intel_dict = {"upi_ids": ["a@oksbi"], "phone_numbers": [], "bank_names": [],
                      "account_numbers": [], "ifsc_codes": [], "urls": [], "names": []}
        intel_obj = ExtractedIntel(**intel_dict)
        assert _score_intel(intel_obj) == 0.3


# ══════════════════════════════════════════════════════════════════════════════
# TestSessionManager
# ══════════════════════════════════════════════════════════════════════════════

class TestSessionManager:

    def test_session_created_with_unique_id(self):
        from core.session_manager import HoneypotSession
        s1 = HoneypotSession()
        s2 = HoneypotSession()
        assert s1.session_id != s2.session_id

    def test_session_starts_active(self):
        from core.session_manager import HoneypotSession
        s = HoneypotSession()
        assert s.is_active is True

    def test_session_get_summary_empty(self):
        from core.session_manager import HoneypotSession
        s = HoneypotSession()
        summary = s.get_summary()
        assert summary["session_id"] == s.session_id
        assert summary["turns"] == 0
        assert summary["intel_yield"] == 0.0

    def test_delta_all_new(self):
        from core.session_manager import HoneypotSession
        from core.state import ExtractedIntel
        s = HoneypotSession()
        current = ExtractedIntel(upi_ids=["a@oksbi"], phone_numbers=["9876543210"])
        delta = s._delta(current)
        assert delta["upi_ids"] == ["a@oksbi"]
        assert delta["phone_numbers"] == ["9876543210"]

    def test_delta_nothing_new(self):
        from core.session_manager import HoneypotSession
        from core.state import ExtractedIntel
        s = HoneypotSession()
        s._prev_intel = ExtractedIntel(upi_ids=["a@oksbi"])
        current = ExtractedIntel(upi_ids=["a@oksbi"])  # same as before
        delta = s._delta(current)
        assert delta["upi_ids"] == []

    def test_delta_incremental(self):
        from core.session_manager import HoneypotSession
        from core.state import ExtractedIntel
        s = HoneypotSession()
        s._prev_intel = ExtractedIntel(upi_ids=["a@oksbi"])
        current = ExtractedIntel(upi_ids=["a@oksbi", "b@paytm"])  # b is new
        delta = s._delta(current)
        assert delta["upi_ids"] == ["b@paytm"]

    def test_session_registry_create(self):
        from core.session_manager import SessionRegistry
        reg = SessionRegistry()
        # Registry.create_session is async — test sync wrapper
        session = reg._sessions  # starts empty
        assert len(session) == 0

    def test_session_registry_active_count(self):
        from core.session_manager import SessionRegistry, HoneypotSession
        reg = SessionRegistry()
        s = HoneypotSession()
        reg._sessions[s.session_id] = s
        assert reg.active_count() == 1
        s.is_active = False
        assert reg.active_count() == 0

    def test_session_registry_remove_closed(self):
        from core.session_manager import SessionRegistry, HoneypotSession
        reg = SessionRegistry()
        s1 = HoneypotSession()
        s2 = HoneypotSession()
        s1.is_active = False
        reg._sessions[s1.session_id] = s1
        reg._sessions[s2.session_id] = s2
        reg.remove_closed()
        assert s1.session_id not in reg._sessions
        assert s2.session_id in reg._sessions

    def test_process_message_empty_string(self):
        """Empty message should return error dict without crashing."""
        from core.session_manager import HoneypotSession

        async def run():
            s = HoneypotSession()
            # No DB patch needed — USE_DB=false in test env, _persist() returns early
            result = await s.process_message("")
            return result

        result = asyncio.run(run())
        assert "error" in result
        assert result["session_active"] is True

    def test_process_message_closed_session(self):
        """Closed session should return error without calling graph."""
        from core.session_manager import HoneypotSession

        async def run():
            s = HoneypotSession()
            s.is_active = False
            result = await s.process_message("hello")
            return result

        result = asyncio.run(run())
        assert "error" in result
        assert result["session_active"] is False

    def test_process_message_preserves_email_recipient_count(self):
        from core.session_manager import HoneypotSession

        async def run():
            session = HoneypotSession()
            graph_result = {
                "bot_response": "Acha, samjha.", "should_continue": True,
                "turn_count": 1, "scam_type": "upi_fraud", "threat_level": "high",
                "engagement_strategy": "play_dumb", "persona": "naive_victim",
                "intel_yield_score": 0.3, "intel": {}, "model_used": "test-model",
                "report_path": "reports/report_TEST.txt", "report_sent": True,
                "email_recipient_count": 2,
            }
            with patch("core.session_manager.honeypot_graph.invoke", return_value=graph_result), \
                 patch.object(session, "_persist", new_callable=AsyncMock):
                return await session.process_message("Pay to this UPI ID")

        result = asyncio.run(run())
        assert result["email_recipient_count"] == 2