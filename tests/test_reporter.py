import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.reporter import (
    reporter_node,
    _complainant_from_env,
    _is_placeholder_email,
    _resolved_recipients,
    should_report,
    build_report,
    report_to_html,
    report_to_text,
    save_report,
    send_email,
)


@pytest.fixture(autouse=True)
def isolate_report_files(tmp_path, monkeypatch):
    from core import reporter

    monkeypatch.setattr(reporter, "_REPORTS_DIR", tmp_path / "reports")


class TestReporterCore:
    def test_report_files_use_per_test_temporary_directory(self, tmp_path):
        from core import reporter

        assert reporter._sent_log_path().parent == tmp_path / "reports"

    def test_should_report_no_identifiers(self):
        assert should_report({"upi_ids": [], "phone_numbers": []}, 0.9) is False

    def test_should_report_low_score(self):
        assert should_report({"upi_ids": ["abc@upi"]}, 0.7) is False

    def test_should_report_valid_case(self):
        intel = {"upi_ids": ["abc@upi"], "phone_numbers": ["9876543210"]}
        assert should_report(intel, 0.9, "high") is True
        assert should_report(intel, 0.9, "critical") is True
        assert should_report(intel, 0.9, "medium") is False

    def test_report_gate_suppresses_low_and_medium_threats(self):
        state = {
            "scam_type": "phishing",
            "threat_level": "medium",
            "confidence_score": 0.99,
            "intel": {"upi_ids": ["abc@upi"]},
        }

        out = reporter_node(state)

        assert out["report_status"] == "below_threat_threshold"
        assert out["report_path"] == ""

    def test_direct_email_send_rejects_medium_threat(self):
        report = {
            "threat_level": "medium",
            "complainant": {
                "name": "Test User",
                "phone": "11111",
                "email": "user@complainant.test",
            },
        }
        with patch("core.reporter._rate_limit_reached", return_value=False), patch("smtplib.SMTP") as smtp_cls:
            assert send_email(report) is False
            smtp_cls.assert_not_called()

    def test_should_report_ignores_bot_only_identifiers(self):
        intel = {"raw_snippets": ["Bot said abc@upi", "Bot said 9876543210"], "upi_ids": [], "phone_numbers": []}
        assert should_report(intel, 0.9) is False

    def test_build_report_and_text_include_identifiers(self):
        intel = {"upi_ids": ["abc@upi"], "phone_numbers": ["9876543210"], "urls": ["https://scam.test"]}
        transcript = [
            {"role": "scammer", "content": "Send 9876543210"},
            {"role": "bot", "content": "I will send to abc@upi"},
        ]
        report = build_report("S123", intel, transcript)
        text = report_to_text(report)
        assert "abc@upi" in report["intel"]["upi_ids"][0]
        assert "9876543210" in text
        assert "https://scam.test" in text

    def test_professional_report_includes_assessment_evidence_and_review_notice(self):
        report = build_report(
            "CASE123",
            {"upi_ids": ["abc@upi"], "phone_numbers": [], "urls": [], "account_numbers": [], "ifsc_codes": [], "bank_names": ["SBI"], "names": []},
            [{"role": "scammer", "content": "Pay to abc@upi"}],
            scam_type="upi_fraud",
            threat_level="high",
            confidence_score=0.92,
            scam_indicators=["UPI/payment transfer request"],
        )

        text = report_to_text(report)
        assert "DIGITAL FRAUD INCIDENT REPORT" in text
        assert "Classification: UPI Fraud" in text
        assert "Threat level: High" in text
        assert "Assessment confidence: 92%" in text
        assert "EVIDENCE REGISTER" in text
        assert "abc@upi" in text
        assert "human reviewer must validate" in text

    def test_save_report_returns_html_and_keeps_machine_readable_copies(self):
        report = build_report(
            "CASEHTML",
            {"upi_ids": ["account@upi"]},
            [{"role": "scammer", "content": "Pay account@upi"}],
            scam_type="upi_fraud",
            threat_level="high",
            confidence_score=0.9,
        )

        html_path = save_report(report)

        assert html_path.name == "report_CASEHTML.html"
        assert "Digital Fraud Incident Report" in html_path.read_text(encoding="utf-8")
        assert html_path.with_suffix(".json").is_file()
        assert html_path.with_suffix(".txt").is_file()

    def test_reporter_status_explains_missing_actionable_evidence(self):
        out = reporter_node({"intel": {}, "confidence_score": 0.99, "threat_level": "high"})

        assert out["report_status"] == "awaiting_evidence"
        assert out["report_path"] == ""

    def test_reporter_status_explains_below_threshold_confidence(self):
        out = reporter_node({
            "intel": {"upi_ids": ["abc@upi"]},
            "confidence_score": 0.2,
            "threat_level": "high",
        })

        assert out["report_status"] == "awaiting_confidence"
        assert out["report_path"] == ""

    def test_high_confidence_classification_saves_draft_without_identifiers(self):
        state = {
            "session_id": "S123",
            "scam_type": "phishing",
            "threat_level": "high",
            "confidence_score": 0.92,
            "scam_indicators": ["Requests an ATM card PIN"],
            "intel": {},
            "messages": [{"type": "human", "content": "Share your ATM card PIN now"}],
        }
        with patch("core.reporter.save_report", return_value=Path("reports/report_S123.txt")) as save_mock, patch("core.reporter.send_email") as send_mock, patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {"REPORT_MIN_SCORE": "0.8", "AUTO_REPORT": "send"}.get(key, default)):
            out = reporter_node(state)

        assert Path(out["report_path"]).name == "report_S123.txt"
        assert out["report_status"] == "draft_saved_waiting_evidence"
        assert out["report_sent"] is False
        save_mock.assert_called_once()
        send_mock.assert_not_called()

    def test_build_report_includes_complainant_metadata(self):
        intel = {"upi_ids": ["abc@upi"], "phone_numbers": ["9876543210"], "urls": []}
        transcript = [{"role": "scammer", "content": "Send 9876543210"}]
        with patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "COMPLAINANT_NAME": "Asha Verma",
            "COMPLAINANT_PHONE": "+91 11111 11111",
            "COMPLAINANT_EMAIL": "asha@complainant.test",
        }.get(key, default)):
            report = build_report("S123", intel, transcript)
        text = report_to_text(report)
        assert report["complainant"]["name"] == "Asha Verma"
        assert report["complainant"]["phone"] == "+91 11111 11111"
        assert report["complainant"]["email"] == "asha@complainant.test"
        assert "Asha Verma" in text
        assert "asha@complainant.test" in text

    def test_sample_complainant_defaults_are_omitted(self):
        with patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "COMPLAINANT_NAME": "Jane Doe",
            "COMPLAINANT_PHONE": "+91 98765 43210",
            "COMPLAINANT_EMAIL": "jane.doe@example.com",
        }.get(key, default)):
            assert _complainant_from_env() == {}

    def test_example_copy_address_is_not_a_send_recipient(self):
        with patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "REPORT_TEST_MODE": "true",
            "REPORT_COPY_TO_SELF": "you@example.com",
        }.get(key, default)):
            assert _is_placeholder_email("you@example.com")
            assert _resolved_recipients({}) == []

    def test_html_report_escapes_untrusted_content(self):
        report = build_report(
            "CASE123",
            {"upi_ids": [], "phone_numbers": [], "urls": [], "account_numbers": [], "ifsc_codes": [], "bank_names": [], "names": []},
            [{"role": "scammer", "content": "<script>alert('x')</script>"}],
            scam_type="phishing",
            threat_level="high",
        )

        rendered = report_to_html(report)
        assert "Digital Fraud Incident Report" in rendered
        assert "<script>alert" not in rendered
        assert "&lt;script&gt;" in rendered

    def test_report_to_text_handles_missing_complainant(self):
        report = {"session_id": "S123", "generated_at": "2024-01-01Z", "intel": {}, "transcript": []}
        text = report_to_text(report)
        assert "Complainant:" not in text

    def test_reporter_node_dedupe_same_intel(self):
        state = {
            "session_id": "S123",
            "intel": {"upi_ids": ["abc@upi"], "phone_numbers": ["9876543210"], "urls": [], "account_numbers": [], "ifsc_codes": [], "bank_names": [], "names": [], "raw_snippets": []},
            "messages": [{"type": "human", "content": "send to abc@upi"}],
            "confidence_score": 0.9,
            "threat_level": "high",
            "last_reported_fp": "",
            "report_path": "",
            "report_sent": False,
            "report_error": "",
        }
        with patch("core.reporter.save_report", return_value=Path("reports/report_S123.txt")) as save_mock, patch("core.reporter.send_email", return_value=True) as send_mock, patch("core.reporter._rate_limit_reached", return_value=False), patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "AUTO_REPORT": "send",
            "REPORT_MIN_SCORE": "0.8",
            "REPORT_RECIPIENTS": "fraud@authority.test",
            "REPORT_COPY_TO_SELF": "me@copy.test",
            "REPORT_TEST_MODE": "false",
            "COMPLAINANT_NAME": "Asha Verma",
            "COMPLAINANT_PHONE": "+91 11111 11111",
            "COMPLAINANT_EMAIL": "asha@complainant.test",
        }.get(key, default)):
            first = reporter_node(state)
            second = reporter_node({**first, "last_reported_fp": first["last_reported_fp"]})
        assert save_mock.call_count == 2
        assert send_mock.call_count == 1
        assert first["report_sent"] is True
        assert second["report_sent"] is False

    def test_send_email_uses_smtp(self):
        report = {
            "session_id": "S123",
            "scam_type": "upi_fraud",
            "threat_level": "high",
            "email_recipients": ["fraud@authority.test"],
            "intel": {"upi_ids": ["abc@upi"]},
            "transcript": [{"role": "scammer", "content": "send me abc@upi"}],
            "report_fingerprint": "abc",
            "complainant": {
                "name": "Asha Verma",
                "phone": "+91 11111 11111",
                "email": "asha@complainant.test",
            },
        }
        with patch("core.reporter._rate_limit_reached", return_value=False), patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "REPORT_RECIPIENTS": "fraud@authority.test, cyber@authority.test",
            "REPORT_COPY_TO_SELF": "me@copy.test",
            "REPORT_TEST_MODE": "false",
            "REPORT_MAX_PER_HOUR": "5",
            "SMTP_HOST": "smtp.example.com",
            "SMTP_PORT": "587",
            "SMTP_USER": "user@smtp.test",
            "SMTP_PASS": "secret",
            "AUTO_REPORT": "send",
        }.get(key, default)), patch("smtplib.SMTP") as smtp_cls:
            smtp = smtp_cls.return_value
            assert send_email(report) is True
            smtp.starttls.assert_called_once()
            smtp.login.assert_called_once_with("user@smtp.test", "secret")
            smtp.send_message.assert_called_once()

    def test_send_email_test_mode_only_sends_to_copy(self):
        report = {
            "session_id": "S123",
            "scam_type": "upi_fraud",
            "threat_level": "high",
            "email_recipients": ["fraud@authority.test", "cyber@authority.test"],
            "intel": {"upi_ids": ["abc@upi"]},
            "transcript": [{"role": "scammer", "content": "send me abc@upi"}],
            "report_fingerprint": "abc",
            "complainant": {
                "name": "Asha Verma",
                "phone": "+91 11111 11111",
                "email": "asha@complainant.test",
            },
        }
        with patch("core.reporter._rate_limit_reached", return_value=False), patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "REPORT_RECIPIENTS": "fraud@authority.test, cyber@authority.test",
            "REPORT_COPY_TO_SELF": "me@copy.test",
            "REPORT_TEST_MODE": "true",
            "REPORT_MAX_PER_HOUR": "5",
            "SMTP_HOST": "smtp.example.com",
            "SMTP_PORT": "587",
            "SMTP_USER": "user@smtp.test",
            "SMTP_PASS": "secret",
            "AUTO_REPORT": "send",
        }.get(key, default)), patch("smtplib.SMTP") as smtp_cls:
            smtp = smtp_cls.return_value
            assert send_email(report) is True
            sent_msg = smtp.send_message.call_args[0][0]
            assert sent_msg["Subject"].startswith("[TEST] Scam report - upi_fraud - session S123")
            assert sent_msg["To"] == "me@copy.test"

    def test_send_email_real_mode_sends_recipients_plus_copy(self):
        report = {
            "session_id": "S123",
            "scam_type": "phishing",
            "threat_level": "critical",
            "email_recipients": ["fraud@authority.test"],
            "intel": {"upi_ids": ["abc@upi"]},
            "transcript": [{"role": "scammer", "content": "send me abc@upi"}],
            "report_fingerprint": "abc",
            "complainant": {
                "name": "Asha Verma",
                "phone": "+91 11111 11111",
                "email": "asha@complainant.test",
            },
        }
        with patch("core.reporter._rate_limit_reached", return_value=False), patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "REPORT_RECIPIENTS": "fraud@authority.test,cyber@authority.test",
            "REPORT_COPY_TO_SELF": "me@copy.test",
            "REPORT_TEST_MODE": "false",
            "REPORT_MAX_PER_HOUR": "5",
            "SMTP_HOST": "smtp.example.com",
            "SMTP_PORT": "587",
            "SMTP_USER": "user@smtp.test",
            "SMTP_PASS": "secret",
            "AUTO_REPORT": "send",
        }.get(key, default)), patch("smtplib.SMTP") as smtp_cls:
            smtp = smtp_cls.return_value
            assert send_email(report) is True
            sent_msg = smtp.send_message.call_args[0][0]
            assert "fraud@authority.test" in sent_msg["To"]
            assert "cyber@authority.test" in sent_msg["To"]
            assert "me@copy.test" in sent_msg["To"]

    def test_send_email_invalid_addresses_skip_and_no_valid_recipients(self):
        report = {
            "session_id": "S123",
            "scam_type": "upi_fraud",
            "threat_level": "high",
            "email_recipients": ["bad-address"],
            "intel": {"upi_ids": ["abc@upi"]},
            "transcript": [{"role": "scammer", "content": "send me abc@upi"}],
            "report_fingerprint": "abc",
            "complainant": {
                "name": "Asha Verma",
                "phone": "+91 11111 11111",
                "email": "asha@complainant.test",
            },
        }
        with patch("core.reporter._rate_limit_reached", return_value=False), patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "REPORT_RECIPIENTS": "bad-address",
            "REPORT_COPY_TO_SELF": "",
            "REPORT_TEST_MODE": "false",
            "REPORT_MAX_PER_HOUR": "5",
            "SMTP_HOST": "smtp.example.com",
            "SMTP_PORT": "587",
            "SMTP_USER": "user@smtp.test",
            "SMTP_PASS": "secret",
            "AUTO_REPORT": "send",
        }.get(key, default)), patch("smtplib.SMTP") as smtp_cls:
            assert send_email(report) is False
            smtp_cls.assert_not_called()

    def test_reporter_node_sets_error_when_no_valid_recipients(self):
        state = {
            "session_id": "S123",
            "scam_type": "upi_fraud",
            "threat_level": "high",
            "intel": {"upi_ids": ["abc@upi"], "phone_numbers": ["9876543210"], "urls": [], "account_numbers": [], "ifsc_codes": [], "bank_names": [], "names": [], "raw_snippets": []},
            "messages": [{"type": "human", "content": "send to abc@upi"}],
            "confidence_score": 0.9,
            "last_reported_fp": "",
            "report_path": "",
            "report_sent": False,
            "report_error": "",
            "complainant": {"name": "Asha Verma", "phone": "+91 11111 11111", "email": "asha@complainant.test"},
        }
        with patch("core.reporter.save_report", return_value=Path("reports/report_S123.txt")), patch("core.reporter._rate_limit_reached", return_value=False), patch("core.reporter.send_email", return_value=False) as send_mock, patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "AUTO_REPORT": "send",
            "REPORT_MIN_SCORE": "0.8",
            "REPORT_RECIPIENTS": "bad-address",
            "REPORT_COPY_TO_SELF": "",
            "REPORT_TEST_MODE": "false",
            "REPORT_MAX_PER_HOUR": "5",
            "COMPLAINANT_NAME": "Asha Verma",
            "COMPLAINANT_PHONE": "+91 11111 11111",
            "COMPLAINANT_EMAIL": "asha@complainant.test",
        }.get(key, default)):
            out = reporter_node(state)
            assert out["report_error"] == "No valid recipients"
            assert out["report_sent"] is False
            send_mock.assert_not_called()

    def test_reporter_node_sets_rate_limit_error(self):
        state = {
            "session_id": "S123",
            "scam_type": "upi_fraud",
            "threat_level": "high",
            "intel": {"upi_ids": ["abc@upi"], "phone_numbers": ["9876543210"], "urls": [], "account_numbers": [], "ifsc_codes": [], "bank_names": [], "names": [], "raw_snippets": []},
            "messages": [{"type": "human", "content": "send to abc@upi"}],
            "confidence_score": 0.9,
            "last_reported_fp": "",
            "report_path": "",
            "report_sent": False,
            "report_error": "",
            "complainant": {"name": "Asha Verma", "phone": "+91 11111 11111", "email": "asha@complainant.test"},
        }
        with patch("core.reporter.save_report", return_value=Path("reports/report_S123.txt")), patch("core.reporter._rate_limit_reached", return_value=True), patch("core.reporter.send_email", side_effect=Exception("should not send")) as send_mock, patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "AUTO_REPORT": "send",
            "REPORT_MIN_SCORE": "0.8",
            "REPORT_RECIPIENTS": "fraud@authority.test",
            "REPORT_COPY_TO_SELF": "me@copy.test",
            "REPORT_TEST_MODE": "false",
            "REPORT_MAX_PER_HOUR": "0",
            "COMPLAINANT_NAME": "Asha Verma",
            "COMPLAINANT_PHONE": "+91 11111 11111",
            "COMPLAINANT_EMAIL": "asha@complainant.test",
        }.get(key, default)):
            out = reporter_node(state)
            assert out["report_error"] == "Rate limit reached"
            assert out["report_sent"] is False
            send_mock.assert_not_called()

    def test_send_email_includes_attachments(self):
        report = {
            "session_id": "S123",
            "scam_type": "upi_fraud",
            "threat_level": "high",
            "email_recipients": ["fraud@authority.test"],
            "intel": {"upi_ids": ["abc@upi"]},
            "transcript": [{"role": "scammer", "content": "send me abc@upi"}],
            "report_fingerprint": "abc",
            "complainant": {
                "name": "Asha Verma",
                "phone": "+91 11111 11111",
                "email": "asha@complainant.test",
            },
        }
        with patch("core.reporter._rate_limit_reached", return_value=False), patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "REPORT_RECIPIENTS": "fraud@authority.test",
            "REPORT_COPY_TO_SELF": "me@copy.test",
            "REPORT_TEST_MODE": "false",
            "REPORT_MAX_PER_HOUR": "5",
            "SMTP_HOST": "smtp.example.com",
            "SMTP_PORT": "587",
            "SMTP_USER": "user@smtp.test",
            "SMTP_PASS": "secret",
            "AUTO_REPORT": "send",
        }.get(key, default)), patch("smtplib.SMTP") as smtp_cls:
            assert send_email(report) is True
            msg = smtp_cls.return_value.send_message.call_args[0][0]
            attachment_names = [part.get_filename() for part in msg.iter_attachments()]
            assert "evidence_S123.json" in attachment_names
            assert "report_S123.html" in attachment_names
            html_part = next(
                part for part in msg.walk()
                if part.get_content_type() == "text/html" and not part.get_filename()
            )
            assert "Digital Fraud Incident Report" in html_part.get_content()

    def test_reporter_node_draft_mode_skips_smtp(self):
        state = {
            "session_id": "S123",
            "intel": {"upi_ids": ["abc@upi"], "phone_numbers": [], "urls": [], "account_numbers": [], "ifsc_codes": [], "bank_names": [], "names": [], "raw_snippets": []},
            "threat_level": "high",
            "messages": [{"type": "human", "content": "send to abc@upi"}],
            "confidence_score": 0.9,
            "last_reported_fp": "",
            "report_path": "",
            "report_sent": False,
            "report_error": "",
        }
        with patch("core.reporter.save_report", return_value=Path("reports/report_S123.txt")), patch("core.reporter.send_email", return_value=True) as send_mock, patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "AUTO_REPORT": "draft",
            "REPORT_MIN_SCORE": "0.8",
            "REPORT_RECIPIENTS": "fraud@example.com",
        }.get(key, default)):
            out = reporter_node(state)
            assert out["report_sent"] is False
            assert out["report_path"]
            assert out["report_status"] == "draft_saved"
            send_mock.assert_not_called()

    def test_reporter_node_send_mode_failure_sets_error(self):
        state = {
            "session_id": "S123",
            "intel": {"upi_ids": ["abc@upi"], "phone_numbers": [], "urls": [], "account_numbers": [], "ifsc_codes": [], "bank_names": [], "names": [], "raw_snippets": []},
            "threat_level": "high",
            "messages": [{"type": "human", "content": "send to abc@upi"}],
            "confidence_score": 0.9,
            "last_reported_fp": "",
            "report_path": "",
            "report_sent": False,
            "report_error": "",
        }
        with patch("core.reporter.save_report", return_value=Path("reports/report_S123.txt")), patch("core.reporter.send_email", side_effect=Exception("SMTP down")), patch("core.reporter._complainant_is_complete", return_value=True), patch("core.reporter._resolved_recipients", return_value=["test@example.com"]), patch("core.reporter._rate_limit_reached", return_value=False), patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "AUTO_REPORT": "send",
            "REPORT_MIN_SCORE": "0.8",
            "REPORT_RECIPIENTS": "fraud@example.com",
        }.get(key, default)):
            out = reporter_node(state)
            assert out["report_error"]
            assert out["report_sent"] is False
            assert out["report_status"] == "email_failed"
