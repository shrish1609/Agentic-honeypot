import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.reporter import (
    reporter_node,
    should_report,
    build_report,
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
        assert should_report({"upi_ids": ["abc@upi"], "phone_numbers": ["9876543210"]}, 0.9) is True

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

    def test_build_report_includes_complainant_metadata(self):
        intel = {"upi_ids": ["abc@upi"], "phone_numbers": ["9876543210"], "urls": []}
        transcript = [{"role": "scammer", "content": "Send 9876543210"}]
        with patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "COMPLAINANT_NAME": "Asha Verma",
            "COMPLAINANT_PHONE": "+91 98765 43210",
            "COMPLAINANT_EMAIL": "asha@example.com",
        }.get(key, default)):
            report = build_report("S123", intel, transcript)
        text = report_to_text(report)
        assert report["complainant"]["name"] == "Asha Verma"
        assert report["complainant"]["phone"] == "+91 98765 43210"
        assert report["complainant"]["email"] == "asha@example.com"
        assert "Asha Verma" in text
        assert "asha@example.com" in text

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
            "last_reported_fp": "",
            "report_path": "",
            "report_sent": False,
            "report_error": "",
        }
        with patch("core.reporter.save_report", return_value=Path("reports/report_S123.txt")) as save_mock, patch("core.reporter.send_email", return_value=True) as send_mock, patch("core.reporter._rate_limit_reached", return_value=False), patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "AUTO_REPORT": "send",
            "REPORT_MIN_SCORE": "0.8",
            "REPORT_RECIPIENTS": "fraud@example.com",
            "REPORT_COPY_TO_SELF": "me@example.com",
            "REPORT_TEST_MODE": "false",
            "COMPLAINANT_NAME": "Asha Verma",
            "COMPLAINANT_PHONE": "+91 98765 43210",
            "COMPLAINANT_EMAIL": "asha@example.com",
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
            "email_recipients": ["fraud@example.com"],
            "intel": {"upi_ids": ["abc@upi"]},
            "transcript": [{"role": "scammer", "content": "send me abc@upi"}],
            "report_fingerprint": "abc",
            "complainant": {
                "name": "Asha Verma",
                "phone": "+91 98765 43210",
                "email": "asha@example.com",
            },
        }
        with patch("core.reporter._rate_limit_reached", return_value=False), patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "REPORT_RECIPIENTS": "fraud@example.com, cyber@example.com",
            "REPORT_COPY_TO_SELF": "me@example.com",
            "REPORT_TEST_MODE": "false",
            "REPORT_MAX_PER_HOUR": "5",
            "SMTP_HOST": "smtp.example.com",
            "SMTP_PORT": "587",
            "SMTP_USER": "user@example.com",
            "SMTP_PASS": "secret",
            "AUTO_REPORT": "send",
        }.get(key, default)), patch("smtplib.SMTP") as smtp_cls:
            smtp = smtp_cls.return_value
            assert send_email(report) is True
            smtp.starttls.assert_called_once()
            smtp.login.assert_called_once_with("user@example.com", "secret")
            smtp.send_message.assert_called_once()

    def test_send_email_test_mode_only_sends_to_copy(self):
        report = {
            "session_id": "S123",
            "scam_type": "upi_fraud",
            "email_recipients": ["fraud@example.com", "cyber@example.com"],
            "intel": {"upi_ids": ["abc@upi"]},
            "transcript": [{"role": "scammer", "content": "send me abc@upi"}],
            "report_fingerprint": "abc",
            "complainant": {
                "name": "Asha Verma",
                "phone": "+91 98765 43210",
                "email": "asha@example.com",
            },
        }
        with patch("core.reporter._rate_limit_reached", return_value=False), patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "REPORT_RECIPIENTS": "fraud@example.com, cyber@example.com",
            "REPORT_COPY_TO_SELF": "me@example.com",
            "REPORT_TEST_MODE": "true",
            "REPORT_MAX_PER_HOUR": "5",
            "SMTP_HOST": "smtp.example.com",
            "SMTP_PORT": "587",
            "SMTP_USER": "user@example.com",
            "SMTP_PASS": "secret",
            "AUTO_REPORT": "send",
        }.get(key, default)), patch("smtplib.SMTP") as smtp_cls:
            smtp = smtp_cls.return_value
            assert send_email(report) is True
            sent_msg = smtp.send_message.call_args[0][0]
            assert sent_msg["Subject"].startswith("[TEST] Scam report - upi_fraud - session S123")
            assert sent_msg["To"] == "me@example.com"

    def test_send_email_real_mode_sends_recipients_plus_copy(self):
        report = {
            "session_id": "S123",
            "scam_type": "phishing",
            "email_recipients": ["fraud@example.com"],
            "intel": {"upi_ids": ["abc@upi"]},
            "transcript": [{"role": "scammer", "content": "send me abc@upi"}],
            "report_fingerprint": "abc",
            "complainant": {
                "name": "Asha Verma",
                "phone": "+91 98765 43210",
                "email": "asha@example.com",
            },
        }
        with patch("core.reporter._rate_limit_reached", return_value=False), patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "REPORT_RECIPIENTS": "fraud@example.com,cyber@example.com",
            "REPORT_COPY_TO_SELF": "me@example.com",
            "REPORT_TEST_MODE": "false",
            "REPORT_MAX_PER_HOUR": "5",
            "SMTP_HOST": "smtp.example.com",
            "SMTP_PORT": "587",
            "SMTP_USER": "user@example.com",
            "SMTP_PASS": "secret",
            "AUTO_REPORT": "send",
        }.get(key, default)), patch("smtplib.SMTP") as smtp_cls:
            smtp = smtp_cls.return_value
            assert send_email(report) is True
            sent_msg = smtp.send_message.call_args[0][0]
            assert "fraud@example.com" in sent_msg["To"]
            assert "cyber@example.com" in sent_msg["To"]
            assert "me@example.com" in sent_msg["To"]

    def test_send_email_invalid_addresses_skip_and_no_valid_recipients(self):
        report = {
            "session_id": "S123",
            "scam_type": "upi_fraud",
            "email_recipients": ["bad-address"],
            "intel": {"upi_ids": ["abc@upi"]},
            "transcript": [{"role": "scammer", "content": "send me abc@upi"}],
            "report_fingerprint": "abc",
            "complainant": {
                "name": "Asha Verma",
                "phone": "+91 98765 43210",
                "email": "asha@example.com",
            },
        }
        with patch("core.reporter._rate_limit_reached", return_value=False), patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "REPORT_RECIPIENTS": "bad-address",
            "REPORT_COPY_TO_SELF": "",
            "REPORT_TEST_MODE": "false",
            "REPORT_MAX_PER_HOUR": "5",
            "SMTP_HOST": "smtp.example.com",
            "SMTP_PORT": "587",
            "SMTP_USER": "user@example.com",
            "SMTP_PASS": "secret",
            "AUTO_REPORT": "send",
        }.get(key, default)), patch("smtplib.SMTP") as smtp_cls:
            assert send_email(report) is False
            smtp_cls.assert_not_called()

    def test_reporter_node_sets_error_when_no_valid_recipients(self):
        state = {
            "session_id": "S123",
            "scam_type": "upi_fraud",
            "intel": {"upi_ids": ["abc@upi"], "phone_numbers": ["9876543210"], "urls": [], "account_numbers": [], "ifsc_codes": [], "bank_names": [], "names": [], "raw_snippets": []},
            "messages": [{"type": "human", "content": "send to abc@upi"}],
            "confidence_score": 0.9,
            "last_reported_fp": "",
            "report_path": "",
            "report_sent": False,
            "report_error": "",
            "complainant": {"name": "Asha Verma", "phone": "+91 98765 43210", "email": "asha@example.com"},
        }
        with patch("core.reporter.save_report", return_value=Path("reports/report_S123.txt")), patch("core.reporter._rate_limit_reached", return_value=False), patch("core.reporter.send_email", return_value=False) as send_mock, patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "AUTO_REPORT": "send",
            "REPORT_MIN_SCORE": "0.8",
            "REPORT_RECIPIENTS": "bad-address",
            "REPORT_COPY_TO_SELF": "",
            "REPORT_TEST_MODE": "false",
            "REPORT_MAX_PER_HOUR": "5",
            "COMPLAINANT_NAME": "Asha Verma",
            "COMPLAINANT_PHONE": "+91 98765 43210",
            "COMPLAINANT_EMAIL": "asha@example.com",
        }.get(key, default)):
            out = reporter_node(state)
            assert out["report_error"] == "No valid recipients"
            assert out["report_sent"] is False
            send_mock.assert_not_called()

    def test_reporter_node_sets_rate_limit_error(self):
        state = {
            "session_id": "S123",
            "scam_type": "upi_fraud",
            "intel": {"upi_ids": ["abc@upi"], "phone_numbers": ["9876543210"], "urls": [], "account_numbers": [], "ifsc_codes": [], "bank_names": [], "names": [], "raw_snippets": []},
            "messages": [{"type": "human", "content": "send to abc@upi"}],
            "confidence_score": 0.9,
            "last_reported_fp": "",
            "report_path": "",
            "report_sent": False,
            "report_error": "",
            "complainant": {"name": "Asha Verma", "phone": "+91 98765 43210", "email": "asha@example.com"},
        }
        with patch("core.reporter.save_report", return_value=Path("reports/report_S123.txt")), patch("core.reporter._rate_limit_reached", return_value=True), patch("core.reporter.send_email", side_effect=Exception("should not send")) as send_mock, patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "AUTO_REPORT": "send",
            "REPORT_MIN_SCORE": "0.8",
            "REPORT_RECIPIENTS": "fraud@example.com",
            "REPORT_COPY_TO_SELF": "me@example.com",
            "REPORT_TEST_MODE": "false",
            "REPORT_MAX_PER_HOUR": "0",
            "COMPLAINANT_NAME": "Asha Verma",
            "COMPLAINANT_PHONE": "+91 98765 43210",
            "COMPLAINANT_EMAIL": "asha@example.com",
        }.get(key, default)):
            out = reporter_node(state)
            assert out["report_error"] == "Rate limit reached"
            assert out["report_sent"] is False
            send_mock.assert_not_called()

    def test_send_email_includes_attachments(self):
        report = {
            "session_id": "S123",
            "scam_type": "upi_fraud",
            "email_recipients": ["fraud@example.com"],
            "intel": {"upi_ids": ["abc@upi"]},
            "transcript": [{"role": "scammer", "content": "send me abc@upi"}],
            "report_fingerprint": "abc",
            "complainant": {
                "name": "Asha Verma",
                "phone": "+91 98765 43210",
                "email": "asha@example.com",
            },
        }
        with patch("core.reporter._rate_limit_reached", return_value=False), patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "REPORT_RECIPIENTS": "fraud@example.com",
            "REPORT_COPY_TO_SELF": "me@example.com",
            "REPORT_TEST_MODE": "false",
            "REPORT_MAX_PER_HOUR": "5",
            "SMTP_HOST": "smtp.example.com",
            "SMTP_PORT": "587",
            "SMTP_USER": "user@example.com",
            "SMTP_PASS": "secret",
            "AUTO_REPORT": "send",
        }.get(key, default)), patch("smtplib.SMTP") as smtp_cls:
            assert send_email(report) is True
            msg = smtp_cls.return_value.send_message.call_args[0][0]
            attachment_names = [part.get_filename() for part in msg.iter_attachments()]
            assert "evidence_S123.json" in attachment_names
            assert "report_S123.txt" in attachment_names

    def test_reporter_node_draft_mode_skips_smtp(self):
        state = {
            "session_id": "S123",
            "intel": {"upi_ids": ["abc@upi"], "phone_numbers": [], "urls": [], "account_numbers": [], "ifsc_codes": [], "bank_names": [], "names": [], "raw_snippets": []},
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
            send_mock.assert_not_called()

    def test_reporter_node_send_mode_failure_sets_error(self):
        state = {
            "session_id": "S123",
            "intel": {"upi_ids": ["abc@upi"], "phone_numbers": [], "urls": [], "account_numbers": [], "ifsc_codes": [], "bank_names": [], "names": [], "raw_snippets": []},
            "messages": [{"type": "human", "content": "send to abc@upi"}],
            "confidence_score": 0.9,
            "last_reported_fp": "",
            "report_path": "",
            "report_sent": False,
            "report_error": "",
        }
        with patch("core.reporter.save_report", return_value=Path("reports/report_S123.txt")), patch("core.reporter.send_email", side_effect=Exception("SMTP down")), patch("core.reporter.os.getenv", side_effect=lambda key, default=None: {
            "AUTO_REPORT": "send",
            "REPORT_MIN_SCORE": "0.8",
            "REPORT_RECIPIENTS": "fraud@example.com",
        }.get(key, default)):
            out = reporter_node(state)
            assert out["report_error"]
            assert out["report_sent"] is False
