#!/usr/bin/env python3
"""Smoke-test the configured Gmail SMTP account in test mode."""

import os
import smtplib
from email.message import EmailMessage

from dotenv import load_dotenv


def main() -> None:
    load_dotenv()

    smtp_host = (os.getenv("SMTP_HOST") or "").strip()
    smtp_port = int((os.getenv("SMTP_PORT") or "587").strip() or "587")
    smtp_user = (os.getenv("SMTP_USER") or "").strip()
    smtp_pass = (os.getenv("SMTP_PASS") or "").strip()
    report_copy_to_self = (os.getenv("REPORT_COPY_TO_SELF") or "").strip()
    report_test_mode = str(os.getenv("REPORT_TEST_MODE", "true")).strip().lower() == "true"

    if not smtp_host or not smtp_user or not smtp_pass:
        print("SMTP is not configured. Fill SMTP_PASS in .env and set SMTP_USER/SMTP_HOST first.")
        raise SystemExit(1)

    if not report_copy_to_self:
        print("REPORT_COPY_TO_SELF is empty. Set it in .env before running this test.")
        raise SystemExit(1)

    if not report_test_mode:
        print("REPORT_TEST_MODE is disabled. Set REPORT_TEST_MODE=true to use the Gmail test path.")
        raise SystemExit(1)

    msg = EmailMessage()
    msg["Subject"] = "[TEST] Gmail SMTP connectivity check"
    msg["From"] = smtp_user
    msg["To"] = report_copy_to_self
    msg.set_content(
        "This is a test message from the scam-baiting project. "
        "If you receive it, the Gmail SMTP setup is working in TEST mode."
    )

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)

    print(f"Test email sent successfully to {report_copy_to_self}.")


if __name__ == "__main__":
    main()
