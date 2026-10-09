#!/usr/bin/env python3
"""Run a tiny sample report-generation flow without exposing secrets."""

import os

from dotenv import load_dotenv

from core.reporter import reporter_node

load_dotenv()

state = {
    "session_id": "sample_session",
    "scam_type": "upi_fraud",
    "confidence_score": 0.95,
    "intel": {
        "upi_ids": ["abc@upi"],
        "phone_numbers": ["9876543210"],
        "account_numbers": ["1234567890"],
        "ifsc_codes": ["SBIN0001234"],
        "urls": ["https://scam.example/verify"],
        "bank_names": ["State Bank of India"],
        "names": ["Fake Support"],
        "raw_snippets": ["Call me at 9876543210"],
    },
    "messages": [
        {"type": "human", "content": "I received a message telling me to send money to abc@upi."},
        {"type": "bot", "content": "I can help investigate that link and number."},
    ],
    "report_path": "",
    "report_sent": False,
    "report_error": "",
}

result = reporter_node(state)
print(f"score={result.get('confidence_score', 0.0)}")
print(f"report_sent={bool(result.get('report_sent'))}")
print(f"report_path={result.get('report_path') or 'none'}")
print(f"report_error={result.get('report_error') or 'none'}")

if result.get("report_path"):
    print("sample report generated locally.")
