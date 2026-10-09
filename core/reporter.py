"""
core/reporter.py — Scam evidence reporting helpers.

Generates human-readable reports from extracted intel, saves them as JSON/TXT,
optionally sends them by SMTP, and is safe to run inside the graph without
breaking the chat loop.
"""

import hashlib
import json
import os
import re
import smtplib
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any

_IDENTIFIER_KEYS = (
    "upi_ids",
    "phone_numbers",
    "account_numbers",
    "ifsc_codes",
    "urls",
)
_REPORTS_DIR = Path("reports")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+91|91)?([6-9]\d{9})(?!\d)")


def _to_dict(state: Any) -> dict:
    if isinstance(state, dict):
        return state
    if hasattr(state, "model_dump"):
        return state.model_dump()
    return {}


def _safe_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if str(v).strip()]
    if isinstance(value, tuple):
        return [str(v) for v in value if str(v).strip()]
    if value is None:
        return []
    return [str(value)] if str(value).strip() else []


def _as_intel_dict(intel: Any) -> dict:
    if isinstance(intel, dict):
        out = {}
        for key in _IDENTIFIER_KEYS + ("bank_names", "names", "raw_snippets"):
            out[key] = _safe_list(intel.get(key, []))
        return out
    return {key: [] for key in _IDENTIFIER_KEYS + ("bank_names", "names", "raw_snippets")}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fingerprint(intel: dict) -> str:
    payload = json.dumps({k: sorted(v) for k, v in sorted(intel.items())}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _parse_recipients(raw: str) -> list[str]:
    if not raw:
        return []
    recipients = []
    for piece in raw.split(","):
        cleaned = piece.strip()
        if cleaned:
            recipients.append(cleaned)
    return recipients


def _valid_email(value: str) -> bool:
    if not isinstance(value, str):
        return False
    candidate = value.strip()
    return bool(candidate) and bool(_EMAIL_RE.fullmatch(candidate))


def _dedupe_emails(values: list[str] | tuple[str, ...] | str | None) -> list[str]:
    if isinstance(values, str):
        values = [values]
    seen = set()
    final = []
    for value in values or []:
        cleaned = str(value).strip()
        if not cleaned or not _valid_email(cleaned):
            continue
        if cleaned.lower() in seen:
            continue
        seen.add(cleaned.lower())
        final.append(cleaned)
    return final


def _complainant_is_complete(report: dict) -> bool:
    complainant = report.get("complainant") or {}
    if not isinstance(complainant, dict):
        return False
    return all(str(complainant.get(field, "")).strip() for field in ("name", "phone", "email"))


def _is_test_mode() -> bool:
    return str(os.getenv("REPORT_TEST_MODE", "true")).strip().lower() == "true"


def _sent_log_path() -> Path:
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return _REPORTS_DIR / ".sent_log.json"


def _load_sent_log() -> list[str]:
    path = _sent_log_path()
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (TypeError, ValueError):
        return []
    if isinstance(payload, list):
        return [str(item) for item in payload]
    return []


def _write_sent_log(entries: list[str]) -> None:
    path = _sent_log_path()
    path.write_text(json.dumps(entries, indent=2), encoding="utf-8")


def _rate_limit_reached() -> bool:
    max_per_hour = int((os.getenv("REPORT_MAX_PER_HOUR") or "5").strip() or "5")
    if max_per_hour <= 0:
        return True
    now = time.time()
    window = [float(ts) for ts in _load_sent_log() if now - float(ts) < 3600]
    return len(window) >= max_per_hour


def _record_send() -> None:
    now = str(time.time())
    entries = _load_sent_log()
    entries = [ts for ts in entries if time.time() - float(ts) < 3600]
    entries.append(now)
    _write_sent_log(entries)


def _resolved_recipients(report: dict) -> list[str]:
    env_recipients = _dedupe_emails(_parse_recipients(os.getenv("REPORT_RECIPIENTS", "")))
    report_recipients = _dedupe_emails(report.get("email_recipients") or [])
    recipients = env_recipients if env_recipients else report_recipients
    copy_self = _dedupe_emails(os.getenv("REPORT_COPY_TO_SELF", ""))

    if _is_test_mode():
        return copy_self

    for email in copy_self:
        if email not in recipients:
            recipients.append(email)
    return recipients


def redact(text: str, identifiers: list[str] | None = None) -> str:
    """Redact personal details that are not the scammer's identifiers."""
    if not isinstance(text, str):
        return text
    ids = {str(v).strip() for v in (identifiers or []) if str(v).strip()}

    def _replace_email(match):
        value = match.group(0)
        if value in ids:
            return value
        return "[REDACTED_EMAIL]"

    def _replace_phone(match):
        value = match.group(0)
        if value in ids:
            return value
        return "[REDACTED_PHONE]"

    redacted = _EMAIL_RE.sub(_replace_email, text)
    redacted = _PHONE_RE.sub(_replace_phone, redacted)
    return redacted


def _transcript_from_state(state: dict) -> list[dict]:
    transcript = []
    for msg in state.get("messages", []) or []:
        if hasattr(msg, "type") and hasattr(msg, "content"):
            transcript.append({"role": "human" if msg.type == "human" else "bot", "content": msg.content})
        elif isinstance(msg, dict):
            content = msg.get("content", "")
            role = msg.get("type", "bot")
            transcript.append({"role": "human" if role == "human" else "bot", "content": content})
        elif isinstance(msg, str):
            transcript.append({"role": "bot", "content": msg})
    return transcript


def should_report(intel: dict, scam_score: float) -> bool:
    """Return True only when there is actionable scammer intel above the threshold."""
    try:
        score = float(scam_score)
    except (TypeError, ValueError):
        return False

    threshold = float(os.getenv("REPORT_MIN_SCORE", "0.8"))
    if score < threshold:
        return False

    intel_dict = _as_intel_dict(intel)
    return any(bool(intel_dict.get(key, [])) for key in _IDENTIFIER_KEYS)


def _complainant_from_env() -> dict[str, str]:
    complainant = {}
    for env_var, field_name in (
        ("COMPLAINANT_NAME", "name"),
        ("COMPLAINANT_PHONE", "phone"),
        ("COMPLAINANT_EMAIL", "email"),
    ):
        value = (os.getenv(env_var, "") or "").strip()
        if value:
            complainant[field_name] = value
    return complainant


def build_report(session_id: str, intel: dict, transcript: list[dict] | list[str] | None) -> dict:
    intel_dict = _as_intel_dict(intel)
    cleaned_transcript = []
    raw_identifiers = []
    for key in _IDENTIFIER_KEYS:
        raw_identifiers.extend(intel_dict.get(key, []))

    for entry in transcript or []:
        if isinstance(entry, dict):
            content = entry.get("content", "")
            role = entry.get("role", "bot")
        else:
            content = str(entry)
            role = "bot"
        cleaned_transcript.append({
            "role": role,
            "content": redact(content, raw_identifiers),
        })

    report = {
        "session_id": session_id,
        "generated_at": _now(),
        "intel": intel_dict,
        "transcript": cleaned_transcript,
        "report_fingerprint": _fingerprint(intel_dict),
        "email_recipients": _parse_recipients(os.getenv("REPORT_RECIPIENTS", "")),
        "complainant": _complainant_from_env(),
        "scam_type": os.getenv("LAST_SCAM_TYPE", "unknown"),
    }
    return report


def report_to_text(report: dict) -> str:
    lines = [
        "Scam evidence report",
        "====================",
        f"Session ID: {report.get('session_id', 'unknown')}",
        f"Generated at: {report.get('generated_at', _now())}",
        "",
    ]

    complainant = report.get("complainant") or {}
    if isinstance(complainant, dict):
        parts = [
            str(complainant.get("name", "")).strip(),
            str(complainant.get("phone", "")).strip(),
            str(complainant.get("email", "")).strip(),
        ]
        parts = [part for part in parts if part]
        if parts:
            lines.append(f"Complainant: {' | '.join(parts)}")
            lines.append("")

    lines.append("Identifiers found:")

    intel = report.get("intel", {})
    found_any = False
    for key in _IDENTIFIER_KEYS:
        values = intel.get(key, [])
        if values:
            found_any = True
            lines.append(f"- {key}: {', '.join(values)}")
    if not found_any:
        lines.append("- None")

    lines.extend(["", "Transcript:"])
    for entry in report.get("transcript", []):
        role = entry.get("role", "bot")
        content = entry.get("content", "")
        lines.append(f"[{role}] {content}")

    return "\n".join(lines) + "\n"


def save_report(report: dict) -> Path:
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    session_id = report.get("session_id", "unknown")
    json_path = _REPORTS_DIR / f"report_{session_id}.json"
    txt_path = _REPORTS_DIR / f"report_{session_id}.txt"

    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)

    txt_path.write_text(report_to_text(report), encoding="utf-8")
    return txt_path


def send_email(report: dict) -> bool:
    """Send a report by SMTP with STARTTLS and evidence attachments."""
    if not _complainant_is_complete(report):
        return False
    if _rate_limit_reached():
        return False

    recipients = _resolved_recipients(report)
    if not recipients:
        return False

    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587") or "587")
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    if not all([smtp_host, smtp_user, smtp_pass]):
        return False

    session_id = report.get("session_id", "unknown")
    scam_type = str(report.get("scam_type") or report.get("scam_type", "unknown")).strip() or "unknown"
    subject_prefix = f"Scam report - {scam_type} - session {session_id}"
    if _is_test_mode():
        subject = f"[TEST] {subject_prefix}"
    else:
        subject = subject_prefix

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = ", ".join(recipients)
    msg.set_content(report_to_text(report))

    evidence_payload = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
    msg.add_attachment(
        evidence_payload,
        maintype="application",
        subtype="json",
        filename=f"evidence_{session_id}.json",
    )

    txt_payload = report_to_text(report).encode("utf-8")
    msg.add_attachment(
        txt_payload,
        maintype="text",
        subtype="plain",
        filename=f"report_{session_id}.txt",
    )

    smtp = smtplib.SMTP(smtp_host, smtp_port)
    try:
        smtp.starttls()
        smtp.login(smtp_user, smtp_pass)
        smtp.send_message(msg)
        _record_send()
        return True
    finally:
        try:
            smtp.quit()
        except Exception:  # pragma: no cover - defensive cleanup
            pass


def reporter_node(state: dict) -> dict:
    """LangGraph node that saves any reportable intel without breaking the chat loop."""
    state = _to_dict(state)
    state["report_path"] = state.get("report_path", "")
    state["report_sent"] = False
    state["report_error"] = ""

    intel = state.get("intel", {}) or {}
    if not should_report(intel, state.get("confidence_score", 0.0)):
        return state

    try:
        session_id = state.get("session_id", "unknown")
        transcript = _transcript_from_state(state)
        report = build_report(session_id, intel, transcript)
        report["scam_type"] = state.get("scam_type", report.get("scam_type", "unknown"))
        fp = report.get("report_fingerprint", "")
        previous_fp = str(state.get("last_reported_fp", ""))
        report_path = save_report(report)
        state["report_path"] = str(report_path)
        state["last_reported_fp"] = fp
        state["email_recipient_count"] = 0

        if previous_fp and previous_fp == fp:
            state["report_sent"] = False
            return state

        auto_report = os.getenv("AUTO_REPORT", "draft").strip().lower()
        if auto_report != "send":
            return state

        if not _complainant_is_complete(report):
            state["report_error"] = "Complainant details missing"
            return state

        if _rate_limit_reached():
            state["report_error"] = "Rate limit reached"
            state["report_sent"] = False
            return state

        recipients = _resolved_recipients(report)
        if not recipients:
            state["report_error"] = "No valid recipients"
            state["report_sent"] = False
            return state

        state["email_recipient_count"] = len(recipients)

        try:
            state["report_sent"] = bool(send_email(report))
            if not state["report_sent"]:
                if not _resolved_recipients(report):
                    state["report_error"] = "No valid recipients"
                elif _rate_limit_reached():
                    state["report_error"] = "Rate limit reached"
                else:
                    state["report_error"] = "Email sending failed or no recipients were configured."
        except Exception as exc:  # pragma: no cover - defensive branch
            state["report_error"] = str(exc)
            state["report_sent"] = False
    except Exception as exc:  # pragma: no cover - defensive branch
        state["report_error"] = str(exc)
        state["report_sent"] = False

    return state
