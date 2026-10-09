"""
core/reporter.py — Scam evidence reporting helpers.

Generates human-readable reports from extracted intel, saves them as JSON/TXT,
optionally sends them by SMTP, and is safe to run inside the graph without
breaking the chat loop.
"""

import hashlib
import html
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


def _is_placeholder_email(value: str) -> bool:
    if not _valid_email(value):
        return True
    domain = value.rsplit("@", 1)[1].strip().casefold()
    return domain in {"example.com", "example.org", "example.net", "example.invalid"} or domain.endswith(".example")


def _complainant_is_complete(report: dict) -> bool:
    complainant = report.get("complainant") or {}
    if not isinstance(complainant, dict):
        return False
    values = {field: str(complainant.get(field, "")).strip() for field in ("name", "phone", "email")}
    return all(values.values()) and all(
        not _is_placeholder_complainant_value(field, value)
        for field, value in values.items()
    ) and _valid_email(values["email"]) and not _is_placeholder_email(values["email"])


def _is_placeholder_complainant_value(field: str, value: str) -> bool:
    normalized = value.strip().casefold()
    if field == "name":
        return normalized in {"jane doe", "john doe", "your name", "full name"}
    if field == "email":
        return normalized in {"jane.doe@example.com", "you@example.com", "your.email@example.com"}
    if field == "phone":
        digits = re.sub(r"\D", "", value)
        if digits.startswith("91") and len(digits) == 12:
            digits = digits[2:]
        return digits in {"9876543210", "1234567890", "0000000000"}
    return False


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
    recipients = [email for email in recipients if not _is_placeholder_email(email)]
    copy_self = [email for email in copy_self if not _is_placeholder_email(email)]

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


def should_report(intel: dict, scam_score: float, threat_level: str = "low") -> bool:
    """Return True only when there is actionable scammer intel above the threshold."""
    return not _report_gate_status(intel, scam_score, threat_level=threat_level)


def _report_gate_status(
    intel: dict,
    scam_score: float,
    scam_type: str = "unknown",
    threat_level: str = "low",
) -> str:
    """Explain why a local report draft is not eligible."""
    if str(threat_level).strip().casefold() not in {"high", "critical"}:
        return "below_threat_threshold"

    intel_dict = _as_intel_dict(intel)
    has_actionable_intel = any(bool(intel_dict.get(key, [])) for key in _IDENTIFIER_KEYS)
    is_classified_scam = bool(scam_type and scam_type != "unknown")

    try:
        score = float(scam_score)
    except (TypeError, ValueError):
        return "awaiting_confidence"

    threshold = float(os.getenv("REPORT_MIN_SCORE", "0.8"))
    if score >= threshold and (has_actionable_intel or is_classified_scam):
        return ""
    if has_actionable_intel or is_classified_scam:
        return "awaiting_confidence"
    return "awaiting_evidence"


def _complainant_from_env() -> dict[str, str]:
    complainant = {}
    for env_var, field_name in (
        ("COMPLAINANT_NAME", "name"),
        ("COMPLAINANT_PHONE", "phone"),
        ("COMPLAINANT_EMAIL", "email"),
    ):
        value = (os.getenv(env_var, "") or "").strip()
        if value and not _is_placeholder_complainant_value(field_name, value):
            complainant[field_name] = value
    return complainant


def build_report(
    session_id: str,
    intel: dict,
    transcript: list[dict] | list[str] | None,
    *,
    scam_type: str | None = None,
    threat_level: str | None = None,
    confidence_score: float | None = None,
    scam_indicators: list[str] | None = None,
) -> dict:
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
        "scam_type": scam_type or os.getenv("LAST_SCAM_TYPE", "unknown"),
        "threat_level": threat_level or "unknown",
        "confidence_score": confidence_score,
        "scam_indicators": _safe_list(scam_indicators),
    }
    return report


def report_to_text(report: dict) -> str:
    scam_type = str(report.get("scam_type", "unknown")).replace("_", " ")
    classification = "UPI Fraud" if scam_type.casefold() == "upi fraud" else scam_type.title()
    lines = [
        "DIGITAL FRAUD INCIDENT REPORT",
        "=" * 31,
        f"Case reference: {report.get('session_id', 'unknown')}",
        f"Generated (UTC): {report.get('generated_at', _now())}",
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

    lines.extend([
        "INCIDENT ASSESSMENT",
        "-------------------",
        f"Classification: {classification}",
        f"Threat level: {str(report.get('threat_level', 'unknown')).title()}",
    ])
    confidence = report.get("confidence_score")
    if confidence is not None:
        lines.append(f"Assessment confidence: {float(confidence):.0%}")

    indicators = _safe_list(report.get("scam_indicators", []))
    if indicators:
        lines.append("Observed indicators:")
        lines.extend(f"- {indicator}" for indicator in indicators)

    lines.extend(["", "EVIDENCE REGISTER", "-----------------"])

    intel = report.get("intel", {})
    found_any = False
    evidence_labels = (
        ("upi_ids", "UPI identifiers"),
        ("phone_numbers", "Phone numbers"),
        ("account_numbers", "Account numbers"),
        ("ifsc_codes", "IFSC codes"),
        ("urls", "URLs"),
        ("bank_names", "Bank references"),
        ("names", "Names mentioned"),
    )
    for key, label in evidence_labels:
        values = intel.get(key, [])
        if values:
            found_any = True
            lines.append(f"{label}: {', '.join(values)}")
    if not found_any:
        lines.append("No identifiers were captured.")

    lines.extend(["", "CONVERSATION RECORD", "-------------------"])
    for entry in report.get("transcript", []):
        role = str(entry.get("role", "bot")).title()
        content = entry.get("content", "")
        lines.append(f"[{role}] {content}")

    lines.extend([
        "",
        "REVIEW NOTICE",
        "-------------",
        "This report is AI-assisted and contains unverified allegations and extracted data.",
        "A human reviewer must validate the evidence and recipient before any external filing.",
    ])
    return "\n".join(lines) + "\n"


def report_to_html(report: dict) -> str:
        """Render an email-safe, self-contained HTML incident report."""
        escape = html.escape
        scam_type = str(report.get("scam_type", "unknown")).replace("_", " ")
        classification = "UPI Fraud" if scam_type.casefold() == "upi fraud" else scam_type.title()
        threat = str(report.get("threat_level", "unknown")).title()
        confidence = report.get("confidence_score")
        confidence_text = f"{float(confidence):.0%}" if confidence is not None else "Not assessed"

        summary_rows = [
                ("Case reference", report.get("session_id", "unknown")),
                ("Classification", classification),
                ("Threat level", threat),
                ("Assessment confidence", confidence_text),
                ("Generated (UTC)", report.get("generated_at", _now())),
        ]
        summary_html = "".join(
                f"<tr><th>{escape(str(label))}</th><td>{escape(str(value))}</td></tr>"
                for label, value in summary_rows
        )

        complainant = report.get("complainant") or {}
        complainant_html = ""
        if _complainant_is_complete(report):
                complainant_html = (
                        "<section><h2>Complainant</h2><p>"
                        f"{escape(str(complainant['name']))} · "
                        f"{escape(str(complainant['phone']))} · "
                        f"{escape(str(complainant['email']))}</p></section>"
                )

        indicators = _safe_list(report.get("scam_indicators", []))
        indicators_html = "".join(f"<li>{escape(item)}</li>" for item in indicators)
        if not indicators_html:
                indicators_html = "<li>No indicators recorded.</li>"

        intel = report.get("intel", {})
        evidence_rows = []
        for key, label in (
                ("upi_ids", "UPI identifiers"),
                ("phone_numbers", "Phone numbers"),
                ("account_numbers", "Account numbers"),
                ("ifsc_codes", "IFSC codes"),
                ("urls", "URLs"),
                ("bank_names", "Bank references"),
                ("names", "Names mentioned"),
        ):
                values = _safe_list(intel.get(key, []))
                if values:
                        evidence_rows.append(
                                f"<tr><th>{escape(label)}</th><td>{'<br>'.join(escape(item) for item in values)}</td></tr>"
                        )
        evidence_html = "".join(evidence_rows) or "<tr><td colspan=\"2\">No identifiers captured yet.</td></tr>"

        transcript_rows = []
        for entry in report.get("transcript", []):
                role = escape(str(entry.get("role", "unknown")).title())
                content = escape(str(entry.get("content", "")))
                transcript_rows.append(
                        f"<tr><th>{role}</th><td>{content}</td></tr>"
                )
        transcript_html = "".join(transcript_rows) or "<tr><td colspan=\"2\">No conversation record available.</td></tr>"

        return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Digital Fraud Incident Report</title></head>
<body style="margin:0;background:#f2f5f7;color:#17212b;font-family:Arial,Helvetica,sans-serif;">
<main style="max-width:760px;margin:24px auto;background:#ffffff;border:1px solid #d9e1e7;">
    <header style="padding:28px 32px;background:#123b35;color:#ffffff;border-bottom:4px solid #24a47a;">
        <div style="font-size:11px;letter-spacing:1.4px;text-transform:uppercase;color:#bfe8d9;">Incident dossier</div>
        <h1 style="margin:8px 0 0;font-size:25px;line-height:1.25;">Digital Fraud Incident Report</h1>
        <p style="margin:8px 0 0;color:#dbece6;font-size:14px;">Case {escape(str(report.get('session_id', 'unknown')))}</p>
    </header>
    <div style="padding:24px 32px 30px;">
        {complainant_html}
        <section><h2 style="margin:0 0 12px;font-size:17px;">Incident assessment</h2>
            <table role="presentation" style="width:100%;border-collapse:collapse;font-size:14px;">{summary_html}</table>
        </section>
        <section style="margin-top:24px;"><h2 style="margin:0 0 12px;font-size:17px;">Observed indicators</h2>
            <ul style="margin:0;padding-left:20px;font-size:14px;line-height:1.6;">{indicators_html}</ul>
        </section>
        <section style="margin-top:24px;"><h2 style="margin:0 0 12px;font-size:17px;">Evidence register</h2>
            <table role="presentation" style="width:100%;border-collapse:collapse;font-size:14px;">{evidence_html}</table>
        </section>
        <section style="margin-top:24px;"><h2 style="margin:0 0 12px;font-size:17px;">Conversation record</h2>
            <table role="presentation" style="width:100%;border-collapse:collapse;font-size:13px;">{transcript_html}</table>
        </section>
        <aside style="margin-top:26px;padding:14px 16px;background:#f4f7f8;border-left:3px solid #758795;font-size:12px;line-height:1.55;color:#43515d;">
            <strong>Review required.</strong> This report is AI-assisted. Allegations and extracted data are unverified; a human reviewer must validate the evidence and recipient before external filing.
        </aside>
    </div>
</main>
<style>
table th,table td{{padding:9px 10px;border-bottom:1px solid #e3e9ed;text-align:left;vertical-align:top;}}
table th{{width:34%;color:#536471;font-weight:600;}}
h2{{color:#123b35;}}
</style>
</body></html>"""


def save_report(report: dict) -> Path:
    _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    session_id = report.get("session_id", "unknown")
    json_path = _REPORTS_DIR / f"report_{session_id}.json"
    txt_path = _REPORTS_DIR / f"report_{session_id}.txt"
    html_path = _REPORTS_DIR / f"report_{session_id}.html"

    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)

    txt_path.write_text(report_to_text(report), encoding="utf-8")
    html_path.write_text(report_to_html(report), encoding="utf-8")
    return html_path


def send_email(report: dict) -> bool:
    """Send a report by SMTP with STARTTLS and evidence attachments."""
    if str(report.get("threat_level", "low")).strip().casefold() not in {"high", "critical"}:
        return False
    if not _is_test_mode() and not _complainant_is_complete(report):
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
    msg.add_alternative(report_to_html(report), subtype="html")

    evidence_payload = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
    msg.add_attachment(
        evidence_payload,
        maintype="application",
        subtype="json",
        filename=f"evidence_{session_id}.json",
    )

    html_payload = report_to_html(report).encode("utf-8")
    msg.add_attachment(html_payload, maintype="text", subtype="html", filename=f"report_{session_id}.html")

    smtp = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
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
    state["report_path"] = ""
    state["report_sent"] = False
    state["report_status"] = _report_gate_status(
        state.get("intel", {}) or {},
        state.get("confidence_score", 0.0),
        state.get("scam_type", "unknown"),
        state.get("threat_level", "low"),
    )
    state["report_error"] = ""

    intel = state.get("intel", {}) or {}
    if state["report_status"]:
        return state

    try:
        session_id = state.get("session_id", "unknown")
        transcript = _transcript_from_state(state)
        report = build_report(
            session_id,
            intel,
            transcript,
            scam_type=state.get("scam_type", "unknown"),
            threat_level=state.get("threat_level", "unknown"),
            confidence_score=state.get("confidence_score"),
            scam_indicators=state.get("scam_indicators", []),
        )
        fp = report.get("report_fingerprint", "")
        previous_fp = str(state.get("last_reported_fp", ""))
        report_path = save_report(report)
        state["report_path"] = str(report_path)
        state["last_reported_fp"] = fp
        state["email_recipient_count"] = 0
        has_actionable_intel = any(bool(_as_intel_dict(intel).get(key, [])) for key in _IDENTIFIER_KEYS)

        if not has_actionable_intel:
            state["report_status"] = "draft_saved_waiting_evidence"
            return state

        state["report_status"] = "draft_saved"
        if previous_fp and previous_fp == fp:
            state["report_status"] = "already_reported"
            return state

        auto_report = os.getenv("AUTO_REPORT", "draft").strip().lower()
        if auto_report != "send":
            return state

        if not _is_test_mode() and not _complainant_is_complete(report):
            state["report_error"] = "Complainant details missing"
            state["report_status"] = "email_not_configured"
            return state

        if _rate_limit_reached():
            state["report_error"] = "Rate limit reached"
            state["report_sent"] = False
            state["report_status"] = "rate_limited"
            return state

        recipients = _resolved_recipients(report)
        if not recipients:
            state["report_error"] = "No valid recipients"
            state["report_sent"] = False
            state["report_status"] = "email_not_configured"
            return state

        state["email_recipient_count"] = len(recipients)

        try:
            state["report_sent"] = bool(send_email(report))
            if not state["report_sent"]:
                state["report_status"] = "email_failed"
                if not _resolved_recipients(report):
                    state["report_error"] = "No valid recipients"
                elif _rate_limit_reached():
                    state["report_error"] = "Rate limit reached"
                else:
                    state["report_error"] = "Email sending failed or no recipients were configured."
            else:
                state["report_status"] = "sent"
        except Exception as exc:  # pragma: no cover - defensive branch
            state["report_error"] = str(exc)
            state["report_sent"] = False
            state["report_status"] = "email_failed"
    except Exception as exc:  # pragma: no cover - defensive branch
        state["report_error"] = str(exc)
        state["report_sent"] = False
        state["report_status"] = "report_failed"

    return state
