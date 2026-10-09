"""Streamlit dashboard for the Agentic Honeypot."""

import asyncio
import os
import re
import sys
import uuid
from urllib.parse import urlsplit
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

os.environ.setdefault("USE_DB", "false")

import streamlit as st


SCENARIOS = {
    "KYC / bank scam": "phishing",
    "UPI payment scam": "upi_fraud",
    "Gift card impostor": "fake_lottery",
    "Job offer scam": "job_scam",
    "Romance scam": "romance_scam",
    "Tech support fraud": "tech_support",
    "Crypto investment bait": "unknown",
    "General / unknown": "unknown",
}

LANGUAGES = ("Hinglish", "Hindi", "English (India)", "English (US)")
SCENARIO_LABELS = {
    "phishing": "KYC / bank scam",
    "upi_fraud": "UPI payment scam",
    "fake_lottery": "Gift card impostor",
    "job_scam": "Job offer scam",
    "romance_scam": "Romance scam",
    "tech_support": "Tech support fraud",
    "unknown": "General / unknown",
}

DEMO_REPLY_TEMPLATES = {
    "credential_request": {
        "Hinglish": ("Aap account details aur PIN maang rahe hain. Kya iske bina KYC verify nahi ho sakti?", "PIN ya OTP share karna safe nahi lag raha. Aap official verification ka exact step batao."),
        "Hindi": ("आप खाते की जानकारी और पिन माँग रहे हैं। क्या इसके बिना केवाईसी सत्यापित नहीं हो सकती?", "पिन या ओटीपी साझा करना सुरक्षित नहीं लगता। कृपया सत्यापन का सही तरीका बताइए।"),
        "English (India)": ("You are asking for account details and a PIN. Is there an official way to verify this without sharing them?", "I am not comfortable sharing a PIN or OTP. What is the official verification step?"),
        "English (US)": ("You're asking for account details and a PIN. Is there an official way to verify this without sharing them?", "I'm not comfortable sharing a PIN or OTP. What is the official verification step?"),
    },
    "link": {
        "Hinglish": ("Aapne link bheja hai. Kholne se pehle batao, ye kis official bank page par le jayega?", "Link mil gaya. Is page par kaunsa reference number ya notice verify karna hai?"),
        "Hindi": ("आपने लिंक भेजा है। खोलने से पहले बताइए, यह बैंक के किस आधिकारिक पेज पर जाएगा?", "लिंक मिल गया। इस पेज पर कौन-सा संदर्भ नंबर या सूचना जाँचनी है?"),
        "English (India)": ("I received the link. Which official bank page should it open, and what notice should I verify there?", "Before I open it, can you tell me the reference number on the bank notice?"),
        "English (US)": ("I got the link. Which official bank page should it open, and what notice should I verify there?", "Before I open it, can you give me the reference number from the notice?"),
    },
    "payment": {
        "Hinglish": ("Payment se pehle recipient ka naam confirm kaise karun? Screen par kya naam dikhna chahiye?", "Aapne payment bola. Exact amount aur receiver ka display name ek baar bata do."),
        "Hindi": ("भुगतान से पहले प्राप्तकर्ता का नाम कैसे जाँचूँ? स्क्रीन पर कौन-सा नाम दिखना चाहिए?", "आपने भुगतान कहा। कृपया सही राशि और प्राप्तकर्ता का नाम बताइए।"),
        "English (India)": ("How do I confirm the recipient name before paying? What name should appear on the screen?", "You mentioned a payment. Please confirm the exact amount and recipient display name."),
        "English (US)": ("How do I verify the recipient before paying? What name should appear on the screen?", "You mentioned a payment. Can you confirm the exact amount and recipient name?"),
    },
    "urgency": {
        "Hinglish": ("Aap keh rahe hain account block hoga. Notice ki exact deadline aur reference number kya hai?", "Itni jaldi kyun hai bhai? KYC notice par date kya likhi hai?"),
        "Hindi": ("आप कह रहे हैं कि खाता बंद होगा। सूचना की अंतिम तारीख और संदर्भ संख्या क्या है?", "इतनी जल्दी क्यों है? केवाईसी सूचना पर कौन-सी तारीख लिखी है?"),
        "English (India)": ("You said the account may be blocked. What deadline and reference number are on the notice?", "Why is this urgent? What date is printed on the KYC notice?"),
        "English (US)": ("You said the account may be blocked. What deadline and reference number are on the notice?", "Why is this urgent? What date is printed on the notice?"),
    },
    "general": {
        "Hinglish": ("Aapki baat samajh raha hoon. Is process ka agla exact step kya hai?", "Thoda dheere batao bhai, abhi aapko mujhse exactly kya karwana hai?"),
        "Hindi": ("मैं आपकी बात समझ रहा हूँ। इस प्रक्रिया का अगला सही कदम क्या है?", "कृपया धीरे बताइए, अभी आपको मुझसे क्या करवाना है?"),
        "English (India)": ("I understand. What exactly do you need me to do next?", "Could you explain the next step a little more clearly?"),
        "English (US)": ("I understand. What exactly do you need me to do next?", "Could you explain the next step a little more clearly?"),
    },
}

EMPTY_INTEL = {"UPI": [], "Phone": [], "URL": [], "Bank": []}


async def _process_backend_turn(session_id: str, message: str) -> dict:
    from core.session_manager import registry

    session = await registry.get_or_create(session_id)
    return await session.process_message(message)


def backend_turn(session_id: str, message: str) -> dict:
    """Run one message through the real pipeline and normalize its response."""
    result = asyncio.run(_process_backend_turn(session_id, message))
    if result.get("error"):
        raise RuntimeError("The honeypot backend could not process that message.")

    raw_intel = result.get("intel") or {}
    if not isinstance(raw_intel, dict):
        raw_intel = {}

    return {
        "reply": result.get("bot_response", ""),
        "scam_type": result.get("scam_type", "unknown"),
        "threat_level": result.get("threat_level", "low"),
        "intel": {
            "UPI": list(raw_intel.get("upi_ids") or []),
            "Phone": list(raw_intel.get("phone_numbers") or []),
            "URL": list(raw_intel.get("urls") or []),
            "Bank": list(raw_intel.get("bank_names") or []),
        },
        "report_path": result.get("report_path", ""),
        "report_sent": result.get("report_sent", False),
        "report_status": result.get("report_status", "awaiting_evidence"),
    }


def _mask_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    return f"***-***-{digits[-4:]}" if len(digits) >= 4 else "***"


def _mask_value(category: str, value: str, enabled: bool) -> str:
    if not enabled:
        return value
    if category == "Phone":
        return _mask_phone(value)
    if category == "UPI" and "@" in value:
        local, provider = value.split("@", 1)
        return f"{local[:2]}***@{provider}"
    if category == "URL":
        parsed = urlsplit(value)
        if parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}/..."
    return value


def _mask_message(message: str, enabled: bool) -> str:
    if not enabled:
        return message

    message = re.sub(
        r"[\w.\-+]+@[\w.\-]+",
        lambda match: _mask_value("UPI", match.group(0), True),
        message,
    )
    return re.sub(r"(?<!\d)(?:\+91[ -]?)?[6-9]\d{9}(?!\d)", lambda match: _mask_phone(match.group(0)), message)


def _start_session() -> None:
    st.session_state.session_id = uuid.uuid4().hex[:8].upper()
    st.session_state.messages = []
    st.session_state.scam_type = "unknown"
    st.session_state.threat_level = "low"
    st.session_state.intel = {key: [] for key in EMPTY_INTEL}
    st.session_state.report_path = ""
    st.session_state.report_status = "awaiting_evidence"
    st.session_state.backend_error = ""


def _initialize_state() -> None:
    if "session_id" not in st.session_state:
        _start_session()
    st.session_state.setdefault("messages", [])
    st.session_state.setdefault("scam_type", "unknown")
    st.session_state.setdefault("threat_level", "low")
    st.session_state.setdefault("intel", {key: [] for key in EMPTY_INTEL})
    st.session_state.setdefault("report_path", "")
    st.session_state.setdefault("report_status", "awaiting_evidence")
    st.session_state.setdefault("backend_error", "")


def _demo_turn(
    message: str,
    scenario: str,
    language: str,
    previous_replies: list[str] | None = None,
    auto_detect: bool = True,
) -> dict:
    folded = message.casefold()
    safety_warning = bool(
        re.search(r"\b(?:never|do not|don't|dont)\s+(?:share|send|give|provide)\b", folded)
    )
    asks_for_secrets = not safety_warning and bool(
        re.search(r"\b(?:otp|pin|cvv|password|account number|card number)\b", folded)
        and re.search(r"\b(?:share|send|give|provide|enter|tell)\b", folded)
    )
    if auto_detect:
        scenario = "General / unknown"
        if re.search(r"\b(?:gift card|gift voucher|lottery|prize|won|winner)\b", folded):
            scenario = "Gift card impostor"
        elif re.search(r"\b(?:job|work from home|registration fee|joining fee)\b", folded):
            scenario = "Job offer scam"
        elif re.search(r"\b(?:girlfriend|boyfriend|romance|love you|relationship)\b", folded):
            scenario = "Romance scam"
        elif re.search(r"\b(?:remote access|anydesk|teamviewer|technical support|antivirus)\b", folded):
            scenario = "Tech support fraud"
        elif re.search(r"\b(?:crypto|bitcoin|investment|guaranteed returns)\b", folded):
            scenario = "Crypto investment bait"
        elif re.search(r"\b(?:upi|gpay|google pay|phonepe|paytm|vpa)\b", folded) and re.search(r"\b(?:pay|payment|send|transfer|deposit)\b", folded):
            scenario = "UPI payment scam"
        elif asks_for_secrets or (
            re.search(r"\b(?:bank|sbi|hdfc|icici|axis|kotak|pnb|rbi)\b", folded)
            and re.search(r"\b(?:kyc|verify|blocked|suspend|expired|update|link)\b", folded)
        ):
            scenario = "KYC / bank scam"

    scam_type = SCENARIOS[scenario]
    has_upi = bool(re.search(r"\b(?:upi|gpay|google pay|phonepe|paytm)\b", folded) or "@" in message)
    asks_payment = bool(re.search(r"\b(?:pay|payment|send|transfer|deposit)\b", folded))
    if asks_for_secrets:
        intent = "credential_request"
        if auto_detect:
            scam_type = "phishing"
    elif has_upi and asks_payment:
        intent = "payment"
        if auto_detect:
            scam_type = "upi_fraud"
    elif re.search(r"https?://\S+|\blink\b", folded):
        intent = "link"
        if auto_detect and scenario == "KYC / bank scam":
            scam_type = "phishing"
    elif any(token in folded for token in ("urgent", "immediately", "blocked", "suspend", "deadline", "last chance")):
        intent = "urgency"
    elif not safety_warning and any(token in folded for token in ("kyc", "verify", "password", "otp")):
        intent = "credential_request"
        if auto_detect:
            scam_type = "phishing"
    else:
        intent = "general"

    reply_options = DEMO_REPLY_TEMPLATES[intent][language]
    recent_replies = set((previous_replies or [])[-2:])
    reply = next((candidate for candidate in reply_options if candidate not in recent_replies), reply_options[0])

    upi_ids = re.findall(
        r"[\w.\-+]+@(?:okaxis|oksbi|okicici|okhdfcbank|paytm|ybl|ibl|upi|gpay|phonepe|apl|axl)",
        message,
        re.IGNORECASE,
    )
    phones = re.findall(r"(?<!\d)(?:\+91[ -]?)?([6-9]\d{9})(?!\d)", message)
    urls = re.findall(r'https?://[^\s<>"]+', message)
    bank_names = [name for name in ("SBI", "HDFC", "ICICI", "Axis", "Kotak", "PNB") if re.search(rf"\b{re.escape(name)}\b", message, re.IGNORECASE)]

    return {
        "reply": reply,
        "scam_type": scam_type,
        "scenario": scenario,
        "threat_level": "high" if asks_for_secrets or asks_payment else "medium" if scam_type != "unknown" else "low",
        "intel": {
            "UPI": list(dict.fromkeys(upi_ids)),
            "Phone": list(dict.fromkeys(phones)),
            "URL": list(dict.fromkeys(urls)),
            "Bank": bank_names,
        },
        "report_path": "",
        "report_sent": False,
        "report_status": "demo_only",
    }


def _render_intel(mask_sensitive: bool) -> None:
    st.subheader("Intel harvested")
    categories = ("UPI", "Phone", "URL", "Bank")
    total = sum(len(st.session_state.intel.get(category, [])) for category in categories)
    st.caption(f"{total} value(s) captured")

    for category in categories:
        values = st.session_state.intel.get(category, [])
        if not values:
            continue
        for value in values:
            shown = _mask_value(category, str(value), mask_sensitive)
            st.markdown(f"**{category}**  ` {shown} `")


def _report_status_message(status: str) -> tuple[str, str]:
    messages = {
        "sent": ("success", "Report email sent successfully."),
        "draft_saved": ("info", "Professional report saved locally; email sending is disabled."),
        "draft_saved_waiting_evidence": ("info", "A high-confidence report draft is saved. Email is held until actionable evidence is captured."),
        "below_threat_threshold": ("info", "No report generated. Reports are created only for high or critical threat assessments."),
        "already_reported": ("info", "This evidence was already reported; no duplicate email was sent."),
        "email_not_configured": ("warning", "Report saved, but email delivery is not fully configured."),
        "email_failed": ("warning", "Report saved, but email delivery failed. The conversation is still active."),
        "rate_limited": ("warning", "Report saved; the email sending limit has been reached."),
        "report_failed": ("warning", "The report could not be created. Your conversation is still active."),
        "awaiting_confidence": ("info", "Evidence was captured, but the assessment is below the report threshold."),
        "awaiting_evidence": ("info", "No report yet. The pipeline is waiting for actionable identifiers."),
    }
    return messages.get(status, messages["awaiting_evidence"])


def main() -> None:
    st.set_page_config(
        page_title="Scam Honeypot",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    _initialize_state()

    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        :root { --bg:#0B0F17; --panel:#111827; --line:#283548; --muted:#94A3B8; --green:#10B981; --text:#F8FAFC; }
        html, body, [class*="css"] { font-family: Inter, sans-serif; letter-spacing: 0; }
        .stApp { background:var(--bg); color:var(--text); }
        [data-testid="stSidebar"] { background:#0D1522; border-right:1px solid var(--line); }
        [data-testid="stSidebar"] > div { padding-top:1.5rem; }
        [data-testid="stHeader"] { background:transparent; }
        .block-container { max-width:1040px; padding-top:2rem; padding-bottom:4rem; }
        [data-testid="stChatMessage"] { border:0; border-bottom:1px solid #1b2635; border-radius:0; background:transparent; padding:1rem 0; }
        div.stButton > button { border-radius:6px; }
        [data-testid="stAlert"] { border-radius:6px; }
        h1 { font-size:30px !important; font-weight:600 !important; }
        h2, h3 { letter-spacing:0 !important; }
        [data-testid="stExpander"] { border:1px solid var(--line); border-radius:6px; background:var(--panel); }
        footer { visibility:hidden; }
        </style>
        """,
        unsafe_allow_html=True,
    )

    with st.sidebar:
        st.markdown("### Session controls")
        run_mode = st.segmented_control(
            "Run mode",
            options=("Demo", "Live AI"),
            default="Demo",
            key="run_mode",
        )
        demo_mode = run_mode != "Live AI"
        mask_sensitive = st.checkbox("Mask sensitive data", value=True, key="mask_sensitive")
        auto_detect = st.checkbox("Auto-detect scenario", value=True, key="auto_detect_scenario")
        scenario = st.selectbox(
            "Scenario override",
            tuple(SCENARIOS),
            disabled=auto_detect,
            help="Turn off auto-detect to force a demo classification. Live AI always classifies the incoming message.",
        )
        language = st.selectbox("Language", LANGUAGES, disabled=not demo_mode)
        if st.button("New session", use_container_width=True):
            _start_session()

    st.title("Scam Honeypot")
    st.caption(
        f"Session {st.session_state.session_id} · "
        f"{SCENARIO_LABELS.get(st.session_state.scam_type, 'General / unknown')} · "
        f"Threat {st.session_state.threat_level.title()}"
    )
    if demo_mode:
        st.caption("Scripted demo · switch to Live AI for model-generated replies")
    else:
        st.caption("Live pipeline · scenario classification is automatic")

    conversation_column, side_space = st.columns([7, 2])
    with conversation_column:
        for item in st.session_state.messages:
            speaker = "user" if item["role"] == "scammer" else "assistant"
            with st.chat_message(speaker):
                st.write(_mask_message(item["content"], mask_sensitive))

        if st.session_state.backend_error:
            st.warning(st.session_state.backend_error)

        incoming = st.chat_input("Message from the suspected scammer")
        if incoming and incoming.strip():
            message = incoming.strip()
            st.session_state.messages.append({"role": "scammer", "content": message})
            st.session_state.backend_error = ""
            try:
                previous_replies = [item["content"] for item in st.session_state.messages if item["role"] == "assistant"]
                result = (
                    _demo_turn(message, scenario, language, previous_replies, auto_detect)
                    if demo_mode
                    else backend_turn(st.session_state.session_id, message)
                )
                st.session_state.messages.append({"role": "assistant", "content": result["reply"]})
                st.session_state.scam_type = result["scam_type"]
                st.session_state.threat_level = result.get("threat_level", "low")
                st.session_state.intel = result["intel"]
                st.session_state.report_path = result.get("report_path", "")
                st.session_state.report_status = result.get("report_status", "awaiting_evidence")
            except Exception:
                st.session_state.backend_error = "The agent couldn't process that message. Your conversation is still here; try again in a moment."
            st.rerun()

    with side_space:
        st.caption(f"{sum(1 for item in st.session_state.messages if item['role'] == 'scammer')} turns")

    intel_count = sum(len(st.session_state.intel.get(key, [])) for key in EMPTY_INTEL)
    with st.expander(f"Intel captured · {intel_count}", expanded=bool(intel_count)):
        _render_intel(mask_sensitive)

    status_kind, status_message = _report_status_message(
        "demo_only" if demo_mode else st.session_state.report_status
    )
    with st.container(border=True):
        st.markdown("**Incident report**")
        if demo_mode:
            st.info("Demo mode does not create reports. Switch to Live AI to save an evidence report.")
        else:
            getattr(st, status_kind)(status_message)
            if st.session_state.report_path:
                st.caption(f"Saved report: {st.session_state.report_path}")


if __name__ == "__main__":
    main()