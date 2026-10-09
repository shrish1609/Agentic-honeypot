"""
run_cli.py — Terminal test tool for the Agentic Honeypot.

Runs a full scam conversation directly in your terminal.
Useful for testing without starting the full API + dashboard stack.

Usage:
    python run_cli.py                      # new session
    python run_cli.py --session ABC123     # resume a session (memory only)
    python run_cli.py --no-db             # skip MongoDB (useful if DB not running)

NOTE: This uses asyncio.run() because session_manager is fully async.
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


# ── Colour helpers (no extra deps) ───────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
DIM    = "\033[2m"


def c(text, colour): return f"{colour}{text}{RESET}"


# ── Pretty-print intel ────────────────────────────────────────────────────────

def print_intel(intel: dict):
    has = any(v for v in intel.values() if isinstance(v, list) and v)
    if not has:
        return
    print(c("\n  ┌─ INTEL HARVESTED ──────────────────────────────", CYAN))
    labels = [
        ("upi_ids",        "💳 UPI IDs      "),
        ("phone_numbers",  "📞 Phones       "),
        ("bank_names",     "🏦 Banks        "),
        ("account_numbers","🔢 Accounts     "),
        ("ifsc_codes",     "🏷️  IFSC Codes   "),
        ("names",          "👤 Names        "),
        ("urls",           "🔗 URLs         "),
    ]
    for key, label in labels:
        vals = intel.get(key, [])
        if vals:
            print(c(f"  │  {label}: ", CYAN) + c(", ".join(vals), BOLD))
    print(c("  └────────────────────────────────────────────────\n", CYAN))


def print_turn_meta(result: dict):
    turn     = result.get("turn", 0)
    strategy = result.get("strategy", "?")
    persona  = result.get("persona", "?")
    scam     = result.get("scam_type", "?")
    threat   = result.get("threat_level", "?")
    yld      = result.get("intel_yield", 0.0)
    model    = result.get("model_used", "?")

    threat_colour = {
        "low": GREEN, "medium": YELLOW, "high": RED, "critical": RED
    }.get(threat, RESET)

    print(
        c(f"\n  [{DIM}Turn {turn}{RESET}"
          f"{c(' | ', DIM)}{c(strategy, YELLOW)}"
          f"{c(' | ', DIM)}{c(persona, CYAN)}"
          f"{c(' | ', DIM)}Scam: {scam}"
          f"{c(' | ', DIM)}Threat: {c(threat.upper(), threat_colour)}"
          f"{c(' | ', DIM)}Yield: {c(f'{yld:.0%}', GREEN)}"
          f"{c(' | ', DIM)}{c(model, DIM)}"
          f"{c(']', DIM)}", DIM)
    )


def _print_report_status(result: dict):
    report_path = result.get("report_path", "")
    report_error = result.get("report_error", "")

    if report_path:
        print(c(f"\n  📝 Report saved: {report_path}", CYAN))
        if result.get("report_sent"):
            recipient_count = result.get("email_recipient_count") or 0
            print(c(f"  📧 Report emailed to {recipient_count} recipient(s)", CYAN))
        elif report_error:
            print(c(f"  Email not sent: {report_error}", YELLOW))
        elif os.getenv("AUTO_REPORT", "draft").strip().lower() != "send":
            print(c("  Email not sent: AUTO_REPORT is set to draft.", DIM))
        else:
            print(c("  Email not sent: this report was already reported.", DIM))
        print(c("     File reports manually at cybercrime.gov.in or call 1930 for guidance.", DIM))
    elif report_error:
        print(c(f"\n  Report error: {report_error}", YELLOW))
    else:
        print(c("\n  No report generated: no actionable identifier or confidence below threshold.", DIM))


# ── Main async entry point ────────────────────────────────────────────────────

async def main(use_db: bool, session_id_arg: str | None):
    # IMPORTANT: set the env var BEFORE importing session_manager, since
    # session_manager reads USE_DB at import time to decide whether to
    # even attempt loading core.database. Without this, --no-db would only
    # skip this file's own connect() call while session_manager still tries
    # (and fails) to use Mongo internally.
    if not use_db:
        os.environ["USE_DB"] = "false"

    if use_db:
        from core.database import db
        try:
            await db.connect()
        except Exception as e:
            print(c(f"\n⚠️  MongoDB unavailable ({e}).\n   Run with --no-db to skip.\n", YELLOW))
            return

    from core.session_manager import registry

    print()
    print(c("╔══════════════════════════════════════════════╗", CYAN))
    print(c("║     🍯  AGENTIC HONEYPOT  —  CLI Mode        ║", CYAN))
    print(c("╚══════════════════════════════════════════════╝", CYAN))
    print(c("  Type a scammer message and watch the bot bait.", DIM))
    print(c("  Commands:  quit | exit | q  → end session", DIM))
    print(c("             intel            → show current intel", DIM))
    print(c("             status           → show session status", DIM))
    print()

    # Create or resume session
    if session_id_arg:
        session = await registry.get_or_create(session_id_arg)
        print(c(f"  Resumed session: {session.session_id}", GREEN))
    else:
        session = await registry.create_session()
        print(c(f"  New session: {session.session_id}", GREEN))

    print(c("─" * 50, DIM))

    while session.is_active:
        try:
            raw = input(c("\n🦹 Scammer: ", RED)).strip()
        except (EOFError, KeyboardInterrupt):
            print(c("\n\nInterrupted — exiting.", DIM))
            break

        if not raw:
            continue

        if raw.lower() in ("quit", "exit", "q"):
            print(c("\nExiting CLI. Session data saved to MongoDB.", DIM))
            break

        if raw.lower() == "intel":
            print_intel(session._prev_intel.model_dump())
            continue

        if raw.lower() == "status":
            print(session.get_summary())
            continue

        print(c("  🤔 thinking...", DIM), end="\r")
        result = await session.process_message(raw)

        # Clear the thinking line
        print(" " * 25, end="\r")

        if "error" in result:
            print(c(f"\n  ❌ Error: {result['error']}", RED))
            if "hint" in result:
                print(c(f"     {result['hint']}", YELLOW))
            continue

        # Print bot response
        print(c("\n🍯 Bot:     ", GREEN) + result.get("bot_response", ""))
        print_turn_meta(result)
        print_intel(result.get("intel", {}))

        _print_report_status(result)

        if not result.get("session_active", True):
            reason = result.get("termination_reason", "mission complete")
            yld    = result.get("intel_yield", 0.0)
            print(c(f"\n  🔒 Session closed: {reason}", YELLOW))
            print(c(f"     Final intel yield: {yld:.0%}", GREEN))
            print(c(f"     Data saved to MongoDB + data/intel_logs/", DIM))
            break

    if use_db:
        from core.database import db
        await db.disconnect()

    print(c("\n  Session ended. Check data/intel_logs/ for saved logs.\n", DIM))


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Agentic Honeypot — CLI")
    parser.add_argument("--session", type=str, help="Resume session by ID")
    parser.add_argument("--no-db",   action="store_true", help="Skip MongoDB connection")
    args = parser.parse_args()

    asyncio.run(main(use_db=not args.no_db, session_id_arg=args.session))