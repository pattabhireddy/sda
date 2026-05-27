"""
test_notification.py
Standalone script to test the patch notification email — no Azure Function
or timer trigger needed.

Usage:
    1. Fill in your real values in local.settings.json
    2. Run:  python test_notification.py

What it does:
    1. Fetches real advisories from the selected platform (or uses sample data
       if you set USE_SAMPLE_DATA = True below)
    2. Sends the formatted email via Azure Communication Services
    3. Prints the result so you can check your inbox

Set USE_SAMPLE_DATA = True if you just want to test the email format without
hitting the actual Red Hat / SUSE / MSRC APIs.
"""

import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone

# ── Load local.settings.json into environment variables ──────────────────────
_SETTINGS_FILE = os.path.join(os.path.dirname(__file__), "local.settings.json")
if os.path.exists(_SETTINGS_FILE):
    with open(_SETTINGS_FILE) as f:
        _settings = json.load(f)
    for k, v in _settings.get("Values", {}).items():
        os.environ.setdefault(k, v)
    print(f"[Setup] Loaded env vars from {_SETTINGS_FILE}")
else:
    print(f"[Setup] WARNING: {_SETTINGS_FILE} not found — using system env vars")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)

# ── Config — change these as needed ──────────────────────────────────────────

# Platform to fetch advisories for: "redhat", "suse", or "windows"
PLATFORM = "redhat"

# Date range — advisories published after this date will be included
AFTER_DATE = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")

# Set True to skip the real API call and use bundled sample data instead
USE_SAMPLE_DATA = False


# ── Sample advisory data (used when USE_SAMPLE_DATA = True) ──────────────────

SAMPLE_ADVISORIES = [
    {
        "platform":   "redhat",
        "RHSA":       "RHSA-2026:1001",
        "severity":   "Critical",
        "synopsis":   "Critical security update for the Linux kernel",
        "issued_date": "2026-05-20",
        "CVEs":       ["CVE-2026-12345", "CVE-2026-12346"],
        "url":        "https://access.redhat.com/errata/RHSA-2026:1001",
    },
    {
        "platform":   "redhat",
        "RHSA":       "RHSA-2026:1002",
        "severity":   "Important",
        "synopsis":   "Important update for OpenSSL security vulnerability",
        "issued_date": "2026-05-21",
        "CVEs":       ["CVE-2026-11111"],
        "url":        "https://access.redhat.com/errata/RHSA-2026:1002",
    },
    {
        "platform":   "redhat",
        "RHSA":       "RHSA-2026:1003",
        "severity":   "Moderate",
        "synopsis":   "Moderate update for glibc",
        "issued_date": "2026-05-22",
        "CVEs":       [],
        "url":        "https://access.redhat.com/errata/RHSA-2026:1003",
    },
]


# ── Main test flow ────────────────────────────────────────────────────────────

def main() -> None:
    print("\n" + "=" * 60)
    print("  Patch Monitor — Notification Test")
    print("=" * 60)

    # Step 1 — Get advisories
    if USE_SAMPLE_DATA:
        print(f"\n[Step 1] Using sample advisory data ({len(SAMPLE_ADVISORIES)} items)")
        advisories = SAMPLE_ADVISORIES
    else:
        print(f"\n[Step 1] Fetching real {PLATFORM.upper()} advisories since {AFTER_DATE} ...")
        try:
            from patch_checker import fetch_advisories
            advisories = fetch_advisories(platform=PLATFORM, after_date=AFTER_DATE)
            print(f"         Found {len(advisories)} advisories")
        except Exception as exc:
            print(f"         ERROR fetching advisories: {exc}")
            print("         Tip: set USE_SAMPLE_DATA = True to skip the API call")
            sys.exit(1)

    if not advisories:
        print("\n  No advisories found for the selected date range.")
        print("  Try extending AFTER_DATE or setting USE_SAMPLE_DATA = True.")
        sys.exit(0)

    # Step 2 — Check email config
    print("\n[Step 2] Checking email configuration ...")
    required_vars = ["ACS_CONNECTION_STRING", "ACS_SENDER_ADDRESS", "NOTIFY_TO_EMAIL"]
    missing = [v for v in required_vars if not os.environ.get(v) or "<" in os.environ.get(v, "")]
    if missing:
        print(f"\n  ERROR: The following env vars are not configured in local.settings.json:")
        for v in missing:
            print(f"    • {v}")
        print("\n  Please fill in your real values and try again.")
        sys.exit(1)

    app_url     = os.environ.get("STREAMLIT_APP_URL", "http://localhost:8501")
    to_email    = os.environ.get("NOTIFY_TO_EMAIL")
    sender      = os.environ.get("ACS_SENDER_ADDRESS")
    print(f"         Sender    : {sender}")
    print(f"         Recipient : {to_email}")
    print(f"         App URL   : {app_url}  (links in the email will use this)")

    # Step 3 — Send the notification
    print(f"\n[Step 3] Sending notification email for {len(advisories)} advisory/advisories ...")
    try:
        from notifier import send_email_notification
        success = send_email_notification(
            advisories=advisories,
            ai_summary=(
                "TEST RUN — AI analysis is not generated in this test script.\n"
                "In production the AI agent provides a full severity breakdown,\n"
                "top advisories to act on, and recommended action."
            ),
        )
    except Exception as exc:
        print(f"\n  ERROR calling send_email_notification: {exc}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    # Step 4 — Result
    print("\n" + "=" * 60)
    if success:
        print("  [SUCCESS]  Email sent successfully!")
        print(f"      Check the inbox of: {to_email}")
        print(f"\n  The email contains a 'View {PLATFORM.upper()} Patches' button.")
        print(f"  Clicking it should open: {app_url}?os={PLATFORM}")
    else:
        print("  [FAILED]  Email failed to send.")
        print("      Check the logs above for the ACS error message.")
        print("      Common causes:")
        print("        * Wrong ACS_CONNECTION_STRING")
        print("        * ACS_SENDER_ADDRESS not verified in your ACS resource")
        print("        * NOTIFY_TO_EMAIL has an invalid address")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
