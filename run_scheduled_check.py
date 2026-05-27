"""
run_scheduled_check.py
Standalone entry point for the GitHub Actions scheduled workflow.

Fetches security advisories from all configured platforms, sends an email
notification if new advisories are found, or a heartbeat "all clear" email
if nothing is found.  State (last check date) is persisted in Azure Blob Storage
so consecutive runs never re-notify for the same advisory.

Environment variables (set as GitHub Secrets in the workflow):
    AZURE_STORAGE_CONNECTION_STRING  — for state persistence
    ACS_CONNECTION_STRING            — Azure Communication Services
    ACS_SENDER_ADDRESS               — verified ACS sender
    NOTIFY_TO_EMAIL                  — recipient(s), comma-separated
    RHEL_VERSIONS                    — e.g. "8,9"   (default: "8,9")
    SUSE_VERSIONS                    — e.g. "12,15" (default: "12,15")

Optional (manual workflow_dispatch inputs passed as env vars):
    OVERRIDE_AFTER_DATE  — override the stored last-check date
    OVERRIDE_PLATFORMS   — override platforms to check (default: "redhat,suse")
"""

import logging
import os
import sys
from datetime import datetime, timezone

from patch_checker import fetch_advisories
from notifier import send_email_notification, send_heartbeat_notification
from state_manager import get_last_check_time, update_last_check_time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    stream=sys.stdout,
)


def main() -> None:
    utc_now = datetime.now(timezone.utc)
    logging.info(f"Patch monitor check started at {utc_now.isoformat()}")

    # Resolve platforms — allow workflow_dispatch override
    platforms_env = os.environ.get("OVERRIDE_PLATFORMS", "").strip()
    platforms = [p.strip() for p in platforms_env.split(",") if p.strip()] \
        if platforms_env else ["redhat", "suse"]
    logging.info(f"Platforms to check: {platforms}")

    # Resolve after_date — allow workflow_dispatch override, else use stored state
    after_date_override = os.environ.get("OVERRIDE_AFTER_DATE", "").strip()
    after_date = after_date_override if after_date_override else get_last_check_time()
    logging.info(f"Checking advisories after: {after_date}")

    # ── Fetch advisories from all platforms ──────────────────────────────────
    all_advisories: list[dict] = []
    for platform in platforms:
        try:
            advisories = fetch_advisories(platform=platform, after_date=after_date)
            logging.info(f"[{platform}] found {len(advisories)} advisories since {after_date}")
            all_advisories.extend(advisories)
        except Exception as exc:
            logging.error(f"[{platform}] fetch failed: {exc}")

    # ── Notify ───────────────────────────────────────────────────────────────
    if all_advisories:
        logging.info(f"Sending advisory notification for {len(all_advisories)} item(s)...")
        sent = send_email_notification(
            advisories=all_advisories,
            ai_summary="AI analysis is not available in scheduled mode. "
                       "Please review the advisories listed below.",
        )
        if sent:
            logging.info("Notification email sent successfully.")
            # Only advance the state when we actually notified — keeps the window
            # open so same-day advisories published after this run are not missed.
            today = utc_now.strftime("%Y-%m-%d")
            update_last_check_time(today)
            logging.info(f"State updated to: {today}")
        else:
            logging.error("Failed to send notification email — state NOT updated.")
            sys.exit(1)
    else:
        logging.info("No new advisories found — sending heartbeat notification.")
        send_heartbeat_notification(after_date=after_date, platforms=platforms)
        logging.info("Heartbeat sent. State not advanced (no new advisories).")

    logging.info("Patch monitor check complete.")


if __name__ == "__main__":
    main()
