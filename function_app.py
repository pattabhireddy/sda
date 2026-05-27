"""
function_app.py
Azure Function App entry point — Timer-triggered RHEL Patch Monitor Agent.

Schedule: Runs every 6 hours at 00:00, 06:00, 12:00, 18:00 UTC (configurable via PATCH_MONITOR_CRON env var).
CRON format: {second} {minute} {hour} {day} {month} {day-of-week}
Default: "0 0 */6 * * *" = every 6 hours

AI mode: If AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_API_KEY are configured, the full SK/GPT-4o
         agent runs (fetch + AI analysis + notify).
Fallback mode: Without valid OpenAI settings, advisories are fetched directly from each
               platform and a notification email is sent with no AI summary.
"""

import logging
import os
from datetime import datetime, timezone

import azure.functions as func

from state_manager import get_last_check_time, update_last_check_time

app = func.FunctionApp()

# Allow schedule override via environment variable for flexibility
CRON_SCHEDULE = os.environ.get("PATCH_MONITOR_CRON", "0 0 */6 * * *")

_PLACEHOLDER = "<YOUR"


def _openai_configured() -> bool:
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
    api_key = os.environ.get("AZURE_OPENAI_API_KEY", "")
    return bool(endpoint and api_key and not endpoint.startswith(_PLACEHOLDER) and not api_key.startswith(_PLACEHOLDER))


@app.schedule(
    schedule=CRON_SCHEDULE,
    arg_name="timer",
    run_on_startup=False,
    use_monitor=True,
)
async def rhel_patch_monitor(timer: func.TimerRequest) -> None:
    """
    Main timer-triggered function.
    Uses AI agent when OpenAI is configured; falls back to direct fetch+notify otherwise.
    """
    utc_now = datetime.now(timezone.utc)
    logging.info(f"Patch Monitor triggered at {utc_now.isoformat()}")

    if timer.past_due:
        logging.warning("Timer is running late — the previous execution was past due.")

    if _openai_configured():
        # Full AI agent path — SK/GPT-4o handles fetch, analysis, and notification
        from agent import run_patch_monitor_agent
        result = await run_patch_monitor_agent()
        logging.info(f"Agent result: {result}")
        # The AI agent handles its own "found advisories" check internally;
        # advance the state unconditionally when running in AI mode.
        notified = True
    else:
        # Fallback: direct fetch + email notification without AI analysis
        logging.info("OpenAI not configured — running in direct fetch+notify mode.")
        notified = await _run_direct_notify()

    # Only advance the state checkpoint when advisories were found and notified.
    # If nothing was found the date stays put so the next run re-queries the same
    # window — this prevents same-calendar-day advisories from being silently skipped.
    if notified:
        today = utc_now.strftime("%Y-%m-%d")
        update_last_check_time(today)
        logging.info(f"State updated. Next check will look for advisories after: {today}")
    else:
        logging.info("State not advanced — no advisories notified this run.")


async def _run_direct_notify() -> None:
    """Fetch advisories from all platforms and send email directly (no AI analysis)."""
    from patch_checker import fetch_advisories
    from notifier import send_email_notification, send_heartbeat_notification

    after_date = get_last_check_time()
    platforms = ["redhat", "suse"]
    all_advisories = []

    for platform in platforms:
        try:
            advisories = fetch_advisories(platform=platform, after_date=after_date)
            logging.info(f"[{platform}] fetched {len(advisories)} advisories since {after_date}")
            all_advisories.extend(advisories)
        except Exception as exc:
            logging.error(f"[{platform}] fetch failed: {exc}")

    if all_advisories:
        try:
            send_email_notification(
                advisories=all_advisories,
                ai_summary="AI analysis is not available (Azure OpenAI not configured). "
                           "Please review the advisories listed below.",
            )
            logging.info(f"Notification sent for {len(all_advisories)} total advisory/advisories.")
            # Only advance the state checkpoint when we have actually notified —
            # keeping it at after_date until new advisories appear ensures we never
            # skip over advisories published on the same calendar day.
            return True
        except Exception as exc:
            logging.error(f"Failed to send notification: {exc}")
    else:
        logging.info("No new advisories found on any platform.")
        try:
            send_heartbeat_notification(after_date=after_date, platforms=platforms)
        except Exception as exc:
            logging.error(f"Failed to send heartbeat notification: {exc}")

    return False
