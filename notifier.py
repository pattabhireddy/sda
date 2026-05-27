"""
notifier.py
Sends email notifications for new RHEL security advisories
using Azure Communication Services Email (HTTPS REST API).
Docs: https://learn.microsoft.com/azure/communication-services/concepts/email/
"""

import os
import logging
from datetime import datetime, timezone
from azure.communication.email import EmailClient
from azure.core.exceptions import HttpResponseError
from patch_checker import format_advisory_summary


def _build_email_body(
    advisories: list[dict],
    ai_summary: str = "",
    app_url: str = "",
) -> tuple[str, str]:
    """
    Build both plain-text and HTML email body from a list of advisories.

    Args:
        advisories: List of advisory dicts from any supported platform.
        ai_summary: AI-generated analysis and recommendations from the LLM agent.
        app_url:    Base URL of the Streamlit Patch Monitor app.  When provided,
                    per-platform "View in App" buttons are added to the email so
                    recipients can click straight through to the filtered results.

    Returns:
        Tuple of (plain_text_body, html_body)
    """
    count = len(advisories)
    run_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Unique platforms present in this batch (e.g. ['redhat', 'suse'])
    platforms_present = list(dict.fromkeys(
        a.get("platform", "redhat").lower() for a in advisories
    ))

    # --- Plain text ---
    plain_lines = [
        f"Patch Monitor — {count} new security advisory/advisories detected",
        f"Report generated: {run_time}",
        "=" * 60,
        "",
    ]
    if ai_summary:
        plain_lines += [
            "AI AGENT ANALYSIS",
            "-" * 60,
            ai_summary,
            "",
            "=" * 60,
            "FULL ADVISORY DETAILS",
            "-" * 60,
            "",
        ]
    # Per-platform app links in plain text
    if app_url:
        plain_lines.append("VIEW PATCHES IN THE APP")
        plain_lines.append("-" * 60)
        for platform in platforms_present:
            plain_lines.append(f"  {platform.upper()}: {app_url}?os={platform}")
        plain_lines += ["", "=" * 60, ""]

    for advisory in advisories:
        plain_lines.append(format_advisory_summary(advisory))
        plain_lines.append("")

    plain_lines += [
        "=" * 60,
        "This is an automated notification from your Patch Monitor AI agent.",
    ]
    plain_text = "\n".join(plain_lines)

    # --- HTML ---
    rows_html = ""
    for adv in advisories:
        advisory_id = adv.get("RHSA") or adv.get("id", "Unknown")
        severity = adv.get("severity", "N/A").upper()
        synopsis = adv.get("synopsis", "No synopsis available")
        release_date = adv.get("issued_date") or adv.get("release_date", "Unknown")
        cves = adv.get("CVEs", [])
        cve_str = ", ".join(cves) if cves else "None listed"
        errata_url = f"https://access.redhat.com/errata/{advisory_id}"

        severity_color = {
            "CRITICAL": "#c00",
            "IMPORTANT": "#e65100",
            "MODERATE": "#f9a825",
            "LOW": "#2e7d32",
        }.get(severity, "#555")

        rows_html += f"""
        <tr>
            <td><a href="{errata_url}" style="color:#005eb8;font-weight:bold;">{advisory_id}</a></td>
            <td style="font-size:12px;font-weight:bold;color:#555;">{adv.get("platform", "").upper()}</td>
            <td style="color:{severity_color};font-weight:bold;">{severity}</td>
            <td>{synopsis}</td>
            <td>{release_date}</td>
            <td style="font-size:12px;">{cve_str}</td>
        </tr>"""

    ai_summary_html = ""
    if ai_summary:
        ai_summary_formatted = ai_summary.replace("\n", "<br>")
        ai_summary_html = f"""
        <div style="background:#f0f4ff;border-left:4px solid #005eb8;padding:14px 18px;
                    border-radius:4px;margin-bottom:20px;">
            <h3 style="margin:0 0 10px 0;color:#005eb8;">&#x1F916; AI Agent Analysis</h3>
            <p style="margin:0;line-height:1.6;">{ai_summary_formatted}</p>
        </div>"""

    # Per-platform "View in App" CTA buttons
    cta_buttons_html = ""
    if app_url:
        _platform_styles = {
            "redhat":  ("#c00",     "RHEL"),
            "suse":    ("#4a8500",  "SUSE"),
            "windows": ("#0078d4",  "Windows"),
        }
        buttons = ""
        for platform in platforms_present:
            color, label = _platform_styles.get(platform, ("#555", platform.upper()))
            link = f"{app_url}?os={platform}"
            buttons += (
                f'<a href="{link}" style="display:inline-block;background:{color};'
                f'color:white;padding:12px 28px;border-radius:6px;'
                f'text-decoration:none;font-weight:bold;margin:0 8px;font-size:14px;">'
                f'&#x1F50D;&nbsp; View {label} Patches</a>'
            )
        cta_buttons_html = f"""
        <div style="background:#f9f9f9;border:1px solid #ddd;border-radius:8px;
                    padding:20px;margin:20px 0;text-align:center;">
            <p style="margin:0 0 14px 0;font-size:15px;font-weight:bold;color:#333;">
                &#x1F514; New security patches require your attention.
                Click below to view the full details in the Patch Monitor app:
            </p>
            {buttons}
            <p style="margin:12px 0 0 0;font-size:11px;color:#888;">
                The app will open pre-filtered to your OS with full CVE details and AI analysis.
            </p>
        </div>"""

    html_body = f"""
    <html>
    <body style="font-family:Arial,sans-serif;color:#333;max-width:900px;margin:auto;">
        <h2 style="background:#1a1a2e;color:#fff;padding:12px 16px;border-radius:4px;">
            &#x1F6E1; Patch Monitor — {count} New Security Advisory/Advisories
        </h2>
        <p style="color:#666;">Report generated: <strong>{run_time}</strong></p>
        {cta_buttons_html}
        {ai_summary_html}
        <table border="1" cellpadding="8" cellspacing="0"
               style="border-collapse:collapse;width:100%;font-size:13px;">
            <thead style="background:#f5f5f5;">
                <tr>
                    <th>Advisory ID</th>
                    <th>Platform</th>
                    <th>Severity</th>
                    <th>Synopsis</th>
                    <th>Release Date</th>
                    <th>CVEs</th>
                </tr>
            </thead>
            <tbody>{rows_html}
            </tbody>
        </table>
        <p style="margin-top:20px;font-size:12px;color:#888;">
            This is an automated notification from your Patch Monitor AI agent.
        </p>
    </body>
    </html>
    """
    return plain_text, html_body


def send_email_notification(advisories: list[dict], ai_summary: str = "") -> bool:
    """
    Send a patch notification email using Azure Communication Services
    Email (HTTPS REST API).

    Args:
        advisories: List of advisory dicts to include in the email.
        ai_summary: AI-generated analysis from the LLM agent (shown at top of email).

    Required env vars:
        ACS_CONNECTION_STRING  — Connection string from your ACS resource
        ACS_SENDER_ADDRESS     — Verified sender address in ACS
                                 (e.g. DoNotReply@<your-domain>.azurecomm.net)
        NOTIFY_TO_EMAIL        — Recipient email address(es), comma-separated

    Returns:
        True if email sent successfully, False otherwise.
    """
    conn_str = os.environ.get("ACS_CONNECTION_STRING")
    sender = os.environ.get("ACS_SENDER_ADDRESS")
    to_addresses = os.environ.get("NOTIFY_TO_EMAIL", "")
    app_url = os.environ.get("STREAMLIT_APP_URL", "").rstrip("/")

    if not all([conn_str, sender, to_addresses]):
        logging.error(
            "Missing one or more required env vars: "
            "ACS_CONNECTION_STRING, ACS_SENDER_ADDRESS, NOTIFY_TO_EMAIL"
        )
        return False

    recipients = [addr.strip() for addr in to_addresses.split(",") if addr.strip()]
    count = len(advisories)

    # Build a platform-aware subject line, e.g. "[Patch Monitor] 3 RHEL + 2 SUSE advisories"
    platform_counts: dict[str, int] = {}
    for adv in advisories:
        p = adv.get("platform", "unknown").upper()
        platform_counts[p] = platform_counts.get(p, 0) + 1
    platform_summary = " + ".join(
        f"{v} {k}" for k, v in platform_counts.items()
    )
    subject = f"[Patch Monitor] {platform_summary} New Security Advisory/Advisories Detected"

    plain_text, html_body = _build_email_body(
        advisories, ai_summary=ai_summary, app_url=app_url
    )

    message = {
        "senderAddress": sender,
        "recipients": {
            "to": [{"address": addr} for addr in recipients],
        },
        "content": {
            "subject": subject,
            "plainText": plain_text,
            "html": html_body,
        },
    }

    try:
        client = EmailClient.from_connection_string(conn_str)
        poller = client.begin_send(message)
        result = poller.result()  # Waits for send to complete
        logging.info(f"Email sent via ACS. Message ID: {result.get('id', 'N/A')}")
        logging.info(f"Notification delivered to: {', '.join(recipients)}")
        return True
    except HttpResponseError as e:
        logging.error(f"ACS HTTP error sending email: {e.message}")
    except Exception as e:
        logging.error(f"Unexpected error sending email via ACS: {e}")

    return False


def send_heartbeat_notification(
    after_date: str = "",
    platforms: list[str] | None = None,
) -> bool:
    """
    Send a brief "all clear" email when no new advisories are found so recipients
    can confirm the agent is running correctly.

    Args:
        after_date: The date window that was checked (shown in the email body).
        platforms:  List of platforms that were checked.

    Required env vars (same as send_email_notification):
        ACS_CONNECTION_STRING, ACS_SENDER_ADDRESS, NOTIFY_TO_EMAIL

    Returns:
        True if email sent successfully, False otherwise.
    """
    conn_str = os.environ.get("ACS_CONNECTION_STRING")
    sender = os.environ.get("ACS_SENDER_ADDRESS")
    to_addresses = os.environ.get("NOTIFY_TO_EMAIL", "")

    if not all([conn_str, sender, to_addresses]):
        logging.error(
            "Missing one or more required env vars: "
            "ACS_CONNECTION_STRING, ACS_SENDER_ADDRESS, NOTIFY_TO_EMAIL"
        )
        return False

    recipients = [addr.strip() for addr in to_addresses.split(",") if addr.strip()]
    run_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    platforms_str = ", ".join(p.upper() for p in (platforms or [])) or "all platforms"
    since_str = f"after {after_date}" if after_date else "recently"

    subject = f"[Patch Monitor] ✅ No New Advisories — {run_time}"

    plain_text = "\n".join([
        "Patch Monitor — Scheduled Check Complete",
        f"Run time : {run_time}",
        f"Checked  : {platforms_str}",
        f"Window   : {since_str}",
        "=" * 60,
        "No new security advisories were found. Your systems are up to date.",
        "=" * 60,
        "This is an automated heartbeat from your Patch Monitor AI agent.",
    ])

    html_body = f"""
    <html>
    <body style="font-family:Arial,sans-serif;color:#333;max-width:700px;margin:auto;">
        <h2 style="background:#1a1a2e;color:#fff;padding:12px 16px;border-radius:4px;">
            &#x2705; Patch Monitor — No New Advisories
        </h2>
        <p style="color:#666;">Run time: <strong>{run_time}</strong></p>
        <div style="background:#e8f5e9;border-left:4px solid #2e7d32;padding:14px 18px;
                    border-radius:4px;margin:20px 0;">
            <p style="margin:0;font-size:15px;">
                <strong>All clear.</strong> No new security advisories were found
                for <strong>{platforms_str}</strong> {since_str}.
                Your patch baseline is current.
            </p>
        </div>
        <table style="width:100%;border-collapse:collapse;font-size:13px;">
            <tr>
                <td style="padding:6px 10px;color:#666;width:140px;">Platforms checked</td>
                <td style="padding:6px 10px;font-weight:bold;">{platforms_str}</td>
            </tr>
            <tr style="background:#f9f9f9;">
                <td style="padding:6px 10px;color:#666;">Advisory window</td>
                <td style="padding:6px 10px;font-weight:bold;">{since_str}</td>
            </tr>
        </table>
        <p style="margin-top:20px;font-size:12px;color:#888;">
            This is an automated heartbeat from your Patch Monitor AI agent.
            You will receive an alert as soon as new advisories are detected.
        </p>
    </body>
    </html>
    """

    message = {
        "senderAddress": sender,
        "recipients": {"to": [{"address": addr} for addr in recipients]},
        "content": {
            "subject": subject,
            "plainText": plain_text,
            "html": html_body,
        },
    }

    try:
        client = EmailClient.from_connection_string(conn_str)
        poller = client.begin_send(message)
        result = poller.result()
        logging.info(f"Heartbeat email sent. Message ID: {result.get('id', 'N/A')}")
        return True
    except HttpResponseError as e:
        logging.error(f"ACS HTTP error sending heartbeat: {e.message}")
    except Exception as e:
        logging.error(f"Unexpected error sending heartbeat: {e}")

    return False


def send_patch_result_notification(result, advisory: dict) -> bool:
    """
    Send a success or failure email after a patch has been applied to a host.

    Args:
        result:   PatchResult dataclass from patcher.py.
        advisory: The advisory dict that was patched (for context in the email).

    Required env vars (same as send_email_notification):
        ACS_CONNECTION_STRING, ACS_SENDER_ADDRESS, NOTIFY_TO_EMAIL

    Returns:
        True if email sent successfully, False otherwise.
    """
    conn_str = os.environ.get("ACS_CONNECTION_STRING")
    sender   = os.environ.get("ACS_SENDER_ADDRESS")
    to_addrs = os.environ.get("NOTIFY_TO_EMAIL", "")

    if not all([conn_str, sender, to_addrs]):
        logging.warning("Patch result notification skipped — email env vars not configured.")
        return False

    recipients  = [a.strip() for a in to_addrs.split(",") if a.strip()]
    status_icon = "✅" if result.success else "❌"
    status_word = "Successfully Applied" if result.success else "FAILED"
    run_time    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    advisory_id = advisory.get("RHSA") or advisory.get("id", result.advisory_id)
    severity    = advisory.get("severity", "N/A").upper()
    synopsis    = advisory.get("synopsis", "")
    cves        = advisory.get("CVEs") or []
    platform    = advisory.get("platform", result.platform).upper()

    subject = (
        f"[Patch Monitor] {status_icon} {advisory_id} "
        f"{status_word} on {result.host}"
    )

    # ── Plain text ────────────────────────────────────────────────────────────
    plain = "\n".join([
        f"Patch Monitor — Patch {status_word}",
        f"Time: {run_time}",
        "=" * 60,
        f"Advisory  : {advisory_id}",
        f"Platform  : {platform}",
        f"Severity  : {severity}",
        f"Synopsis  : {synopsis}",
        f"CVEs      : {', '.join(cves) or 'None'}",
        "=" * 60,
        f"Host      : {result.host}",
        f"Status    : {'SUCCESS' if result.success else 'FAILED'}",
        f"Exit code : {result.exit_code}",
        "",
        "--- Output ---",
        result.output or "(no output)",
        "",
        ("--- Error ---\n" + result.error) if result.error else "",
    ])

    # ── HTML ──────────────────────────────────────────────────────────────────
    status_color = "#2e7d32" if result.success else "#c00"
    status_bg    = "#e8f5e9" if result.success else "#ffebee"
    sev_color    = {
        "CRITICAL":  "#c00",
        "IMPORTANT": "#e65100",
        "MODERATE":  "#f9a825",
        "LOW":       "#2e7d32",
    }.get(severity, "#555")

    def _esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    output_html = _esc(result.output or "(no output)").replace("\n", "<br>")
    error_section_html = ""
    if result.error:
        error_html = _esc(result.error).replace("\n", "<br>")
        error_section_html = f"""
        <div style="background:#fff3e0;border-left:4px solid #e65100;
                    padding:12px;border-radius:4px;margin-top:12px;">
            <strong>Error details:</strong><br>
            <code style="font-size:12px;">{error_html}</code>
        </div>"""

    html = f"""
    <html>
    <body style="font-family:Arial,sans-serif;color:#333;max-width:800px;margin:auto;">
        <h2 style="background:{status_color};color:#fff;padding:12px 16px;border-radius:4px;">
            {status_icon} Patch {status_word}: {_esc(advisory_id)}
        </h2>
        <p style="color:#666;">Completed: <strong>{run_time}</strong></p>

        <div style="background:{status_bg};border:1px solid {status_color};
                    border-radius:8px;padding:16px;margin:16px 0;">
            <table style="width:100%;border-collapse:collapse;">
                <tr>
                    <td style="width:130px;font-weight:bold;padding:5px 0;">Host</td>
                    <td><code>{_esc(result.host)}</code></td>
                </tr>
                <tr>
                    <td style="font-weight:bold;padding:5px 0;">Status</td>
                    <td>
                        <span style="background:{status_color};color:white;
                                     padding:2px 12px;border-radius:12px;font-weight:bold;">
                            {'SUCCESS' if result.success else 'FAILED'}
                        </span>
                    </td>
                </tr>
                <tr>
                    <td style="font-weight:bold;padding:5px 0;">Advisory</td>
                    <td><strong>{_esc(advisory_id)}</strong></td>
                </tr>
                <tr>
                    <td style="font-weight:bold;padding:5px 0;">Platform</td>
                    <td>{_esc(platform)}</td>
                </tr>
                <tr>
                    <td style="font-weight:bold;padding:5px 0;">Severity</td>
                    <td><span style="color:{sev_color};font-weight:bold;">{severity}</span></td>
                </tr>
                <tr>
                    <td style="font-weight:bold;padding:5px 0;">Synopsis</td>
                    <td>{_esc(synopsis)}</td>
                </tr>
                <tr>
                    <td style="font-weight:bold;padding:5px 0;">CVEs</td>
                    <td>{_esc(', '.join(cves)) or 'None listed'}</td>
                </tr>
            </table>
        </div>

        <div style="background:#f5f5f5;border-radius:6px;padding:14px;margin:12px 0;">
            <strong>Command Output:</strong>
            <pre style="margin:8px 0;font-size:12px;white-space:pre-wrap;
                        word-break:break-all;">{output_html}</pre>
        </div>
        {error_section_html}

        <p style="margin-top:20px;font-size:12px;color:#888;">
            This notification was sent automatically by the Patch Monitor AI agent.
        </p>
    </body>
    </html>
    """

    message = {
        "senderAddress": sender,
        "recipients": {"to": [{"address": r} for r in recipients]},
        "content": {
            "subject": subject,
            "plainText": plain,
            "html": html,
        },
    }

    try:
        client = EmailClient.from_connection_string(conn_str)
        poller = client.begin_send(message)
        send_result = poller.result()
        logging.info(
            "Patch result notification sent. ID: %s", send_result.get("id", "N/A")
        )
        return True
    except HttpResponseError as exc:
        logging.error("ACS error sending patch result notification: %s", exc.message)
    except Exception as exc:
        logging.error("Unexpected error sending patch result notification: %s", exc)

    return False
