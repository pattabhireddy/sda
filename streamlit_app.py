"""
streamlit_app.py
Interactive Patch Monitor UI — choose your OS from a dropdown and view the
latest security advisories, with an optional AI-generated analysis.

Run locally:
    streamlit run streamlit_app.py
"""

import asyncio
import logging
import os
import re
from datetime import datetime, timedelta

import streamlit as st

from patch_checker import fetch_advisories
from patcher import apply_patch_ssh, PatchResult, PARAMIKO_AVAILABLE
from notifier import send_patch_result_notification

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Patch Monitor Agent",
    page_icon="🔐",
    layout="wide",
)

# ── URL query-param → OS mapping ─────────────────────────────────────────────
# Handles links like  https://your-app.com/?os=redhat  sent in email notifications.

_URL_TO_OS_LABEL = {
    "redhat":  "Red Hat Enterprise Linux (RHEL)",
    "rhel":    "Red Hat Enterprise Linux (RHEL)",
    "suse":    "SUSE Linux Enterprise (SLES)",
    "sles":    "SUSE Linux Enterprise (SLES)",
    "windows": "Windows Server",
}

_os_param      = st.query_params.get("os", "").lower()
_from_email    = _os_param in _URL_TO_OS_LABEL          # True → auto-fetch on load
_default_label = _URL_TO_OS_LABEL.get(_os_param, "")    # pre-selected OS label (or "")


# ── Constants ─────────────────────────────────────────────────────────────────

OS_OPTIONS = {
    "Red Hat Enterprise Linux (RHEL)": "redhat",
    "SUSE Linux Enterprise (SLES)":    "suse",
    "Windows Server":                  "windows",
}

SEVERITY_COLORS = {
    "CRITICAL":  "#D32F2F",
    "IMPORTANT": "#E64A19",
    "MODERATE":  "#F9A825",
    "LOW":       "#388E3C",
    "UNKNOWN":   "#757575",
}

# Display order — highest severity first
SEVERITY_ORDER = ["CRITICAL", "IMPORTANT", "MODERATE", "LOW", "UNKNOWN"]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _severity_key(advisory: dict) -> int:
    sev = advisory.get("severity", "UNKNOWN").upper()
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return len(SEVERITY_ORDER)


def _render_severity_metric(severity: str, count: int) -> None:
    color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["UNKNOWN"])
    st.markdown(
        f"""
        <div style="
            background:{color};color:white;
            padding:16px 8px;border-radius:10px;
            text-align:center;margin-bottom:8px;
        ">
            <div style="font-size:32px;font-weight:700;line-height:1">{count}</div>
            <div style="font-size:13px;margin-top:4px;letter-spacing:.5px">{severity}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_patch_section(advisory_id: str, advisory: dict, platform_lc: str, _key: str) -> None:
    """
    Render the Apply-Patch area at the bottom of an advisory card.
    Handles: Apply button → SSH form → spinner → result display → email notification.
    """
    result_key    = f"pr_{_key}"
    show_form_key = f"sf_{_key}"

    # ── Show a previous patch result ──────────────────────────────────────────
    if result_key in st.session_state:
        res: PatchResult = st.session_state[result_key]
        if res.success:
            st.success(f"✅ **{advisory_id}** applied successfully on `{res.host}`")
        else:
            st.error(
                f"❌ Patch **{advisory_id}** failed on `{res.host}`\n\n"
                f"**Error:** {res.error}"
            )
        if res.output:
            with st.expander("📋 View command output"):
                st.code(res.output, language="bash")
        if st.button("↩️ Apply to another host", key=f"re_{_key}"):
            del st.session_state[result_key]
            st.rerun()
        return

    # ── Windows: no SSH support ────────────────────────────────────────────────
    if platform_lc == "windows":
        st.info(
            "ℹ️ Automated patching is supported for **RHEL** and **SUSE**. "
            "For Windows, apply this update manually via Windows Update or WSUS."
        )
        return

    # ── paramiko not installed ────────────────────────────────────────────────
    if not PARAMIKO_AVAILABLE:
        st.warning("⚠️ Install `paramiko` to enable patching:  `pip install paramiko`")
        return

    # ── Show button or form depending on state ────────────────────────────────
    if not st.session_state.get(show_form_key, False):
        if st.button("🔧 Apply this Patch via SSH", key=f"btn_{_key}", type="secondary"):
            st.session_state[show_form_key] = True
            st.rerun()
        return

    # ── SSH connection form ───────────────────────────────────────────────────
    st.markdown("**🔌 SSH Connection Details**")
    h_col, u_col = st.columns(2)
    with h_col:
        st.text_input(
            "Target host / IP *",
            placeholder="10.0.1.10 or hostname",
            key=f"host_{_key}",
        )
    with u_col:
        st.text_input(
            "SSH user",
            value=os.environ.get("PATCH_SSH_USER", ""),
            key=f"user_{_key}",
        )

    k_col, p_col, port_col = st.columns([2, 2, 1])
    with k_col:
        st.text_input(
            "SSH key path",
            value="~/.ssh/id_rsa",
            help="Leave blank to use password auth",
            key=f"key_{_key}",
        )
    with p_col:
        st.text_input(
            "Password",
            type="password",
            help="Used only when no SSH key path is set",
            key=f"pass_{_key}",
        )
    with port_col:
        st.number_input("Port", value=22, min_value=1, max_value=65535, key=f"port_{_key}")

    cancel_col, apply_col = st.columns([1, 2])
    with cancel_col:
        if st.button("✖ Cancel", key=f"cancel_{_key}"):
            st.session_state[show_form_key] = False
            st.rerun()
    with apply_col:
        target_host  = st.session_state.get(f"host_{_key}", "").strip()
        apply_clicked = st.button(
            "✅ Confirm & Apply Patch",
            key=f"apply_{_key}",
            type="primary",
            disabled=not target_host,
        )

    if apply_clicked:
        _host    = st.session_state.get(f"host_{_key}", "").strip()
        _user    = st.session_state.get(f"user_{_key}", "").strip()
        _keypath = st.session_state.get(f"key_{_key}", "").strip() or None
        _passwd  = st.session_state.get(f"pass_{_key}", "") or None
        _port    = int(st.session_state.get(f"port_{_key}", 22))

        with st.spinner(f"Applying **{advisory_id}** on `{_host}` …"):
            res = apply_patch_ssh(
                host=_host,
                username=_user,
                advisory_id=advisory_id,
                platform=platform_lc,
                ssh_key_path=_keypath,
                password=_passwd,
                port=_port,
            )

        st.session_state[result_key]    = res
        st.session_state[show_form_key] = False
        try:
            send_patch_result_notification(res, advisory)
        except Exception as exc:
            logging.warning("Patch result notification failed: %s", exc)
        st.rerun()


def _render_advisory_card(advisory: dict) -> None:
    advisory_id = advisory.get("RHSA") or advisory.get("id", "Unknown")
    severity    = advisory.get("severity", "UNKNOWN").upper()
    synopsis    = advisory.get("synopsis", "No synopsis available")
    platform    = advisory.get("platform", "").upper()
    platform_lc = advisory.get("platform", "redhat").lower()
    issued      = advisory.get("issued_date") or advisory.get("release_date", "Unknown")
    cves        = advisory.get("CVEs") or []
    url         = advisory.get("url") or "#"
    color       = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["UNKNOWN"])
    # Sanitise advisory ID into a safe Streamlit widget key
    _key        = re.sub(r"[^a-zA-Z0-9]", "_", advisory_id)

    label = (
        f"{advisory_id}  —  "
        f"{synopsis[:90]}{'…' if len(synopsis) > 90 else ''}"
    )
    with st.expander(label):
        left, right = st.columns([3, 1])

        with left:
            st.markdown(f"**Synopsis:** {synopsis}")
            if cves:
                links = []
                for cve in cves:
                    if cve.startswith("CVE-"):
                        links.append(
                            f"[{cve}](https://nvd.nist.gov/vuln/detail/{cve})"
                        )
                    else:
                        links.append(cve)
                st.markdown(f"**CVEs:** {' · '.join(links)}")
            else:
                st.markdown("**CVEs:** None listed")

            if url != "#":
                st.markdown(f"[🔗 View full advisory]({url})")

        with right:
            st.markdown(
                f'<span style="background:{color};color:white;'
                f'padding:4px 12px;border-radius:20px;font-weight:700;'
                f'font-size:13px">{severity}</span>',
                unsafe_allow_html=True,
            )
            st.markdown(f"**Platform:** {platform}")
            st.markdown(f"**Released:** {issued}")

        # ── Apply Patch section ───────────────────────────────────────────────
        st.markdown("---")
        _render_patch_section(advisory_id, advisory, platform_lc, _key)


# ── AI Analysis (async, isolated event loop) ──────────────────────────────────

async def _ai_summary_async(os_label: str, advisories: list[dict]) -> str:
    """Call Azure OpenAI via Semantic Kernel and return a concise analysis."""
    from semantic_kernel import Kernel
    from semantic_kernel.connectors.ai.open_ai import (
        AzureChatCompletion,
        OpenAIChatPromptExecutionSettings,
    )
    from semantic_kernel.contents import ChatHistory

    endpoint   = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
    api_key    = os.environ.get("AZURE_OPENAI_API_KEY", "")
    deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")

    if not endpoint or not api_key:
        return (
            "_AI summary unavailable — set `AZURE_OPENAI_ENDPOINT` and "
            "`AZURE_OPENAI_API_KEY` in your environment._"
        )

    kernel = Kernel()
    kernel.add_service(
        AzureChatCompletion(
            service_id="chat",
            deployment_name=deployment,
            endpoint=endpoint,
            api_key=api_key,
        )
    )
    chat_service = kernel.get_service("chat")

    # Build compact advisory list (cap at 30 to stay within token budget)
    lines = "\n".join(
        f"- [{a.get('severity', 'N/A').upper()}] "
        f"{a.get('RHSA') or a.get('id', 'Unknown')}: "
        f"{a.get('synopsis', '')} | "
        f"CVEs: {', '.join(a.get('CVEs') or []) or 'None'}"
        for a in advisories[:30]
    )

    history = ChatHistory()
    history.add_user_message(
        f"You are a cybersecurity analyst. Analyse these {os_label} security advisories:\n\n"
        f"{lines}\n\n"
        "Provide a concise response with:\n"
        "1. Severity breakdown (count per level)\n"
        "2. Top 3 most urgent advisories and why\n"
        "3. Recommended action (patch immediately vs scheduled maintenance window)\n"
        "4. Notable CVEs to watch\n\n"
        "Be factual and concise."
    )

    settings = OpenAIChatPromptExecutionSettings(max_tokens=700)
    response = await chat_service.get_chat_message_content(
        chat_history=history,
        settings=settings,
    )
    return str(response)


def get_ai_summary(os_label: str, advisories: list[dict]) -> str:
    """Synchronous wrapper — runs the async AI call in a fresh event loop."""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(_ai_summary_async(os_label, advisories))
        finally:
            loop.close()
    except Exception as exc:
        return f"_AI summary error: {exc}_"


# ── Main UI ───────────────────────────────────────────────────────────────────

st.title("🔐 Patch Monitor Agent")

# Show a banner when the user arrived via an email notification link
if _from_email:
    st.info(
        f"📧 You were directed here from a patch notification email. "
        f"Loading **{_default_label}** advisories automatically…",
        icon="📧",
    )
else:
    st.markdown(
        "Select your **Operating System** below and click **Check for Patches** to view "
        "the latest security advisories."
    )

st.divider()

# ── Controls row ──────────────────────────────────────────────────────────────
ctrl_os, ctrl_date = st.columns([2, 1])

with ctrl_os:
    _os_index = (
        list(OS_OPTIONS.keys()).index(_default_label)
        if _default_label in OS_OPTIONS
        else 0
    )
    selected_label = st.selectbox(
        "🖥️ Operating System",
        options=list(OS_OPTIONS.keys()),
        index=_os_index,
        help="Choose the OS platform you want to check patches for.",
    )

with ctrl_date:
    since_date = st.date_input(
        "📅 Show advisories since",
        value=datetime.today() - timedelta(days=30),
        max_value=datetime.today(),
        help="Only advisories published after this date will be shown.",
    )

ai_enabled = st.checkbox(
    "✨ Include AI-generated analysis",
    value=True,
    help="Requires AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_API_KEY environment variables.",
)

st.divider()

# ── Fetch & display ───────────────────────────────────────────────────────────
# Auto-fetch when the user arrives via an email link (?os=...),
# otherwise wait for the button click.
_btn_clicked = st.button("🔍 Check for Patches", type="primary", use_container_width=True)
if _btn_clicked or _from_email:
    platform       = OS_OPTIONS[selected_label]
    after_date_str = since_date.strftime("%Y-%m-%d")

    with st.spinner(f"Fetching {selected_label} advisories since {after_date_str} …"):
        try:
            advisories = fetch_advisories(platform=platform, after_date=after_date_str)
        except Exception as exc:
            st.error(f"Failed to fetch advisories: {exc}")
            st.stop()

    # ── No results ────────────────────────────────────────────────────────────
    if not advisories:
        st.success(
            f"✅ No new advisories found for **{selected_label}** "
            f"since **{after_date_str}**."
        )
        st.stop()

    # ── Severity summary cards ────────────────────────────────────────────────
    severity_counts: dict[str, int] = {}
    for adv in advisories:
        sev = adv.get("severity", "UNKNOWN").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    present_levels = [s for s in SEVERITY_ORDER if s in severity_counts]

    st.markdown(
        f"### Found **{len(advisories)}** adviser(s) for {selected_label}"
    )

    metric_cols = st.columns(len(present_levels) if present_levels else 1)
    for col, level in zip(metric_cols, present_levels):
        with col:
            _render_severity_metric(level, severity_counts[level])

    # ── AI Analysis ───────────────────────────────────────────────────────────
    if ai_enabled:
        st.markdown("---")
        with st.expander("✨ AI Analysis", expanded=True):
            with st.spinner("Generating AI analysis …"):
                summary = get_ai_summary(selected_label, advisories)
            st.markdown(summary)

    # ── Advisory list sorted by severity ─────────────────────────────────────
    st.markdown("---")
    st.markdown("### Advisory Details")
    st.caption(
        "Advisories are sorted by severity — Critical first. "
        "Click any row to expand full details."
    )

    sorted_advisories = sorted(advisories, key=_severity_key)
    for advisory in sorted_advisories:
        _render_advisory_card(advisory)
