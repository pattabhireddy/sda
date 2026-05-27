"""
agent.py
AI Agent core — Semantic Kernel + Azure OpenAI (GPT-4o) with automatic function calling.
Monitors security advisories across Red Hat, SUSE, and Windows.

Flow:
  1. SK agent calls fetch_advisories(platform, after_date) for each platform
  2. LLM analyses all results, prioritises advisories by severity
  3. LLM calls send_patch_notification with a unified cross-platform summary
  4. SK handles the tool-call loop automatically via FunctionChoiceBehavior.Auto()
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Annotated

from semantic_kernel import Kernel
from semantic_kernel.agents import ChatCompletionAgent
from semantic_kernel.connectors.ai.function_choice_behavior import FunctionChoiceBehavior
from semantic_kernel.connectors.ai.open_ai import (
    AzureChatCompletion,
    OpenAIChatPromptExecutionSettings,
)
from semantic_kernel.contents import ChatHistory
from semantic_kernel.functions import kernel_function

from patch_checker import fetch_advisories as _fetch_advisories
from notifier import send_email_notification
from state_manager import get_last_check_time

# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a cybersecurity patch management AI agent for enterprise Linux systems.
You monitor Red Hat Enterprise Linux (RHEL) and SUSE Linux Enterprise.

Your responsibilities on each run:
1. Call fetch_advisories for EACH of the two platforms — redhat and suse —
   using the provided after_date for every call.
2. Analyse ALL returned advisories across both platforms:
   - Identify CRITICAL and IMPORTANT ones — explain the risk and associated CVEs.
   - Prioritise: CRITICAL → IMPORTANT → MODERATE → LOW.
   - Highlight advisories affecting core components (kernel, glibc, OpenSSL, etc.).
3. If any advisories exist across either platform, call send_patch_notification with:
   - advisories_json: the combined list of ALL advisory objects (both platforms).
   - ai_summary containing:
       • Per-platform count and severity breakdown
       • Top 2-3 advisories to act on immediately (include platform label) and why
       • Recommended action (immediate patching vs scheduled maintenance window)
       • Any notable CVEs
4. If NO new advisories are found on either platform, do NOT call send_patch_notification.
   Simply state that no new advisories were found.

Be factual, concise, and security-focused. Avoid speculation beyond what the data shows.
"""


# ── Semantic Kernel Plugin ────────────────────────────────────────────────────

class PatchMonitorPlugin:
    """
    Exposes patch-monitoring tools to the LLM as Semantic Kernel kernel functions.
    The LLM decides when and how to call these — no manual loop needed.
    """

    @kernel_function(
        description=(
            "Fetch new security advisories for a given platform published after a given date. "
            "Supported platforms: redhat, suse, windows. "
            "Returns a JSON string with advisory count and the full list of advisory objects."
        )
    )
    def fetch_advisories(
        self,
        platform: Annotated[str, "Platform to check: 'redhat', 'suse', or 'windows'"],
        after_date: Annotated[str, "ISO date YYYY-MM-DD — only return advisories after this date"],
    ) -> Annotated[str, "JSON string: {platform, count, advisories[]}"]:
        advisories = _fetch_advisories(platform=platform, after_date=after_date)
        logging.info(f"[Tool] fetch_advisories({platform}) → {len(advisories)} results")
        return json.dumps({"platform": platform, "count": len(advisories), "advisories": advisories})

    @kernel_function(
        description=(
            "Send an email notification to the security team with patch advisories and AI analysis. "
            "Only call this when there are advisories to report."
        )
    )
    def send_patch_notification(
        self,
        advisories_json: Annotated[str, "JSON array of advisory objects from all platforms combined"],
        ai_summary: Annotated[
            str,
            "AI-generated analysis: per-platform severity breakdown, top advisories, "
            "recommended actions, notable CVEs",
        ],
    ) -> Annotated[str, "JSON string: {success, status}"]:
        try:
            advisories = json.loads(advisories_json)
        except json.JSONDecodeError:
            advisories = []
            logging.error("[Tool] send_patch_notification — failed to parse advisories_json")

        success = send_email_notification(advisories, ai_summary=ai_summary)
        status = "success" if success else "failed"
        logging.info(f"[Tool] send_patch_notification → {status}")
        return json.dumps({"success": success, "status": status})


# ── Agent entrypoint ──────────────────────────────────────────────────────────

async def run_patch_monitor_agent() -> str:
    """
    Run the multi-platform patch monitor AI agent using Semantic Kernel.

    Builds a Kernel with AzureChatCompletion, registers the PatchMonitorPlugin,
    and lets the ChatCompletionAgent drive the tool-call loop automatically.

    Returns:
        The final natural-language response from the agent.
    """
    # ── Build kernel ─────────────────────────────────────────────────────────
    kernel = Kernel()
    kernel.add_service(
        AzureChatCompletion(
            deployment_name=os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o"),
            endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
            api_key=os.environ["AZURE_OPENAI_API_KEY"],
            api_version=os.environ.get("AZURE_OPENAI_API_VERSION", "2024-10-21"),
        )
    )
    kernel.add_plugin(PatchMonitorPlugin(), plugin_name="PatchMonitor")

    # Auto function calling — SK drives the tool loop until the LLM stops calling tools
    settings = OpenAIChatPromptExecutionSettings(
        temperature=0.2,
        function_choice_behavior=FunctionChoiceBehavior.Auto(),
    )

    agent = ChatCompletionAgent(
        kernel=kernel,
        name="PatchMonitorAgent",
        instructions=SYSTEM_PROMPT,
        execution_settings=settings,
    )

    # ── Seed the conversation ─────────────────────────────────────────────────
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    last_check_date = get_last_check_time()

    history = ChatHistory()
    history.add_user_message(
        f"Today is {today}. "
        f"Check for new security advisories on both platforms (redhat, suse) "
        f"published after {last_check_date}. "
        "Analyse them and notify the security team if any are found."
    )

    # ── Run agent — SK drives the tool-call loop automatically ──────────────
    final_response = "Agent completed with no output."
    async for message in agent.invoke(messages=history):
        if message.content:
            final_response = str(message.content)

    logging.info(f"SK Agent completed. Response:\n{final_response}")
    return final_response
