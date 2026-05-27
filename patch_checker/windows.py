"""
patch_checker/windows.py
Fetches Windows security updates from the Microsoft Security Response Center (MSRC) API.
API docs: https://api.msrc.microsoft.com/cvrf/v2.0/swagger/index

Authentication:
  - The /updates endpoint is public (no key required for basic listing).
  - Set MSRC_API_KEY env var for higher rate limits.
  - Free API key: https://portal.msrc.microsoft.com/developer

The /updates endpoint returns one entry per monthly Patch Tuesday release.
Each entry contains the DocumentTitle (e.g. "May 2026 Security Updates")
and a CvrfUrl linking to the full CVRF document with individual CVE details.
"""

import logging
import os
from datetime import datetime
from typing import Optional

import requests

MSRC_API_BASE = "https://api.msrc.microsoft.com/cvrf/v2.0"
REQUEST_TIMEOUT = 30  # seconds


def fetch_windows_advisories(
    after_date: Optional[str] = None, limit: int = 100
) -> list[dict]:
    """
    Fetch Windows security updates from the MSRC API.

    Args:
        after_date: ISO date string YYYY-MM-DD — only include updates released after this date.
        limit:      Maximum number of updates to return.

    Returns:
        List of normalised advisory dicts.
    """
    api_key = os.environ.get("MSRC_API_KEY", "")
    headers = {"Accept": "application/json"}
    if api_key:
        headers["api-key"] = api_key

    after_dt: Optional[datetime] = None
    if after_date:
        try:
            after_dt = datetime.strptime(after_date, "%Y-%m-%d")
        except ValueError:
            logging.warning(f"[Windows] Invalid after_date format: {after_date}")

    # ── Fetch the update index ───────────────────────────────────────────────
    try:
        logging.info("[Windows] Fetching security update list from MSRC API")
        resp = requests.get(
            f"{MSRC_API_BASE}/updates",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        updates = resp.json().get("value", [])
    except Exception as e:
        logging.error(f"[Windows] Failed to fetch MSRC updates: {e}")
        return []

    # ── Filter and normalise ─────────────────────────────────────────────────
    advisories: list[dict] = []

    for update in updates:
        release_str = update.get("InitialReleaseDate", "")
        if release_str and after_dt:
            try:
                # MSRC dates are ISO 8601 e.g. "2026-05-12T00:00:00Z"
                release_dt = datetime.fromisoformat(
                    release_str.replace("Z", "+00:00")
                ).replace(tzinfo=None)
                if release_dt <= after_dt:
                    continue
            except ValueError:
                pass

        advisories.append({
            "id":          update.get("ID", ""),
            "platform":    "windows",
            "severity":    update.get("Severity") or "Unknown",
            "synopsis":    update.get("DocumentTitle", update.get("Alias", "")),
            "description": (
                f"Microsoft Security Update — {update.get('Alias', '')}. "
                "See the CVRF document for individual CVE details."
            ),
            "issued_date": release_str[:10] if release_str else "",
            # CVEs are in the per-document CVRF — not fetched here to avoid
            # N extra HTTP calls per update. The LLM can use the CvrfUrl if needed.
            "CVEs": [],
            "url":  update.get("CvrfUrl", ""),
        })

        if len(advisories) >= limit:
            break

    logging.info(f"[Windows] Found {len(advisories)} updates after {after_date}")
    return advisories
