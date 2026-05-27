"""
patch_checker.py
Polls the Red Hat Security Data API for new security advisories.
API Docs: https://access.redhat.com/labs/securitydataapi/
"""

import requests
import logging
from datetime import datetime, timezone
from typing import Optional

RHEL_ADVISORY_API = "https://access.redhat.com/labs/securitydataapi/cvrf.json"
REQUEST_TIMEOUT = 30  # seconds


def fetch_new_advisories(after_date: Optional[str] = None, limit: int = 100) -> list[dict]:
    """
    Fetch RHEL security advisories published after the given date.

    Args:
        after_date: ISO format date string (YYYY-MM-DD). Defaults to today if None.
        limit: Maximum number of advisories to retrieve per call.

    Returns:
        List of advisory dictionaries.
    """
    if not after_date:
        after_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    params = {
        "after": after_date,
        "limit": limit,
    }

    try:
        logging.info(f"Polling RHEL Security Data API for advisories after {after_date}")
        response = requests.get(
            RHEL_ADVISORY_API,
            params=params,
            timeout=REQUEST_TIMEOUT,
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        data = response.json()

        advisories = data if isinstance(data, list) else data.get("data", [])
        logging.info(f"Fetched {len(advisories)} advisory entries from RHEL API")
        return advisories

    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP error fetching RHEL advisories: {e}")
    except requests.exceptions.ConnectionError as e:
        logging.error(f"Connection error reaching RHEL API: {e}")
    except requests.exceptions.Timeout:
        logging.error("Request to RHEL API timed out")
    except ValueError as e:
        logging.error(f"Failed to parse RHEL API response: {e}")

    return []


def fetch_advisory_detail(advisory_id: str) -> Optional[dict]:
    """
    Fetch detailed information for a specific advisory ID.

    Args:
        advisory_id: e.g. 'RHSA-2024:1234'

    Returns:
        Advisory detail dict or None on failure.
    """
    url = f"https://access.redhat.com/labs/securitydataapi/cvrf/{advisory_id}.json"
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"Accept": "application/json"})
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.warning(f"Could not fetch detail for advisory {advisory_id}: {e}")
        return None


def format_advisory_summary(advisory: dict) -> str:
    """
    Format a single advisory into a human-readable string for the email body.
    """
    advisory_id = advisory.get("RHSA") or advisory.get("id", "Unknown")
    severity = advisory.get("severity", "N/A").upper()
    synopsis = advisory.get("synopsis", "No synopsis available")
    release_date = advisory.get("issued_date") or advisory.get("release_date", "Unknown")
    cves = advisory.get("CVEs", [])
    cve_list = ", ".join(cves) if cves else "None listed"

    return (
        f"Advisory : {advisory_id}\n"
        f"Severity : {severity}\n"
        f"Synopsis : {synopsis}\n"
        f"Released : {release_date}\n"
        f"CVEs     : {cve_list}\n"
        f"Details  : https://access.redhat.com/errata/{advisory_id}\n"
        f"{'-' * 60}"
    )
