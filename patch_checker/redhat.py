"""
patch_checker/redhat.py
Fetches RHEL security advisories from the Red Hat Security Data API (CSAF).
API docs: https://docs.redhat.com/en/documentation/red_hat_security_data_api/1.0
"""

import logging
import os
import requests
from datetime import datetime, timezone
from typing import Optional

# CVRF endpoint was deprecated; CSAF is the current standard
RHEL_ADVISORY_API = "https://access.redhat.com/hydra/rest/securitydata/csaf.json"
REQUEST_TIMEOUT = 30  # seconds


def _get_configured_versions() -> list[str]:
    """
    Read RHEL_VERSIONS env var and return a list of RHEL major version numbers.
    Used for post-filtering CSAF results by released package suffixes (.el8., .el9., ...).

    RHEL_VERSIONS=8,9  →  ["8", "9"]
    RHEL_VERSIONS=     →  []  (no filter — return all advisories)
    """
    raw = os.environ.get("RHEL_VERSIONS", "").strip()
    if not raw:
        return []
    return [v.strip() for v in raw.split(",") if v.strip()]


def fetch_redhat_advisories(
    after_date: Optional[str] = None, limit: int = 100
) -> list[dict]:
    """
    Fetch RHEL security advisories published after the given date via the CSAF API.
    Optionally filters by RHEL version using the RHEL_VERSIONS env var.

    Args:
        after_date: ISO date string YYYY-MM-DD. Defaults to today if None.
        limit:      Maximum number of advisories to retrieve.

    Returns:
        List of normalised advisory dicts.
    """
    if not after_date:
        after_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    params: dict = {
        "after": after_date,
        "per_page": limit,
        "isCompressed": "false",
    }
    logging.info(f"[RedHat] Fetching CSAF advisories after {after_date}")

    try:
        response = requests.get(
            RHEL_ADVISORY_API,
            params=params,
            timeout=REQUEST_TIMEOUT,
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        data = response.json()
        raw: list[dict] = data if isinstance(data, list) else data.get("data", [])
    except requests.exceptions.HTTPError as e:
        logging.error(f"[RedHat] HTTP error: {e}")
        return []
    except requests.exceptions.ConnectionError as e:
        logging.error(f"[RedHat] Connection error: {e}")
        return []
    except requests.exceptions.Timeout:
        logging.error("[RedHat] Request timed out")
        return []
    except ValueError as e:
        logging.error(f"[RedHat] Failed to parse response: {e}")
        return []

    # Optional: filter by RHEL version via released package suffixes (.el8, .el9, ...)
    # Match ".el8" without requiring a trailing dot so that sub-versions like
    # ".el8_10." and ".el9_6." are also included.
    versions = _get_configured_versions()
    if versions:
        version_tags = [f".el{v}" for v in versions]
        raw = [
            item for item in raw
            if any(
                any(tag in pkg for tag in version_tags)
                for pkg in item.get("released_packages", [])
            )
        ]
        logging.info(f"[RedHat] After version filter ({versions}): {len(raw)} advisories")

    # Normalise to the common advisory schema
    advisories = []
    for item in raw:
        adv_id = item.get("RHSA", "Unknown")
        cves: list[str] = item.get("CVEs", [])
        packages: list[str] = item.get("released_packages", [])
        # Build a human-readable synopsis from available fields
        pkg_names = [p.split("/")[-1].split("@")[0] for p in packages[:3]]
        synopsis = f"{len(cves)} CVE(s): {', '.join(pkg_names)}" if pkg_names else f"{len(cves)} CVE(s)"
        advisories.append({
            "id":          adv_id,
            "platform":    "redhat",
            "severity":    item.get("severity", "Unknown"),
            "synopsis":    synopsis,
            "description": "Released packages: " + ", ".join(packages[:5]) if packages else "",
            "issued_date": (item.get("released_on") or "")[:10],  # YYYY-MM-DD
            "CVEs":        cves,
            "url":         item.get("resource_url") or f"https://access.redhat.com/errata/{adv_id}",
            # keep raw fields for backward-compatibility
            **item,
        })

    logging.info(f"[RedHat] Fetched {len(advisories)} advisories")
    return advisories


def fetch_advisory_detail(advisory_id: str) -> Optional[dict]:
    """
    Fetch detailed information for a specific advisory ID (e.g. 'RHSA-2024:1234').
    """
    url = f"https://access.redhat.com/hydra/rest/securitydata/csaf/{advisory_id}.json"
    try:
        response = requests.get(
            url, timeout=REQUEST_TIMEOUT, headers={"Accept": "application/json"}
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.warning(f"[RedHat] Could not fetch detail for {advisory_id}: {e}")
        return None
