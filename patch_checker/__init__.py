"""
patch_checker/__init__.py
Entry point for Red Hat security advisory fetching.
Supported platforms: redhat
"""

from .redhat import fetch_redhat_advisories
from .utils import format_advisory_summary

SUPPORTED_PLATFORMS = ["redhat"]

_FETCHERS = {
    "redhat": fetch_redhat_advisories,
}


def fetch_advisories(platform: str, after_date: str | None = None) -> list[dict]:
    """
    Fetch security advisories for the given platform.

    Args:
        platform:   One of 'redhat', 'suse', 'windows' (case-insensitive).
        after_date: ISO date string YYYY-MM-DD — only return advisories after this date.

    Returns:
        List of normalised advisory dicts, each containing at minimum:
            id, platform, severity, synopsis, issued_date, CVEs, url
    """
    key = platform.lower().strip()
    fetcher = _FETCHERS.get(key)
    if not fetcher:
        raise ValueError(
            f"Unsupported platform '{platform}'. Supported: {SUPPORTED_PLATFORMS}"
        )
    return fetcher(after_date=after_date)


__all__ = [
    "fetch_advisories",
    "fetch_redhat_advisories",
    "format_advisory_summary",
    "SUPPORTED_PLATFORMS",
]
