"""
patch_checker/__init__.py
Unified entry point for multi-platform security advisory fetching.
Supported platforms: redhat, suse, windows
"""

from .redhat import fetch_redhat_advisories
from .suse import fetch_suse_advisories
from .utils import format_advisory_summary

SUPPORTED_PLATFORMS = ["redhat", "suse"]

_FETCHERS = {
    "redhat": fetch_redhat_advisories,
    "suse":   fetch_suse_advisories,
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
    "fetch_suse_advisories",
    "format_advisory_summary",
    "SUPPORTED_PLATFORMS",
]
