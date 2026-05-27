"""
patch_checker/utils.py
Shared formatting utilities used across the patch_checker package and notifier.
"""


def format_advisory_summary(advisory: dict) -> str:
    """
    Format a single advisory into a human-readable string for the email body.
    Works for all supported platforms (redhat, suse, windows).
    """
    advisory_id  = advisory.get("RHSA") or advisory.get("id", "Unknown")
    platform     = advisory.get("platform", "redhat").upper()
    severity     = advisory.get("severity", "N/A").upper()
    synopsis     = advisory.get("synopsis", "No synopsis available")
    release_date = advisory.get("issued_date") or advisory.get("release_date", "Unknown")
    cves         = advisory.get("CVEs", [])
    cve_list     = ", ".join(cves) if cves else "None listed"
    url          = advisory.get("url") or f"https://access.redhat.com/errata/{advisory_id}"

    return (
        f"Platform : {platform}\n"
        f"Advisory : {advisory_id}\n"
        f"Severity : {severity}\n"
        f"Synopsis : {synopsis}\n"
        f"Released : {release_date}\n"
        f"CVEs     : {cve_list}\n"
        f"Details  : {url}\n"
        f"{'-' * 60}"
    )
