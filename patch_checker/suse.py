"""
patch_checker/suse.py
Fetches SUSE security advisories from the official SUSE OVAL XML feeds.

Supported versions are controlled by the SUSE_VERSIONS env var:
  SUSE_VERSIONS=12,15  (default — covers SLES 12 SP5 legacy + SLES 15 current)

OVAL feed URL pattern:
  https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.server.{version}.xml.gz

Note: The OVAL file is a full history dump; date filtering is performed client-side
by comparing each advisory's <issued date="..."/> against last_check_date.
"""

import gzip
import logging
import os
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Optional

import requests

OVAL_URL_TEMPLATE = (
    "https://ftp.suse.com/pub/projects/security/oval/"
    "suse.linux.enterprise.server.{version}.xml.gz"
)
REQUEST_TIMEOUT = 60  # seconds — larger file than a REST API response

# All elements in a SUSE OVAL file share this default namespace
_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"


def _tag(local: str) -> str:
    return f"{{{_NS}}}{local}"


def _get_configured_versions() -> list[str]:
    """
    Read SUSE_VERSIONS env var and return list of version strings.
    SUSE_VERSIONS=12,15  →  ["12", "15"]
    Falls back to ["12", "15"] if not set.
    """
    raw = os.environ.get("SUSE_VERSIONS", "12,15").strip()
    return [v.strip() for v in raw.split(",") if v.strip()]


def _fetch_one_version(version: str, after_dt: Optional[datetime], limit: int) -> list[dict]:
    """Download and parse the OVAL XML for a single SUSE version."""
    url = OVAL_URL_TEMPLATE.format(version=version)
    try:
        logging.info(f"[SUSE] Downloading OVAL for SLES {version} from {url}")
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        xml_bytes = gzip.decompress(resp.content)
        root = ET.fromstring(xml_bytes)
    except Exception as e:
        logging.error(f"[SUSE] Failed to fetch/parse OVAL for SLES {version}: {e}")
        return []

    advisories: list[dict] = []

    for defn in root.iter(_tag("definition")):
        if defn.get("class") != "vulnerability":
            continue

        meta = defn.find(_tag("metadata"))
        if meta is None:
            continue

        adv = meta.find(_tag("advisory"))
        if adv is None:
            continue

        # Client-side date filter — skip anything not newer than last_check_date
        issued_el = adv.find(_tag("issued"))
        issued_date = issued_el.get("date") if issued_el is not None else None
        if issued_date and after_dt:
            try:
                if datetime.strptime(issued_date, "%Y-%m-%d") <= after_dt:
                    continue
            except ValueError:
                pass

        title    = (meta.findtext(_tag("title")) or "").strip()
        desc     = (meta.findtext(_tag("description")) or "").strip()
        severity = (adv.findtext(_tag("severity")) or "Unknown").strip()

        # Reference: source changed from 'SUSE' to 'SUSE CVE' in current OVAL feeds
        ref = meta.find(f"{_tag('reference')}[@source='SUSE CVE']")
        if ref is None:
            ref = meta.find(f"{_tag('reference')}[@source='SUSE']")
        advisory_id = title if title.startswith("CVE-") else defn.get("id", "")
        ref_url     = ref.get("ref_url", "") if ref is not None else ""

        # CVE list: title is the primary CVE; also extract from advisory/cve hrefs
        cves: list[str] = [title] if title.startswith("CVE-") else []
        for cve_el in adv.findall(_tag("cve")):
            href = cve_el.get("href", "")
            if "/CVE-" in href:
                cve_id = "CVE-" + href.split("/CVE-")[-1].rstrip("/")
                if cve_id not in cves:
                    cves.append(cve_id)

        advisories.append({
            "id":           advisory_id,
            "platform":     "suse",
            "suse_version": f"SLES {version}",
            "severity":     severity,
            "synopsis":     title,
            "description":  desc[:500],
            "issued_date":  issued_date or "",
            "CVEs":         cves,
            "url":          ref_url,
        })

        if len(advisories) >= limit:
            break

    logging.info(f"[SUSE] SLES {version} → {len(advisories)} advisories after filter")
    return advisories


def fetch_suse_advisories(
    after_date: Optional[str] = None, limit: int = 100
) -> list[dict]:
    """
    Fetch SUSE security advisories for all configured SUSE versions.

    Args:
        after_date: ISO date string YYYY-MM-DD — only include advisories after this date.
        limit:      Maximum advisories to return per version.

    Returns:
        Combined list of normalised advisory dicts across all configured versions.
    """
    after_dt: Optional[datetime] = None
    if after_date:
        try:
            after_dt = datetime.strptime(after_date, "%Y-%m-%d")
        except ValueError:
            logging.warning(f"[SUSE] Invalid after_date format: {after_date}")

    versions = _get_configured_versions()
    all_advisories: list[dict] = []

    # De-duplicate across versions — same advisory can appear in both SLES 12 and 15
    seen: set[str] = set()
    for version in versions:
        for adv in _fetch_one_version(version, after_dt, limit):
            if adv["id"] not in seen:
                seen.add(adv["id"])
                all_advisories.append(adv)

    logging.info(f"[SUSE] Total unique advisories across {versions}: {len(all_advisories)}")
    return all_advisories


import gzip
import logging
import os
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Optional

import requests

# Default to SLES 15 — override via SUSE_OVAL_URL env var
DEFAULT_OVAL_URL = (
    "https://ftp.suse.com/pub/projects/security/oval/"
    "suse.linux.enterprise.server.15.xml.gz"
)
REQUEST_TIMEOUT = 60  # seconds — larger file than RedHat API response

# All elements in a SUSE OVAL file use this default namespace
_NS = "http://oval.mitre.org/XMLSchema/oval-definitions-5"


def _tag(local: str) -> str:
    """Return Clark-notation tag: {namespace}localname"""
    return f"{{{_NS}}}{local}"


def fetch_suse_advisories(
    after_date: Optional[str] = None, limit: int = 100
) -> list[dict]:
    """
    Fetch SUSE security advisories from the OVAL XML feed.

    Args:
        after_date: ISO date string YYYY-MM-DD — only include advisories after this date.
        limit:      Maximum number of advisories to return.

    Returns:
        List of normalised advisory dicts.
    """
    oval_url = os.environ.get("SUSE_OVAL_URL", DEFAULT_OVAL_URL)
    after_dt: Optional[datetime] = None
    if after_date:
        try:
            after_dt = datetime.strptime(after_date, "%Y-%m-%d")
        except ValueError:
            logging.warning(f"[SUSE] Invalid after_date format: {after_date}")

    # ── Download & decompress ────────────────────────────────────────────────
    try:
        logging.info(f"[SUSE] Downloading OVAL from {oval_url}")
        resp = requests.get(oval_url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        xml_bytes = gzip.decompress(resp.content)
        root = ET.fromstring(xml_bytes)
    except Exception as e:
        logging.error(f"[SUSE] Failed to fetch/parse OVAL: {e}")
        return []

    # ── Parse definitions ────────────────────────────────────────────────────
    advisories: list[dict] = []

    for defn in root.iter(_tag("definition")):
        if defn.get("class") != "patch":
            continue

        meta = defn.find(_tag("metadata"))
        if meta is None:
            continue

        adv = meta.find(_tag("advisory"))
        if adv is None:
            continue

        # Filter by issued date
        issued_el = adv.find(_tag("issued"))
        issued_date = issued_el.get("date") if issued_el is not None else None
        if issued_date and after_dt:
            try:
                if datetime.strptime(issued_date, "%Y-%m-%d") <= after_dt:
                    continue
            except ValueError:
                pass

        # Extract fields
        title    = (meta.findtext(_tag("title")) or "").strip()
        desc     = (meta.findtext(_tag("description")) or "").strip()
        severity = (adv.findtext(_tag("severity")) or "Unknown").strip()

        ref = meta.find(f"{_tag('reference')}[@source='SUSE']")
        advisory_id = ref.get("ref_id", defn.get("id", "")) if ref is not None else defn.get("id", "")
        ref_url     = ref.get("ref_url", "") if ref is not None else ""

        cves = [
            el.text.strip()
            for el in adv.findall(_tag("cve"))
            if el.text
        ]

        advisories.append({
            "id":          advisory_id,
            "platform":    "suse",
            "severity":    severity,
            "synopsis":    title,
            "description": desc[:500],
            "issued_date": issued_date or "",
            "CVEs":        cves,
            "url":         ref_url,
        })

        if len(advisories) >= limit:
            break

    logging.info(f"[SUSE] Found {len(advisories)} advisories after {after_date}")
    return advisories
