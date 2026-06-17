"""
Turn the LLM's free-text recommendation into structured, scorable data.

The recommender emits prose ("Exploitation Order:\n\n1. Port 445 — EternalBlue
(MS17-010) ..."). Two things have to be extracted from it:

  * `parse_ranked_exploit_types` — the ORDERED list of ASHEN exploit types the
    model recommended, mapped through a synonym table. This is what E2's
    ranking metrics (Precision@1, MRR) are computed against, using the exploit
    runner's verdict as ground truth.

  * `extract_cve_ids` — every CVE id the model mentioned, for E1's fabrication
    rate (a recommended CVE that does not exist / does not apply is a
    hallucination).

The synonym table is the one piece a reviewer will poke at, so it is explicit
and kept here as the single source of truth. There are only four exploit types,
which keeps the mapping auditable.
"""
from __future__ import annotations

import re

from app.services.exploits import REGISTRY

# Canonical exploit types, from the live registry — the only valid targets.
CANONICAL: tuple[str, ...] = tuple(REGISTRY.keys())

# Surface forms the model uses -> canonical exploit_type. Lower-cased matching.
# Order within a value does not matter; longer/more-specific phrases are tried
# first (see _match) so "ssh brute force" wins over a bare "ssh".
SYNONYMS: dict[str, str] = {
    # ms17_010_check
    "ms17_010": "ms17_010_check",
    "ms17-010": "ms17_010_check",
    "ms17010": "ms17_010_check",
    "eternalblue": "ms17_010_check",
    "eternal blue": "ms17_010_check",
    "smb_ms17": "ms17_010_check",
    "smbghost": "ms17_010_check",  # mis-attribution we still map to the SMB check
    # ssh_brute_force
    "ssh_brute_force": "ssh_brute_force",
    "ssh brute force": "ssh_brute_force",
    "ssh bruteforce": "ssh_brute_force",
    "ssh brute-force": "ssh_brute_force",
    "ssh password": "ssh_brute_force",
    "ssh credential": "ssh_brute_force",
    # ftp_brute_force
    "ftp_brute_force": "ftp_brute_force",
    "ftp brute force": "ftp_brute_force",
    "ftp bruteforce": "ftp_brute_force",
    "ftp brute-force": "ftp_brute_force",
    "ftp password": "ftp_brute_force",
    "ftp credential": "ftp_brute_force",
    # shellshock_cgi
    "shellshock": "shellshock_cgi",
    "shell shock": "shellshock_cgi",
    "cve-2014-6271": "shellshock_cgi",
    "bash cgi": "shellshock_cgi",
}

# Phrases are matched longest-first so specific beats generic.
_ORDERED_SYNONYMS: list[tuple[str, str]] = sorted(
    SYNONYMS.items(), key=lambda kv: len(kv[0]), reverse=True
)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _split_steps(text: str) -> list[str]:
    """Split the recommendation into ordered steps.

    The model is prompted to produce a numbered list ("1.", "2.", ...). We split
    on that so a single step that names two tools does not silently reorder the
    ranking. Falls back to lines if no numbering is present.
    """
    # Break before "N." that starts a step (newline- or start-anchored).
    parts = re.split(r"(?m)^\s*\d+[.)]\s*", text)
    parts = [p.strip() for p in parts if p.strip()]
    if len(parts) > 1:
        return parts
    return [l.strip() for l in text.splitlines() if l.strip()]


def _match(segment: str) -> str | None:
    """Return the canonical exploit type named in a text segment, or None."""
    low = segment.lower()
    for phrase, canonical in _ORDERED_SYNONYMS:
        if phrase in low:
            return canonical
    return None


def parse_ranked_exploit_types(recommendation: str) -> list[str]:
    """Ordered, de-duplicated list of canonical exploit types the model picked.

    Order follows first mention (the model's priority order). Duplicates after
    the first are dropped so the ranking reflects distinct recommendations.
    """
    ranked: list[str] = []
    for step in _split_steps(recommendation):
        hit = _match(step)
        if hit and hit not in ranked:
            ranked.append(hit)
    return ranked


def extract_cve_ids(recommendation: str) -> list[str]:
    """Every distinct CVE id mentioned, upper-cased, in order of appearance."""
    seen: list[str] = []
    for m in _CVE_RE.findall(recommendation):
        cid = m.upper()
        if cid not in seen:
            seen.append(cid)
    return seen
