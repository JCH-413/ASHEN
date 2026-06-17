"""
Action-aware grounding: tie retrieved CVE knowledge back to the exploit types
ASHEN can actually run.

The plain RAG path dumps retrieved CVEs into the prompt, which biases the model
toward CVE-shaped actions even when the matching exploit does not exist in the
tool (e.g. it recommends an SMB check because a Samba RCE CVE was retrieved).
This module instead maps each retrieved CVE onto an available exploit type using
that exploit's own `service` + `signatures` declaration, and separates out CVEs
that map to no available exploit. The corpus stays tool-agnostic; adding an
exploit type only changes its adapter, never the corpus.
"""
from __future__ import annotations

from app.services.exploits import RUNNERS


def map_cves_to_exploits(cve_rows: list[dict]) -> tuple[dict[str, list[dict]], list[dict]]:
    """Map retrieved CVEs onto available exploit types.

    Returns (per_exploit, unmatched):
      * per_exploit — exploit_type -> the retrieved CVEs that support it.
      * unmatched   — retrieved CVEs that match no available exploit (these are
        informational; recommending them would be a hallucinated action).

    A CVE supports an exploit iff their `service` agrees (when both are known)
    and one of the exploit's `signatures` appears in the CVE id or description.
    """
    per_exploit: dict[str, list[dict]] = {r.exploit_type: [] for r in RUNNERS}
    unmatched: list[dict] = []

    for cve in cve_rows:
        text = f"{cve.get('id', '')} {cve.get('description', '')}".lower()
        matched = False
        for r in RUNNERS:
            if r.service and cve.get("service") and r.service != cve["service"]:
                continue
            if any(sig in text for sig in r.signatures):
                per_exploit[r.exploit_type].append(cve)
                matched = True
        if not matched:
            unmatched.append(cve)

    return per_exploit, unmatched


def build_grounding_block(cve_rows: list[dict]) -> str:
    """Render the action-aware grounding the recommender prompt consumes."""
    per_exploit, unmatched = map_cves_to_exploits(cve_rows)
    lines = ["Available ASHEN exploit types (recommend ONLY from these):"]
    for r in RUNNERS:
        ev = per_exploit[r.exploit_type]
        if ev:
            ids = "; ".join(f"{c['id']} — {c.get('product', '')}".strip(" —") for c in ev)
            lines.append(
                f"- {r.exploit_type} [service={r.service}, port {r.default_port}]: "
                f"CVE evidence: {ids}"
            )
        else:
            lines.append(
                f"- {r.exploit_type} [service={r.service}, port {r.default_port}]: "
                f"no specific CVE evidence — recommend only if the scan shows this "
                f"service is weak (e.g. weak credentials)"
            )
    if unmatched:
        info = "; ".join(f"{c['id']} ({c.get('product', '')})" for c in unmatched)
        lines.append(
            "Retrieved CVEs with NO matching ASHEN exploit — informational only, "
            f"do NOT recommend or cite these as exploits: {info}"
        )
    return "\n".join(lines)
