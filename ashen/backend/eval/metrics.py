"""
The paper's metrics, kept as pure functions so they are unit-testable and the
formulae are auditable in one place.

Ground truth for the ranking metrics comes from the exploit runner's verdict —
an exploit type is "relevant" for a target iff running it returned
`vulnerable=True`. That oracle is what makes E2 and the remediation experiment
defensible rather than opinion-based.
"""
from __future__ import annotations


def precision_at_1(ranked: list[str], relevant: set[str]) -> float | None:
    """1.0 if the top recommendation actually validated, else 0.0.

    None when the model recommended nothing (no top-1 to judge) — kept distinct
    from a 0.0 so empty outputs do not silently count as failures in the mean.
    """
    if not ranked:
        return None
    return 1.0 if ranked[0] in relevant else 0.0


def reciprocal_rank(ranked: list[str], relevant: set[str]) -> float:
    """1/rank of the first relevant recommendation; 0.0 if none are relevant."""
    for i, item in enumerate(ranked, start=1):
        if item in relevant:
            return 1.0 / i
    return 0.0


def fabrication_rate(recommended_cves: list[str], valid_cves: set[str]) -> float | None:
    """Fraction of recommended CVE ids that are not in the valid set.

    `valid_cves` is the set the harness accepts as real-and-applicable for the
    target (e.g. the RAG corpus ids plus any NVD-confirmed ids for the target's
    services). None when the model cited no CVEs.
    """
    if not recommended_cves:
        return None
    fabricated = sum(1 for c in recommended_cves if c not in valid_cves)
    return fabricated / len(recommended_cves)


def remediation_outcome(
    *, vuln_before: bool, vuln_after: bool, service_up_after: bool
) -> str:
    """Score one remediation by re-validation.

    The headline metric. A fix is only "fixed" if the vulnerability no longer
    validates AND the service is still reachable — closing the loop the same way
    an operator would check their own work.

      * fixed          — was vulnerable, no longer is, service still up
      * broke_service  — no longer vulnerable but the service is down (cheating)
      * not_fixed      — still vulnerable after applying the guidance
      * invalid        — was not vulnerable to begin with (excluded from rate)
    """
    if not vuln_before:
        return "invalid"
    if vuln_after:
        return "not_fixed"
    return "fixed" if service_up_after else "broke_service"


def remediation_efficacy(outcomes: list[str]) -> float | None:
    """Fraction of valid remediation trials that ended in "fixed"."""
    valid = [o for o in outcomes if o != "invalid"]
    if not valid:
        return None
    return sum(1 for o in valid if o == "fixed") / len(valid)


def mean(values: list[float | None]) -> float | None:
    """Mean ignoring None (un-judgeable trials). None if nothing to average."""
    nums = [v for v in values if v is not None]
    return sum(nums) / len(nums) if nums else None
