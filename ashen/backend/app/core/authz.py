"""
authz.py — the one seam where authorisation policy lives.

Four checks used to be copy-pasted preambles across the scans / exploits / ai /
reports routes (and the AI routes had already drifted out of sync, skipping
several). They now live here, once:

  1. Actor       — the caller's role must match (Analyst-only for offensive actions)
  2. Disclaimer  — the ethical-use acknowledgement must be present
  3. Target gate — the target IP (or a Scan's target) must be an *authorised*
                   TargetSystem; malformed IPs are rejected up front
  4. Rate        — a per-Analyst sliding window for the action's bucket

`require_action(...)` returns a configured FastAPI dependency. A route declares
exactly the checks it needs via one `Depends(require_action(...))` and its body
carries business logic only — policy stops leaking into routes, and auditing the
gate means reading this module, not N route preambles.
"""
import ipaddress
from typing import Callable, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.core import rate_limit
from app.core.db import get_db
from app.models.scan import Scan
from app.models.target_system import TargetSystem
from app.utils.jwt_handler import decode_access_token

bearer_scheme = HTTPBearer()

# Action bucket -> rate-limit checker. Keyed so a route names its bucket, not the
# limiter function.
_RATE: dict[str, Callable[[str], None]] = {
    "scan": rate_limit.check_scan_rate,
    "exploit": rate_limit.check_exploit_rate,
    "ai": rate_limit.check_ai_rate,
    "report": rate_limit.check_report_rate,
}


def _truthy(value) -> bool:
    """Disclaimer flags arrive as real bools (JSON body) or strings (query param)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "on")
    return bool(value)


def _gate_target_ip(db: Session, ip: Optional[str]) -> None:
    """The raw-IP gate (scans, exploits): well-formed *and* admin-authorised."""
    try:
        ip = (ip or "").strip()
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Invalid IP address: {ip!r}")
    authorised = db.query(TargetSystem).filter(
        TargetSystem.ip_address == ip,
        TargetSystem.authorized == True,  # noqa: E712 — SQLAlchemy needs ==
    ).first()
    if not authorised:
        raise HTTPException(
            status_code=403,
            detail="Target IP is not authorized. Only admin-approved IPs are in scope.",
        )


def _gate_scan_target(db: Session, scan_id) -> None:
    """The Scan-derived gate (AI guidance): the Scan exists and its target is authorised."""
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    authorised = db.query(TargetSystem).filter(
        TargetSystem.target_id == scan.target_system_id,
        TargetSystem.authorized == True,  # noqa: E712
    ).first()
    if not authorised:
        raise HTTPException(
            status_code=403,
            detail="The Scan's target is not authorized.",
        )


async def _inputs(request: Request) -> dict:
    """Merge query params and JSON body into one dict for the extractor callables.

    Reading the body here caches it on the Starlette request, so FastAPI's own
    Pydantic body parsing still works for the endpoint.
    """
    data = dict(request.query_params)
    try:
        body = await request.json()
        if isinstance(body, dict):
            data.update(body)
    except Exception:
        pass  # no body / not JSON — query params only
    return data


def require_action(
    *,
    actor: Optional[str] = None,
    disclaimer: bool = False,
    target_from: Optional[Callable[[dict], Optional[str]]] = None,
    scan_target_from: Optional[Callable[[dict], Optional[int]]] = None,
    rate: Optional[str] = None,
):
    """Build a FastAPI dependency enforcing the requested subset of the four checks.

    Checks run in a fixed order — actor, disclaimer, target gate, rate — so the
    most specific rejection (wrong actor) wins over the most expensive (rate).
    Returns the decoded JWT payload, so routes can still read `sub`/`role`.
    """
    if rate is not None and rate not in _RATE:
        raise ValueError(f"unknown rate bucket: {rate!r}")

    async def dependency(
        request: Request,
        credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
        db: Session = Depends(get_db),
    ) -> dict:
        payload = decode_access_token(credentials.credentials)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
            )

        if actor and payload.get("role") != actor:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"{actor} privileges required",
            )

        data = await _inputs(request)

        if disclaimer and not _truthy(data.get("ack_disclaimer")):
            raise HTTPException(
                status_code=400,
                detail="Must acknowledge ethical disclaimer first",
            )

        if target_from is not None:
            _gate_target_ip(db, target_from(data))

        if scan_target_from is not None:
            _gate_scan_target(db, scan_target_from(data))

        if rate:
            _RATE[rate](payload.get("sub"))

        return payload

    return dependency
