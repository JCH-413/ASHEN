"""
CSRF protection middleware.

Requires a custom header (X-CSRF-Token) on all state-changing requests
(POST, PUT, PATCH, DELETE). Browsers will not attach custom headers to
cross-origin requests without CORS preflight approval, so this blocks
forged form submissions from malicious sites.

Safe methods (GET, HEAD, OPTIONS) and auth login endpoints are exempt.
"""
import os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Endpoints that must work without the CSRF header (login flows)
EXEMPT_PATHS = {
    "/auth/admin-login",
    "/auth/user-login",
}

# Allow disabling in tests via env var
CSRF_ENABLED = os.getenv("CSRF_ENABLED", "true").lower() not in ("0", "false", "no")


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not CSRF_ENABLED:
            return await call_next(request)

        if request.method in SAFE_METHODS:
            return await call_next(request)

        if request.url.path in EXEMPT_PATHS:
            return await call_next(request)

        if not request.headers.get(CSRF_HEADER):
            return JSONResponse(
                status_code=403,
                content={"detail": "Missing CSRF token header"},
            )

        return await call_next(request)
