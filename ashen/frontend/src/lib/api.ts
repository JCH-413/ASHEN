// Centralized API client for ASHEN backend (http://localhost:8000)
// - Injects Bearer token from localStorage
// - Handles 401 by clearing session and redirecting to /login
// - Typed wrappers for every backend endpoint

const BASE_URL = "http://localhost:8000";

// ── Helpers ──────────────────────────────────────────────────────────

function getToken(): string | null {
  return localStorage.getItem("ashen_token");
}

function authHeaders(): Record<string, string> {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function request<T>(
  path: string,
  options: RequestInit = {},
  /** Skip the global 401 redirect (used by login endpoints) */
  skipAuthRedirect = false
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...authHeaders(),
    ...(options.headers as Record<string, string> | undefined),
  };

  const res = await fetch(`${BASE_URL}${path}`, { ...options, headers });

  if (res.status === 401 && !skipAuthRedirect) {
    localStorage.removeItem("ashen_token");
    localStorage.removeItem("ashen_user");
    window.location.href = "/login";
    throw new Error("Session expired");
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(res.status, body.detail || res.statusText);
  }

  return res.json() as Promise<T>;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

// Response types ==================================================================

export interface LoginResponse {
  access_token: string;
  role: string; // "Admin" | "Analyst" from backend
}

export interface ScanHistoryItem {
  scan_id: number;
  ip: string | null;
  user: string | null;
  status: string;
  start_time: string | null;
  end_time: string | null;
}

export interface ScanStatus {
  scan_id: number;
  status: string;
  start_time: string | null;
  end_time: string | null;
  results_json: string | null;
}

export interface Vulnerability {
  vuln_id: number;
  scan_id?: number;
  port: string;
  script_id: string;
  severity: string;
  description: string;
  timestamp: string;
}

export interface ExploitResult {
  exploit_id: number;
  target_ip: string;
  exploit_type: string;
  tool_used: string;
  status: string;
  vulnerable: boolean | null;
  result_summary: string | null;
  raw_output: unknown;
  timestamp: string;
}

export interface ExploitListItem {
  exploit_id: number;
  target_ip: string;
  exploit_type: string;
  tool_used: string;
  status: string;
  vulnerable: boolean | null;
  result_summary: string | null;
  timestamp: string;
}

export interface AuditLog {
  log_id: number;
  action: string;
  performed_by: string;
  timestamp: string;
}

export interface SessionItem {
  session_id: number;
  user_id: number | null;
  admin_id: number | null;
  user_name: string | null;
  user_email: string | null;
  login_time: string | null;
  logout_time: string | null;
  status: string;
}

export interface TargetItem {
  target_id: number;
  ip: string;
  "added by": number; // backend uses space in key
  authorized: boolean;
  created_at: string;
}

export interface ScanRequestItem {
  request_id: number;
  target_ip: string;
  requested_by: number;
  status: string;
  created_at: string;
}

// Auth ==================================================================

export const auth = {
  adminLogin(email: string, password: string) {
    return request<LoginResponse>("/auth/admin-login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }, true);
  },

  userLogin(email: string, password: string) {
    return request<LoginResponse>("/auth/user-login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }, true);
  },

  /** Try user-login first, fall back to admin-login */
  async login(email: string, password: string): Promise<LoginResponse> {
    try {
      return await this.userLogin(email, password);
    } catch (e: unknown) {
      // Fall back to admin-login on 401 (wrong endpoint for this user type)
      const status = (e as { status?: number }).status;
      if (status === 401) {
        return this.adminLogin(email, password);
      }
      throw e;
    }
  },

  adminLogout() {
    return request<{ message: string }>("/auth/admin-logout", { method: "POST" });
  },

  userLogout() {
    return request<{ message: string }>("/auth/user-logout", { method: "POST" });
  },

  createUser(name: string, email: string, password: string) {
    return request<{ message: string }>("/auth/create-user", {
      method: "POST",
      body: JSON.stringify({ name, email, password }),
    });
  },
};

// Users ==================================================================

export const users = {
  me() {
    return request<{ id: number; username: string; email: string }>("/users/me");
  },
};

// Scans ==================================================================

export const scans = {
  start(ip_address: string, ack_disclaimer: boolean) {
    return request<{ scan_id: number; status: string; message: string }>(
      "/scan/start",
      { method: "POST", body: JSON.stringify({ ip_address, ack_disclaimer }) }
    );
  },

  status(scanId: number) {
    return request<ScanStatus>(`/scan/status/${scanId}`);
  },

  history() {
    return request<ScanHistoryItem[]>("/scan/history");
  },

  requestScan(ip_address: string, reason: string) {
    return request<{ message: string; status: string }>("/scan/request-scan", {
      method: "POST",
      body: JSON.stringify({ ip_address, reason }),
    });
  },
};

// ── Vulnerabilities ──────────────────────────────────────────────────

export const vulns = {
  byScan(scanId: number) {
    return request<Vulnerability[]>(`/vulns/by-scan/${scanId}`);
  },

  all() {
    return request<Vulnerability[]>("/vulns/all");
  },
};

// ── Exploits ─────────────────────────────────────────────────────────
// NOTE: POST /exploit/run uses query params (backend convention)

export const exploits = {
  run(params: {
    target_ip: string;
    exploit_type: string;
    ack_disclaimer: boolean;
    scan_id?: number;
    vuln_id?: number;
  }) {
    const qs = new URLSearchParams({
      target_ip: params.target_ip,
      exploit_type: params.exploit_type,
      ack_disclaimer: String(params.ack_disclaimer),
    });
    if (params.scan_id != null) qs.set("scan_id", String(params.scan_id));
    if (params.vuln_id != null) qs.set("vuln_id", String(params.vuln_id));

    return request<{ exploit_id: number; status: string; message: string }>(
      `/exploit/run?${qs.toString()}`,
      { method: "POST" }
    );
  },

  results(exploitId: number) {
    return request<ExploitResult>(`/exploit/results/${exploitId}`);
  },

  all() {
    return request<ExploitListItem[]>("/exploit/all");
  },
};

// Admin ==================================================================

export const admin = {
  auditLogs(params?: {
    performed_by?: string;
    action?: string;
    start?: string;
    end?: string;
    skip?: number;
    limit?: number;
  }) {
    const qs = new URLSearchParams();
    if (params?.performed_by) qs.set("performed_by", params.performed_by);
    if (params?.action) qs.set("action", params.action);
    if (params?.start) qs.set("start", params.start);
    if (params?.end) qs.set("end", params.end);
    if (params?.skip != null) qs.set("skip", String(params.skip));
    if (params?.limit != null) qs.set("limit", String(params.limit));
    const query = qs.toString();
    return request<AuditLog[]>(`/admin/audit-logs${query ? `?${query}` : ""}`);
  },

  sessions(params?: { active_only?: boolean; skip?: number; limit?: number }) {
    const qs = new URLSearchParams();
    if (params?.active_only) qs.set("active_only", "true");
    if (params?.skip != null) qs.set("skip", String(params.skip));
    if (params?.limit != null) qs.set("limit", String(params.limit));
    const query = qs.toString();
    return request<SessionItem[]>(`/admin/sessions${query ? `?${query}` : ""}`);
  },

  targets() {
    return request<TargetItem[]>("/admin/targets");
  },

  addTarget(ip_address: string) {
    return request<{ message: string }>("/admin/targets", {
      method: "POST",
      body: JSON.stringify({ ip_address }),
    });
  },

  scanRequests() {
    return request<ScanRequestItem[]>("/admin/scan-requests");
  },

  reviewScanRequest(requestId: number, approve: boolean) {
    return request<{ message: string }>(
      `/admin/scan-requests/${requestId}/review`,
      { method: "POST", body: JSON.stringify({ approve }) }
    );
  },
};
