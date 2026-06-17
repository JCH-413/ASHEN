/**
 * Lightweight, client-side notification store (no backend table).
 *
 * Notifications are DERIVED by polling analyst-visible data (scans, exploits,
 * target requests) and de-duplicated by a stable id, plus PUSHED for events the
 * client already knows about (e.g. a finished remediation). Persisted to
 * localStorage so the unread count survives a refresh.
 */
import { useSyncExternalStore } from "react";
import { scans as scansApi, exploits as exploitsApi } from "./api";

export interface AppNotification {
  id: string;
  type: "scan" | "exploit" | "request" | "remediation";
  message: string;
  ts: number;
}

interface NotifState {
  items: AppNotification[];
  lastSeen: number;
}

const STORAGE_KEY = "ashen_notifications";
const MAX = 50;

function load(): NotifState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) return JSON.parse(raw) as NotifState;
  } catch {
    // ignore corrupt storage
  }
  // First ever load: baseline lastSeen to now so pre-existing history isn't all "unread".
  return { items: [], lastSeen: Date.now() };
}

let state: NotifState = load();
const listeners = new Set<() => void>();

function emit() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {
    // non-critical
  }
  listeners.forEach((fn) => fn());
}

/** Add a notification; no-op if one with the same id already exists. */
export function addNotification(n: AppNotification) {
  if (state.items.some((i) => i.id === n.id)) return;
  state = { ...state, items: [n, ...state.items].slice(0, MAX) };
  emit();
}

export const notifications = {
  getState: () => state,
  subscribe(fn: () => void) {
    listeners.add(fn);
    return () => listeners.delete(fn);
  },
  markAllRead() {
    state = { ...state, lastSeen: Date.now() };
    emit();
  },
};

const toTs = (s?: string | null) => (s ? new Date(s).getTime() : Date.now());

/** Poll analyst-visible data and synthesize notifications (deduped by id). */
export async function refreshNotifications() {
  const [h, ex, reqs] = await Promise.allSettled([
    scansApi.history(0, 50),
    exploitsApi.all(),
    scansApi.myRequests(),
  ]);

  if (h.status === "fulfilled") {
    for (const s of h.value.items) {
      if (["completed", "failed", "completed_with_errors"].includes(s.status)) {
        addNotification({
          id: `scan-${s.scan_id}-${s.status}`,
          type: "scan",
          message: `Scan SCN-${s.scan_id}${s.ip ? ` on ${s.ip}` : ""} ${s.status.replace(/_/g, " ")}`,
          ts: toTs(s.end_time ?? s.start_time),
        });
      }
    }
  }

  if (ex.status === "fulfilled") {
    for (const e of ex.value) {
      if (!["pending", "running"].includes(e.status)) {
        const verdict = e.vulnerable == null ? e.status : e.vulnerable ? "vulnerable" : "not vulnerable";
        addNotification({
          id: `exploit-${e.exploit_id}-${e.status}`,
          type: "exploit",
          message: `Exploit E-${e.exploit_id} (${e.exploit_type}) — ${verdict}`,
          ts: toTs(e.timestamp),
        });
      }
    }
  }

  if (reqs.status === "fulfilled") {
    for (const r of reqs.value) {
      if (r.status !== "pending") {
        addNotification({
          id: `req-${r.request_id}-${r.status}`,
          type: "request",
          message: `Target ${r.target_ip} ${r.status === "approved" ? "authorized" : "denied"}`,
          ts: toTs(r.reviewed_at ?? r.created_at),
        });
      }
    }
  }
}

/** Subscribe a component to the store and derive the unread count. */
export function useNotifications() {
  const s = useSyncExternalStore(notifications.subscribe, notifications.getState);
  const unread = s.items.filter((i) => i.ts > s.lastSeen).length;
  return { items: s.items, unread };
}
