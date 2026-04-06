import { PageShell } from "@/components/PageShell";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Search, X, RefreshCw, Loader2 } from "lucide-react";
import { useState, useEffect, useCallback } from "react";
import { EmptyState } from "@/components/EmptyState";
import { useAuth } from "@/contexts/AuthContext";
import {
  admin as adminApi,
  scans as scansApi,
  vulns as vulnsApi,
  exploits as exploitsApi,
  AuditLog,
  ScanHistoryItem,
  Vulnerability,
  ExploitListItem,
  ApiError,
} from "@/lib/api";

const sevBadge = (s: string) => {
  const l = s.toLowerCase();
  return l === "critical" ? "status-badge-critical" : l === "high" ? "status-badge-high" : l === "medium" ? "status-badge-medium" : "status-badge-low";
};

const DataLogs = () => {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [activeTab, setActiveTab] = useState(isAdmin ? "activity" : "scans");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(false);

  // ── Audit logs (admin only) ──────────────────────────────────────
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);

  const fetchAuditLogs = useCallback(async () => {
    if (!isAdmin) return;
    setLoading(true);
    try {
      setAuditLogs(await adminApi.auditLogs({ limit: 100 }));
    } catch { /* silent */ }
    setLoading(false);
  }, [isAdmin]);

  // ── Scan history ─────────────────────────────────────────────────
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);

  const fetchScans = useCallback(async () => {
    try { const res = await scansApi.history(0, 200); setScanHistory(res.items); } catch { /* silent */ }
  }, []);

  // ── Vulnerabilities ──────────────────────────────────────────────
  const [allVulns, setAllVulns] = useState<Vulnerability[]>([]);

  const fetchVulns = useCallback(async () => {
    try { const res = await vulnsApi.all({ limit: 200 }); setAllVulns(res.items); } catch { setAllVulns([]); }
  }, []);

  // ── Exploit logs ─────────────────────────────────────────────────
  const [allExploits, setAllExploits] = useState<ExploitListItem[]>([]);

  const fetchExploits = useCallback(async () => {
    try { setAllExploits(await exploitsApi.all()); } catch { setAllExploits([]); }
  }, []);

  // Initial fetch
  useEffect(() => {
    fetchAuditLogs();
    fetchScans();
    fetchVulns();
    fetchExploits();
  }, [fetchAuditLogs, fetchScans, fetchVulns, fetchExploits]);

  // Filter audit logs
  const filteredLogs = auditLogs.filter((l) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return l.action.toLowerCase().includes(q) || l.performed_by.toLowerCase().includes(q);
  });

  return (
    <PageShell title="Data / Logs">
      <p className="text-sm text-muted-foreground mb-4">Consolidated audit console — scan history, vulnerabilities, exploits, and system activity</p>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <div className="flex items-center justify-between mb-6">
          <TabsList>
            {isAdmin && <TabsTrigger value="activity">Audit Logs</TabsTrigger>}
            <TabsTrigger value="scans">Scan History</TabsTrigger>
            <TabsTrigger value="vulns">Vulnerabilities</TabsTrigger>
            <TabsTrigger value="attacks">Exploit Logs</TabsTrigger>
          </TabsList>
        </div>

        {/* ── Audit Logs (Admin) ───────────────────────────────── */}
        {isAdmin && (
          <TabsContent value="activity">
            <div className="flex flex-wrap items-center gap-3 mb-4">
              <div className="relative flex-1 min-w-[200px] max-w-sm">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input placeholder="Search actions, users..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9" />
              </div>
              {search && (
                <Button variant="ghost" size="sm" onClick={() => setSearch("")}>
                  <X className="h-3 w-3 mr-1" /> Clear
                </Button>
              )}
              <Button variant="outline" size="sm" onClick={fetchAuditLogs} disabled={loading}>
                <RefreshCw className={`h-3 w-3 mr-1 ${loading ? "animate-spin" : ""}`} /> Refresh
              </Button>
            </div>

            {filteredLogs.length === 0 && !loading ? (
              <EmptyState message="No audit logs found." />
            ) : (
              <div className="bg-card border border-border rounded-lg overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border bg-muted/50">
                      {["ID", "Timestamp", "Performed By", "Action"].map((h) => (
                        <th key={h} className="text-left p-3 font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredLogs.map((l) => (
                      <tr key={l.log_id} className="border-b border-border last:border-0 hover:bg-muted/30">
                        <td className="p-3 font-mono text-accent">{l.log_id}</td>
                        <td className="p-3 font-mono text-xs text-muted-foreground whitespace-nowrap">{new Date(l.timestamp).toLocaleString()}</td>
                        <td className="p-3 font-mono">{l.performed_by}</td>
                        <td className="p-3">{l.action}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="text-xs text-muted-foreground mt-3">Showing {filteredLogs.length} entries</p>
          </TabsContent>
        )}

        {/* ── Scan History ─────────────────────────────────────── */}
        <TabsContent value="scans">
          {scanHistory.length === 0 ? (
            <EmptyState message="No scan history yet." />
          ) : (
            <div className="bg-card border border-border rounded-lg overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/50">
                    {["ID", "Target", "User", "Status", "Started", "Ended"].map((h) => (
                      <th key={h} className="text-left p-3 font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {scanHistory.map((s) => (
                    <tr key={s.scan_id} className="border-b border-border last:border-0 hover:bg-muted/30">
                      <td className="p-3 font-mono text-accent">SCN-{s.scan_id}</td>
                      <td className="p-3 font-mono">{s.ip ?? "—"}</td>
                      <td className="p-3">{s.user ?? "—"}</td>
                      <td className="p-3"><span className={s.status === "completed" ? "status-badge-low" : s.status === "failed" ? "status-badge-critical" : "status-badge-info"}>{s.status}</span></td>
                      <td className="p-3 text-muted-foreground">{s.start_time ? new Date(s.start_time).toLocaleString() : "—"}</td>
                      <td className="p-3 text-muted-foreground">{s.end_time ? new Date(s.end_time).toLocaleString() : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </TabsContent>

        {/* ── Vulnerabilities ──────────────────────────────────── */}
        <TabsContent value="vulns">
          {allVulns.length === 0 ? (
            <EmptyState message="No vulnerabilities recorded." />
          ) : (
            <div className="bg-card border border-border rounded-lg overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/50">
                    {["ID", "Scan", "Port", "Script", "Severity", "Description", "Found"].map((h) => (
                      <th key={h} className="text-left p-3 font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {allVulns.map((v) => (
                    <tr key={v.vuln_id} className="border-b border-border last:border-0 hover:bg-muted/30">
                      <td className="p-3 font-mono text-accent">V-{v.vuln_id}</td>
                      <td className="p-3 font-mono">{v.scan_id != null ? `SCN-${v.scan_id}` : "—"}</td>
                      <td className="p-3 font-mono">{v.port}</td>
                      <td className="p-3 font-mono text-xs">{v.script_id}</td>
                      <td className="p-3"><span className={sevBadge(v.severity)}>{v.severity}</span></td>
                      <td className="p-3 text-muted-foreground max-w-xs truncate">{v.description}</td>
                      <td className="p-3 text-muted-foreground text-xs">{new Date(v.timestamp).toLocaleDateString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </TabsContent>

        {/* ── Exploit Logs ─────────────────────────────────────── */}
        <TabsContent value="attacks">
          {allExploits.length === 0 ? (
            <EmptyState message="No exploit executions recorded." />
          ) : (
            <div className="bg-card border border-border rounded-lg overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-muted/50">
                    {["ID", "Target", "Type", "Tool", "Status", "Vulnerable", "Summary", "Time"].map((h) => (
                      <th key={h} className="text-left p-3 font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {allExploits.map((e) => (
                    <tr key={e.exploit_id} className="border-b border-border last:border-0 hover:bg-muted/30">
                      <td className="p-3 font-mono text-accent">EXP-{e.exploit_id}</td>
                      <td className="p-3 font-mono">{e.target_ip}</td>
                      <td className="p-3">{e.exploit_type}</td>
                      <td className="p-3">{e.tool_used}</td>
                      <td className="p-3"><span className={e.status === "completed" ? "status-badge-low" : e.status === "failed" ? "status-badge-critical" : "status-badge-info"}>{e.status}</span></td>
                      <td className="p-3">{e.vulnerable == null ? "—" : e.vulnerable ? <span className="status-badge-critical">Yes</span> : <span className="status-badge-low">No</span>}</td>
                      <td className="p-3 text-muted-foreground max-w-xs truncate">{e.result_summary ?? "—"}</td>
                      <td className="p-3 text-muted-foreground text-xs">{new Date(e.timestamp).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </TabsContent>
      </Tabs>
    </PageShell>
  );
};

export default DataLogs;
