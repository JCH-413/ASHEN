import { PageShell } from "@/components/PageShell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useState, useEffect, useCallback } from "react";
import { Play, Terminal, AlertTriangle, Loader2, RefreshCw, Send, Crosshair, XCircle, ChevronLeft, ChevronRight, ChevronDown, ChevronUp } from "lucide-react";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { EthicalDisclaimer } from "@/components/EthicalDisclaimer";
import { EmptyState } from "@/components/EmptyState";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  scans as scansApi,
  vulns as vulnsApi,
  exploits as exploitsApi,
  ScanHistoryItem,
  ScanStatus,
  Vulnerability,
  ApiError,
} from "@/lib/api";

// ── Helpers ──────────────────────────────────────────────────────────

function validateIp(value: string): string | null {
  const v = value.trim();
  if (!v) return "IP address is required";
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4.test(v)) {
    const parts = v.split(".").map(Number);
    if (parts.every((p) => p >= 0 && p <= 255)) return null;
    return "Invalid IPv4 address (octets must be 0-255)";
  }
  const ipv6 = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  if (ipv6.test(v)) return null;
  if (v === "::1") return null;
  return "Invalid IP address. Enter a valid IPv4 or IPv6 address.";
}

const statusColor = (s: string) =>
  s === "completed" || s === "completed_with_errors"
    ? "status-badge-low"
    : s === "running"
      ? "status-badge-info"
      : s === "queued"
        ? "status-badge-medium"
        : s === "cancelled"
          ? "status-badge-medium"
          : "status-badge-critical";

const sevBadge = (s: string) => {
  const l = s.toLowerCase();
  return l === "critical"
    ? "status-badge-critical"
    : l === "high"
      ? "status-badge-high"
      : l === "medium"
        ? "status-badge-medium"
        : "status-badge-low";
};

const PAGE_SIZE = 20;

const NetworkScans = () => {
  const [activeTab, setActiveTab] = useState("scans");
  const { toast } = useToast();

  // ── All Scans tab state ───────────────────────────────────────────
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);
  const [scanTotal, setScanTotal] = useState(0);
  const [scanPage, setScanPage] = useState(0);
  const [historyLoading, setHistoryLoading] = useState(false);

  const fetchHistory = useCallback(async (page = 0) => {
    setHistoryLoading(true);
    try {
      const res = await scansApi.history(page * PAGE_SIZE, PAGE_SIZE);
      setScanHistory(res.items);
      setScanTotal(res.total);
      setScanPage(page);
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Failed to load scan history";
      toast({ title: "Error", description: msg, variant: "destructive" });
    } finally {
      setHistoryLoading(false);
    }
  }, [toast]);

  useEffect(() => { fetchHistory(); }, [fetchHistory]);

  // ── New Scan tab state ────────────────────────────────────────────
  const [targetIp, setTargetIp] = useState("");
  const [ipError, setIpError] = useState<string | null>(null);
  const [showDisclaimer, setShowDisclaimer] = useState(false);
  const [scanStarting, setScanStarting] = useState(false);

  const handleIpChange = (value: string) => {
    setTargetIp(value);
    setIpError(value.trim() ? validateIp(value) : null);
  };

  const handleStartScan = () => {
    const err = validateIp(targetIp);
    if (err) { setIpError(err); return; }
    setShowDisclaimer(true);
  };

  const handleConfirmScan = async () => {
    setShowDisclaimer(false);
    setScanStarting(true);
    try {
      const res = await scansApi.start(targetIp.trim(), true);
      toast({ title: "Scan Queued", description: res.message });
      setActiveScanId(res.scan_id);
      setTargetIp("");
      setIpError(null);
      setActiveTab("monitor");
      fetchHistory();
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Failed to start scan";
      toast({ title: "Scan Failed", description: msg, variant: "destructive" });
    } finally {
      setScanStarting(false);
    }
  };

  // ── Scan Request ──────────────────────────────────────────────────
  const [requestIp, setRequestIp] = useState("");
  const [requestIpError, setRequestIpError] = useState<string | null>(null);
  const [requestReason, setRequestReason] = useState("");
  const [requesting, setRequesting] = useState(false);

  const handleRequestIpChange = (value: string) => {
    setRequestIp(value);
    setRequestIpError(value.trim() ? validateIp(value) : null);
  };

  const handleRequestAuth = async () => {
    const err = validateIp(requestIp);
    if (err) { setRequestIpError(err); return; }
    if (!requestReason.trim()) {
      toast({ title: "Error", description: "Provide a reason for the request.", variant: "destructive" });
      return;
    }
    setRequesting(true);
    try {
      const res = await scansApi.requestScan(requestIp.trim(), requestReason.trim());
      toast({ title: "Request Submitted", description: res.message });
      setRequestIp(""); setRequestIpError(null); setRequestReason("");
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Failed to submit request";
      toast({ title: "Request Failed", description: msg, variant: "destructive" });
    } finally {
      setRequesting(false);
    }
  };

  // ── Live Monitor ──────────────────────────────────────────────────
  const [activeScanId, setActiveScanId] = useState<number | null>(null);
  const [activeScanStatus, setActiveScanStatus] = useState<ScanStatus | null>(null);
  const [monitorLoading, setMonitorLoading] = useState(false);
  const [pollError, setPollError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);

  const handleScanRowClick = (s: ScanHistoryItem) => {
    if (s.status === "running" || s.status === "queued") {
      setActiveScanId(s.scan_id);
      setActiveScanStatus(null);
      setPollError(null);
      setActiveTab("monitor");
    } else {
      viewScanResults(s.scan_id);
    }
  };

  const handleCancelScan = async () => {
    if (activeScanId == null) return;
    setCancelling(true);
    try {
      await scansApi.cancel(activeScanId);
      toast({ title: "Scan Cancelled", description: `Scan SCN-${activeScanId} was cancelled.` });
      setActiveScanStatus((prev) => prev ? { ...prev, status: "cancelled" } : prev);
      fetchHistory();
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Failed to cancel scan";
      toast({ title: "Error", description: msg, variant: "destructive" });
    } finally {
      setCancelling(false);
    }
  };

  useEffect(() => {
    if (activeScanId == null) return;
    let cancelled = false;
    const poll = async () => {
      setMonitorLoading(true);
      setPollError(null);
      try {
        const s = await scansApi.status(activeScanId);
        if (!cancelled) setActiveScanStatus(s);
        if (["completed", "completed_with_errors", "failed", "cancelled"].includes(s.status)) {
          fetchHistory();
          return;
        }
        if (!cancelled) setTimeout(poll, 3000);
      } catch (e) {
        if (!cancelled) {
          setPollError(e instanceof ApiError ? e.message : "Polling failed — will retry");
          if (!cancelled) setTimeout(poll, 8000);
        }
      } finally {
        if (!cancelled) setMonitorLoading(false);
      }
    };
    poll();
    return () => { cancelled = true; };
  }, [activeScanId, fetchHistory]);

  // ── Vulnerabilities ───────────────────────────────────────────────
  const [allVulns, setAllVulns] = useState<Vulnerability[]>([]);
  const [vulnsTotal, setVulnsTotal] = useState(0);
  const [vulnsPage, setVulnsPage] = useState(0);
  const [vulnsLoading, setVulnsLoading] = useState(false);
  const [vulnsError, setVulnsError] = useState<string | null>(null);
  const [vulnFilterSev, setVulnFilterSev] = useState<string>("");
  const [vulnFilterPort, setVulnFilterPort] = useState("");
  const [vulnFilterScan, setVulnFilterScan] = useState("");
  const [expandedVuln, setExpandedVuln] = useState<number | null>(null);

  const fetchVulns = useCallback(async (page = 0) => {
    setVulnsLoading(true);
    setVulnsError(null);
    try {
      const res = await vulnsApi.all({
        severity: vulnFilterSev || undefined,
        port: vulnFilterPort ? Number(vulnFilterPort) : undefined,
        scan_id: vulnFilterScan ? Number(vulnFilterScan) : undefined,
        skip: page * PAGE_SIZE,
        limit: PAGE_SIZE,
      });
      setAllVulns(res.items);
      setVulnsTotal(res.total);
      setVulnsPage(page);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        setAllVulns([]);
        setVulnsTotal(0);
      } else {
        setVulnsError(e instanceof ApiError ? e.message : "Failed to load vulnerabilities");
        setAllVulns([]);
      }
    } finally {
      setVulnsLoading(false);
    }
  }, [vulnFilterSev, vulnFilterPort, vulnFilterScan]);

  useEffect(() => {
    if (activeTab === "vulns") fetchVulns();
  }, [activeTab, fetchVulns]);

  // ── Results ───────────────────────────────────────────────────────
  const [selectedScan, setSelectedScan] = useState<ScanStatus | null>(null);
  const [resultsLoading, setResultsLoading] = useState(false);

  const viewScanResults = async (scanId: number) => {
    setResultsLoading(true);
    try {
      const s = await scansApi.status(scanId);
      setSelectedScan(s);
      setActiveTab("results");
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Failed to load results";
      toast({ title: "Error", description: msg, variant: "destructive" });
    } finally {
      setResultsLoading(false);
    }
  };

  const parsedResults = (() => {
    if (!selectedScan?.results_json) return null;
    try {
      const parsed = JSON.parse(selectedScan.results_json);
      return parsed.scan_results ?? parsed;
    } catch { return null; }
  })();

  const extractionError = (() => {
    if (!selectedScan?.results_json) return null;
    try {
      const parsed = JSON.parse(selectedScan.results_json);
      return parsed.extraction_error ?? parsed.error ?? null;
    } catch { return null; }
  })();

  // ── Exploit execution ─────────────────────────────────────────────
  const [exploitTypes, setExploitTypes] = useState<{ key: string; tool: string }[]>([]);
  const [exploitVuln, setExploitVuln] = useState<Vulnerability | null>(null);
  const [exploitType, setExploitType] = useState("");
  const [exploitTargetIp, setExploitTargetIp] = useState("");
  const [exploitIpError, setExploitIpError] = useState<string | null>(null);
  const [showExploitDisclaimer, setShowExploitDisclaimer] = useState(false);
  const [exploitRunning, setExploitRunning] = useState(false);

  // Fetch exploit types from backend on mount
  useEffect(() => {
    exploitsApi.types().then((res) => setExploitTypes(res.exploit_types)).catch(() => {
      // Fallback to hardcoded if endpoint unavailable
      setExploitTypes([
        { key: "ssh_brute_force", tool: "metasploit" },
        { key: "ftp_brute_force", tool: "hydra" },
        { key: "ms17_010_check", tool: "metasploit" },
        { key: "shellshock_cgi", tool: "curl" },
      ]);
    });
  }, []);

  const exploitLabel = (key: string) =>
    key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

  const handleExploitClick = (vuln: Vulnerability) => {
    setExploitVuln(vuln);
    setExploitType("");
    setExploitIpError(null);
    const scan = scanHistory.find((s) => s.scan_id === vuln.scan_id);
    const ip = scan?.ip ?? "";
    setExploitTargetIp(ip);
    if (!ip) setExploitIpError("Could not resolve target IP from scan. Enter it manually.");
  };

  const handleExploitTargetIpChange = (value: string) => {
    setExploitTargetIp(value);
    setExploitIpError(value.trim() ? validateIp(value) : "Target IP is required");
  };

  const handleExploitRun = () => {
    const err = validateIp(exploitTargetIp);
    if (err) { setExploitIpError(err); return; }
    if (!exploitType) {
      toast({ title: "Error", description: "Select an exploit type.", variant: "destructive" });
      return;
    }
    setShowExploitDisclaimer(true);
  };

  const handleExploitConfirm = async () => {
    setShowExploitDisclaimer(false);
    if (!exploitTargetIp.trim() || !exploitType) return;
    setExploitRunning(true);
    try {
      const res = await exploitsApi.run({
        target_ip: exploitTargetIp.trim(),
        exploit_type: exploitType,
        ack_disclaimer: true,
        scan_id: exploitVuln?.scan_id,
        vuln_id: exploitVuln?.vuln_id,
      });
      toast({ title: "Exploit Queued", description: res.message });
      setExploitVuln(null);
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Failed to run exploit";
      toast({ title: "Exploit Failed", description: msg, variant: "destructive" });
    } finally {
      setExploitRunning(false);
    }
  };

  // ── Pagination helper ─────────────────────────────────────────────
  const PaginationBar = ({ total, page, onPage }: { total: number; page: number; onPage: (p: number) => void }) => {
    const totalPages = Math.ceil(total / PAGE_SIZE);
    if (totalPages <= 1) return null;
    return (
      <div className="flex items-center justify-between mt-4 text-sm text-muted-foreground">
        <span>{total} total &middot; page {page + 1} of {totalPages}</span>
        <div className="flex gap-1">
          <Button variant="outline" size="sm" disabled={page === 0} onClick={() => onPage(page - 1)}>
            <ChevronLeft className="h-3 w-3" />
          </Button>
          <Button variant="outline" size="sm" disabled={page >= totalPages - 1} onClick={() => onPage(page + 1)}>
            <ChevronRight className="h-3 w-3" />
          </Button>
        </div>
      </div>
    );
  };

  return (
    <PageShell title="Network Scan">
      <EthicalDisclaimer
        open={showDisclaimer}
        onConfirm={handleConfirmScan}
        onCancel={() => setShowDisclaimer(false)}
        action="Network Scan"
        target={targetIp}
      />
      <EthicalDisclaimer
        open={showExploitDisclaimer}
        onConfirm={handleExploitConfirm}
        onCancel={() => setShowExploitDisclaimer(false)}
        action={`Exploit: ${exploitLabel(exploitType)}`}
        target={exploitTargetIp}
      />

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <div className="flex items-center justify-between mb-6">
          <TabsList>
            <TabsTrigger value="scans">All Scans</TabsTrigger>
            <TabsTrigger value="monitor">Live Monitor</TabsTrigger>
            <TabsTrigger value="results">Results</TabsTrigger>
            <TabsTrigger value="vulns">Vulnerabilities</TabsTrigger>
            <TabsTrigger value="new">New Scan</TabsTrigger>
          </TabsList>
        </div>

        {/* ── All Scans ──────────────────────────────────────────── */}
        <TabsContent value="scans">
          <div className="flex justify-end mb-3">
            <Button variant="outline" size="sm" onClick={() => fetchHistory(scanPage)} disabled={historyLoading}>
              <RefreshCw className={`h-3 w-3 mr-1 ${historyLoading ? "animate-spin" : ""}`} /> Refresh
            </Button>
          </div>
          {scanHistory.length === 0 && !historyLoading ? (
            <EmptyState message="No scans yet. Start one from the New Scan tab." />
          ) : (
            <>
              <div className="bg-card border border-border rounded-lg overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border bg-muted/50">
                      {["ID", "Target IP", "User", "Status", "Started", "Ended"].map((h) => (
                        <th key={h} className="text-left p-3 font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {scanHistory.map((s) => (
                      <tr
                        key={s.scan_id}
                        className="border-b border-border last:border-0 hover:bg-muted/30 cursor-pointer"
                        onClick={() => handleScanRowClick(s)}
                      >
                        <td className="p-3 font-mono text-accent">SCN-{s.scan_id}</td>
                        <td className="p-3 font-mono">{s.ip ?? "—"}</td>
                        <td className="p-3">{s.user ?? "—"}</td>
                        <td className="p-3">
                          <span className={statusColor(s.status)}>{s.status}</span>
                          {(s.status === "running" || s.status === "queued") && (
                            <span className="ml-2 text-xs text-muted-foreground">(click to monitor)</span>
                          )}
                        </td>
                        <td className="p-3 text-muted-foreground">{s.start_time ? new Date(s.start_time).toLocaleString() : "—"}</td>
                        <td className="p-3 text-muted-foreground">{s.end_time ? new Date(s.end_time).toLocaleString() : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <PaginationBar total={scanTotal} page={scanPage} onPage={fetchHistory} />
            </>
          )}
        </TabsContent>

        {/* ── Live Monitor ───────────────────────────────────────── */}
        <TabsContent value="monitor">
          {activeScanId == null || activeScanStatus == null ? (
            <EmptyState message="No active scan. Start a scan from the New Scan tab, or click a running scan in All Scans to monitor it." />
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="stat-card">
                <div className="flex items-center gap-2 mb-4">
                  {(activeScanStatus.status === "running" || activeScanStatus.status === "queued") && (
                    <span className="h-2 w-2 rounded-full bg-accent animate-pulse" />
                  )}
                  <h2 className="font-semibold">
                    SCN-{activeScanStatus.scan_id} — {activeScanStatus.status}
                  </h2>
                </div>
                <div className="space-y-3">
                  <Progress value={activeScanStatus.progress ?? 0} className="h-2" />
                  <p className="text-xs text-muted-foreground">{activeScanStatus.progress ?? 0}% complete</p>
                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <div>
                      <p className="text-muted-foreground">Start</p>
                      <p className="font-mono">{activeScanStatus.start_time ? new Date(activeScanStatus.start_time).toLocaleString() : "—"}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">End</p>
                      <p className="font-mono">{activeScanStatus.end_time ? new Date(activeScanStatus.end_time).toLocaleString() : "Pending"}</p>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    {(activeScanStatus.status === "completed" || activeScanStatus.status === "completed_with_errors") && (
                      <Button size="sm" variant="outline" onClick={() => viewScanResults(activeScanStatus.scan_id)}>
                        View Full Results
                      </Button>
                    )}
                    {(activeScanStatus.status === "running" || activeScanStatus.status === "queued") && (
                      <Button size="sm" variant="destructive" onClick={handleCancelScan} disabled={cancelling} className="gap-1">
                        {cancelling ? <Loader2 className="h-3 w-3 animate-spin" /> : <XCircle className="h-3 w-3" />}
                        Cancel Scan
                      </Button>
                    )}
                  </div>
                </div>
              </div>

              <div className="stat-card">
                <div className="flex items-center gap-2 mb-3">
                  <Terminal className="h-4 w-4 text-muted-foreground" />
                  <h2 className="font-semibold">Status</h2>
                </div>
                <div className="bg-foreground/5 rounded-md p-3 h-64 overflow-y-auto font-mono text-xs space-y-1">
                  <p className="text-muted-foreground">Scan ID: {activeScanStatus.scan_id}</p>
                  <p className="text-muted-foreground">Status: {activeScanStatus.status}</p>
                  <p className="text-muted-foreground">Progress: {activeScanStatus.progress}%</p>
                  {activeScanStatus.status === "running" && <p className="text-accent animate-pulse">Scan in progress...</p>}
                  {activeScanStatus.status === "queued" && <p className="text-muted-foreground">Waiting in queue...</p>}
                  {activeScanStatus.status === "completed" && <p className="text-success">Scan completed successfully.</p>}
                  {activeScanStatus.status === "completed_with_errors" && <p className="text-warning">Scan completed with extraction errors.</p>}
                  {activeScanStatus.status === "failed" && (
                    <>
                      <p className="text-destructive">Scan failed.</p>
                      {activeScanStatus.error_detail && <p className="text-destructive/80 mt-1">{activeScanStatus.error_detail}</p>}
                    </>
                  )}
                  {activeScanStatus.status === "cancelled" && <p className="text-muted-foreground">Scan was cancelled.</p>}
                  {pollError && <p className="text-destructive mt-2">Polling error: {pollError} — retrying...</p>}
                </div>
              </div>
            </div>
          )}
        </TabsContent>

        {/* ── Results ────────────────────────────────────────────── */}
        <TabsContent value="results">
          {resultsLoading ? (
            <div className="flex justify-center py-12"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>
          ) : selectedScan == null ? (
            <EmptyState message="Select a scan from All Scans to view its results." />
          ) : (
            <div className="space-y-6">
              <div className="flex items-center gap-4">
                <h2 className="font-semibold">Results — SCN-{selectedScan.scan_id}</h2>
                <span className={statusColor(selectedScan.status)}>{selectedScan.status}</span>
              </div>

              {(extractionError || selectedScan.error_detail) && (
                <div className="flex items-center gap-3 p-3 rounded-lg border bg-destructive/5 border-destructive/20">
                  <AlertTriangle className="h-4 w-4 shrink-0 text-destructive" />
                  <div>
                    <p className="text-sm font-medium text-destructive">
                      {selectedScan.status === "failed" ? "Scan Failed" : "Extraction Warning"}
                    </p>
                    <p className="text-xs text-muted-foreground mt-1">{String(extractionError || selectedScan.error_detail).slice(0, 500)}</p>
                  </div>
                </div>
              )}

              {parsedResults ? (
                <div className="space-y-4">
                  <div className="grid grid-cols-3 gap-4">
                    <div className="stat-card text-center">
                      <p className="text-2xl font-bold text-accent">{parsedResults.hosts?.length ?? 0}</p>
                      <p className="text-xs text-muted-foreground">Hosts Discovered</p>
                    </div>
                    <div className="stat-card text-center">
                      <p className="text-2xl font-bold text-foreground">
                        {parsedResults.hosts?.reduce((sum: number, h: { protocols?: Record<string, unknown[]> }) =>
                          sum + Object.values(h.protocols ?? {}).reduce((s: number, ports) => s + (ports as unknown[]).length, 0), 0) ?? 0}
                      </p>
                      <p className="text-xs text-muted-foreground">Open Ports</p>
                    </div>
                    <div className="stat-card text-center">
                      <p className="text-2xl font-bold text-primary">
                        {parsedResults.duration != null ? `${Number(parsedResults.duration).toFixed(1)}s` : "—"}
                      </p>
                      <p className="text-xs text-muted-foreground">Scan Duration</p>
                    </div>
                  </div>

                  {(parsedResults.hosts as Array<{
                    ip: string; state: string;
                    protocols: Record<string, Array<{ port: number; state: string; name: string; product: string; version: string }>>;
                    vulns: Array<{ port: number; id: string; output: string }>;
                  }> ?? []).map((host) => (
                    <div key={host.ip} className="bg-card border border-border rounded-lg overflow-hidden">
                      <div className="px-4 py-3 border-b border-border bg-muted/50 flex items-center gap-3">
                        <span className="font-mono font-semibold text-accent">{host.ip}</span>
                        <span className={host.state === "up" ? "status-badge-low" : "status-badge-critical"}>{host.state}</span>
                      </div>
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="border-b border-border">
                            {["Port", "State", "Service", "Product", "Version"].map((h) => (
                              <th key={h} className="text-left p-3 font-medium text-xs">{h}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {Object.entries(host.protocols ?? {}).flatMap(([, ports]) =>
                            (ports as Array<{ port: number; state: string; name: string; product: string; version: string }>).map((p) => (
                              <tr key={p.port} className="border-b border-border last:border-0 hover:bg-muted/30">
                                <td className="p-3 font-mono">{p.port}</td>
                                <td className="p-3"><span className={p.state === "open" ? "status-badge-low" : "status-badge-medium"}>{p.state}</span></td>
                                <td className="p-3">{p.name}</td>
                                <td className="p-3 text-muted-foreground">{p.product || "—"}</td>
                                <td className="p-3 text-muted-foreground">{p.version || "—"}</td>
                              </tr>
                            ))
                          )}
                        </tbody>
                      </table>
                      {host.vulns?.length > 0 && (
                        <div className="px-4 py-3 border-t border-border bg-destructive/5">
                          <p className="text-xs font-semibold text-destructive mb-2">Vulnerabilities detected ({host.vulns.length})</p>
                          {host.vulns.map((v, i) => (
                            <div key={i} className="text-xs font-mono text-muted-foreground mb-1">Port {v.port} — {v.id}</div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState
                  message={
                    selectedScan.status === "failed" ? "Scan failed. See error details above."
                      : ["completed", "completed_with_errors"].includes(selectedScan.status) ? "No detailed results available."
                        : "Scan is still in progress."
                  }
                />
              )}
            </div>
          )}
        </TabsContent>

        {/* ── Vulnerabilities ────────────────────────────────────── */}
        <TabsContent value="vulns">
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-primary" />
                <h2 className="font-semibold">Discovered Vulnerabilities</h2>
              </div>
              <Button variant="outline" size="sm" onClick={() => fetchVulns(vulnsPage)} disabled={vulnsLoading}>
                <RefreshCw className={`h-3 w-3 mr-1 ${vulnsLoading ? "animate-spin" : ""}`} /> Refresh
              </Button>
            </div>

            {/* Filters */}
            <div className="flex flex-wrap gap-3 items-end">
              <div className="space-y-1">
                <Label className="text-xs">Severity</Label>
                <Select value={vulnFilterSev} onValueChange={(v) => { setVulnFilterSev(v === "all" ? "" : v); setVulnsPage(0); }}>
                  <SelectTrigger className="w-32"><SelectValue placeholder="All" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Port</Label>
                <Input className="w-24" placeholder="Any" value={vulnFilterPort} onChange={(e) => { setVulnFilterPort(e.target.value.replace(/\D/g, "")); setVulnsPage(0); }} />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Scan ID</Label>
                <Input className="w-24" placeholder="Any" value={vulnFilterScan} onChange={(e) => { setVulnFilterScan(e.target.value.replace(/\D/g, "")); setVulnsPage(0); }} />
              </div>
              <Button variant="outline" size="sm" onClick={() => fetchVulns(0)}>Apply</Button>
            </div>

            {vulnsError && (
              <div className="flex items-center gap-3 p-3 rounded-lg border bg-destructive/5 border-destructive/20">
                <AlertTriangle className="h-4 w-4 shrink-0 text-destructive" />
                <p className="text-sm text-destructive">{vulnsError}</p>
              </div>
            )}

            {exploitVuln && (
              <div className="bg-card border border-border rounded-lg p-4 mb-4 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="font-semibold text-sm">Run Exploit — V-{exploitVuln.vuln_id} ({exploitVuln.script_id})</h3>
                  <Button variant="ghost" size="sm" onClick={() => setExploitVuln(null)}>Cancel</Button>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="space-y-1">
                    <Label className="text-xs">Target IP</Label>
                    <Input
                      value={exploitTargetIp}
                      onChange={(e) => handleExploitTargetIpChange(e.target.value)}
                      placeholder="192.168.1.100"
                      disabled={exploitRunning}
                      className={exploitIpError ? "border-destructive" : ""}
                    />
                    {exploitIpError && <p className="text-xs text-destructive">{exploitIpError}</p>}
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs">Exploit Type</Label>
                    <Select value={exploitType} onValueChange={setExploitType}>
                      <SelectTrigger><SelectValue placeholder="Select exploit..." /></SelectTrigger>
                      <SelectContent>
                        {exploitTypes.map((t) => (
                          <SelectItem key={t.key} value={t.key}>{exploitLabel(t.key)} ({t.tool})</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="flex items-end">
                    <Button
                      className="gap-2 w-full"
                      disabled={!exploitType || !exploitTargetIp.trim() || !!exploitIpError || exploitRunning}
                      onClick={handleExploitRun}
                    >
                      {exploitRunning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                      Execute
                    </Button>
                  </div>
                </div>
              </div>
            )}

            {allVulns.length === 0 && !vulnsLoading && !vulnsError ? (
              <EmptyState message="No vulnerabilities found yet. Run a scan first." />
            ) : (
              <>
                <div className="bg-card border border-border rounded-lg overflow-hidden">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border bg-muted/50">
                        {["ID", "Scan", "Port", "Script", "Severity", "Description", "Found", "Action"].map((h) => (
                          <th key={h} className="text-left p-3 font-medium">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {allVulns.map((v) => (
                        <>
                          <tr
                            key={v.vuln_id}
                            className="border-b border-border last:border-0 hover:bg-muted/30 cursor-pointer"
                            onClick={() => setExpandedVuln(expandedVuln === v.vuln_id ? null : v.vuln_id)}
                          >
                            <td className="p-3 font-mono text-accent">V-{v.vuln_id}</td>
                            <td className="p-3 font-mono">{v.scan_id != null ? `SCN-${v.scan_id}` : "—"}</td>
                            <td className="p-3 font-mono">{v.port}</td>
                            <td className="p-3 font-mono text-xs">{v.script_id}</td>
                            <td className="p-3"><span className={sevBadge(v.severity)}>{v.severity}</span></td>
                            <td className="p-3 text-muted-foreground max-w-xs truncate">
                              <span className="flex items-center gap-1">
                                {v.description}
                                {v.raw_output && (expandedVuln === v.vuln_id ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />)}
                              </span>
                            </td>
                            <td className="p-3 text-muted-foreground text-xs">{new Date(v.timestamp).toLocaleDateString()}</td>
                            <td className="p-3">
                              <Button variant="outline" size="sm" className="gap-1" onClick={(e) => { e.stopPropagation(); handleExploitClick(v); }}>
                                <Crosshair className="h-3 w-3" /> Exploit
                              </Button>
                            </td>
                          </tr>
                          {expandedVuln === v.vuln_id && v.raw_output && (
                            <tr key={`${v.vuln_id}-detail`}>
                              <td colSpan={8} className="p-4 bg-muted/30">
                                <pre className="text-xs font-mono whitespace-pre-wrap max-h-48 overflow-y-auto">{v.raw_output}</pre>
                              </td>
                            </tr>
                          )}
                        </>
                      ))}
                    </tbody>
                  </table>
                </div>
                <PaginationBar total={vulnsTotal} page={vulnsPage} onPage={fetchVulns} />
              </>
            )}
          </div>
        </TabsContent>

        {/* ── New Scan ───────────────────────────────────────────── */}
        <TabsContent value="new">
          <div className="flex items-center gap-3 p-3 rounded-lg border bg-warning/5 border-warning/20 mb-6">
            <AlertTriangle className="h-4 w-4 shrink-0 text-warning" />
            <p className="text-sm">Ensure you have proper authorization before scanning any target. Unauthorized scanning may violate laws and policies.</p>
          </div>

          <div className="max-w-2xl space-y-6">
            <div className="stat-card space-y-4">
              <h2 className="font-semibold">Scan Configuration</h2>
              <div className="space-y-3">
                <div className="space-y-1">
                  <Label>Target IP Address</Label>
                  <Input
                    placeholder="e.g., 192.168.1.100"
                    value={targetIp}
                    onChange={(e) => handleIpChange(e.target.value)}
                    disabled={scanStarting}
                    className={ipError ? "border-destructive" : ""}
                  />
                  {ipError ? <p className="text-xs text-destructive">{ipError}</p> : (
                    <p className="text-xs text-muted-foreground">Enter the IP of an authorized target.</p>
                  )}
                </div>
              </div>
            </div>

            <Button className="gap-2" onClick={handleStartScan} disabled={scanStarting || !!ipError}>
              {scanStarting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              Start Scan
            </Button>

            <div className="stat-card space-y-4 border-t border-border pt-6 mt-2">
              <h2 className="font-semibold">Request Target Authorization</h2>
              <p className="text-xs text-muted-foreground">If your target IP is not yet authorized, submit a request to your administrator.</p>
              <div className="space-y-3">
                <div className="space-y-1">
                  <Label>Target IP</Label>
                  <Input placeholder="e.g., 192.168.1.200" value={requestIp} onChange={(e) => handleRequestIpChange(e.target.value)} disabled={requesting} className={requestIpError ? "border-destructive" : ""} />
                  {requestIpError && <p className="text-xs text-destructive">{requestIpError}</p>}
                </div>
                <div className="space-y-1">
                  <Label>Reason</Label>
                  <Textarea placeholder="Why do you need to scan this target?" value={requestReason} onChange={(e) => setRequestReason(e.target.value)} disabled={requesting} rows={3} />
                </div>
              </div>
              <Button variant="outline" className="gap-2" onClick={handleRequestAuth} disabled={requesting || !!requestIpError}>
                {requesting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
                Submit Request
              </Button>
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </PageShell>
  );
};

export default NetworkScans;
