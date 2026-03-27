import { PageShell } from "@/components/PageShell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useState, useEffect, useCallback } from "react";
import { Play, Terminal, AlertTriangle, Loader2, RefreshCw, Send, Crosshair } from "lucide-react";
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

const statusColor = (s: string) =>
  s === "completed"
    ? "status-badge-low"
    : s === "running"
      ? "status-badge-info"
      : s === "queued"
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

const NetworkScans = () => {
  const [activeTab, setActiveTab] = useState("scans");
  const { toast } = useToast();

  // ── All Scans tab state ───────────────────────────────────────────
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  const fetchHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      setScanHistory(await scansApi.history());
    } catch (e) {
      if (e instanceof ApiError) toast({ title: "Error", description: e.message, variant: "destructive" });
    } finally {
      setHistoryLoading(false);
    }
  }, [toast]);

  useEffect(() => { fetchHistory(); }, [fetchHistory]);

  // ── New Scan tab state ────────────────────────────────────────────
  const [targetIp, setTargetIp] = useState("");
  const [showDisclaimer, setShowDisclaimer] = useState(false);
  const [scanStarting, setScanStarting] = useState(false);

  const handleStartScan = () => {
    if (!targetIp.trim()) {
      toast({ title: "Error", description: "Enter a target IP address.", variant: "destructive" });
      return;
    }
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
      setActiveTab("monitor");
      fetchHistory();
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Failed to start scan";
      toast({ title: "Scan Failed", description: msg, variant: "destructive" });
    } finally {
      setScanStarting(false);
    }
  };

  // ── Scan Request (analyst requests IP authorization) ────────────
  const [requestIp, setRequestIp] = useState("");
  const [requestReason, setRequestReason] = useState("");
  const [requesting, setRequesting] = useState(false);

  const handleRequestAuth = async () => {
    if (!requestIp.trim()) {
      toast({ title: "Error", description: "Enter an IP address.", variant: "destructive" });
      return;
    }
    if (!requestReason.trim()) {
      toast({ title: "Error", description: "Provide a reason for the request.", variant: "destructive" });
      return;
    }
    setRequesting(true);
    try {
      const res = await scansApi.requestScan(requestIp.trim(), requestReason.trim());
      toast({ title: "Request Submitted", description: res.message });
      setRequestIp("");
      setRequestReason("");
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Failed to submit request";
      toast({ title: "Request Failed", description: msg, variant: "destructive" });
    } finally {
      setRequesting(false);
    }
  };

  // ── Live Monitor tab state ────────────────────────────────────────
  const [activeScanId, setActiveScanId] = useState<number | null>(null);
  const [activeScanStatus, setActiveScanStatus] = useState<ScanStatus | null>(null);
  const [monitorLoading, setMonitorLoading] = useState(false);

  // Poll scan status while it's queued or running
  useEffect(() => {
    if (activeScanId == null) return;

    let cancelled = false;

    const poll = async () => {
      setMonitorLoading(true);
      try {
        const s = await scansApi.status(activeScanId);
        if (!cancelled) setActiveScanStatus(s);
        // Stop polling if terminal
        if (s.status === "completed" || s.status === "failed") {
          fetchHistory();
          return;
        }
        // Continue polling
        if (!cancelled) setTimeout(poll, 3000);
      } catch {
        // stop polling on error
      } finally {
        if (!cancelled) setMonitorLoading(false);
      }
    };

    poll();
    return () => { cancelled = true; };
  }, [activeScanId, fetchHistory]);

  // ── Vulnerabilities tab state ─────────────────────────────────────
  const [allVulns, setAllVulns] = useState<Vulnerability[]>([]);
  const [vulnsLoading, setVulnsLoading] = useState(false);

  const fetchVulns = useCallback(async () => {
    setVulnsLoading(true);
    try {
      setAllVulns(await vulnsApi.all());
    } catch {
      // 404 means no vulns — that's fine
      setAllVulns([]);
    } finally {
      setVulnsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (activeTab === "vulns") fetchVulns();
  }, [activeTab, fetchVulns]);

  // ── Scan results (when user clicks a completed scan) ──────────────
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

  // Parse results_json safely
  const parsedResults = (() => {
    if (!selectedScan?.results_json) return null;
    try { return JSON.parse(selectedScan.results_json); } catch { return null; }
  })();

  // ── Exploit execution ─────────────────────────────────────────────
  const EXPLOIT_TYPES = [
    { value: "ssh_brute_force", label: "SSH Brute Force" },
    { value: "ftp_brute_force", label: "FTP Brute Force" },
    { value: "ms17_010_check", label: "MS17-010 Check" },
    { value: "shellshock_cgi", label: "Shellshock CGI" },
  ];
  const [exploitVuln, setExploitVuln] = useState<Vulnerability | null>(null);
  const [exploitType, setExploitType] = useState("");
  const [exploitTargetIp, setExploitTargetIp] = useState("");
  const [showExploitDisclaimer, setShowExploitDisclaimer] = useState(false);
  const [exploitRunning, setExploitRunning] = useState(false);

  const handleExploitClick = (vuln: Vulnerability) => {
    setExploitVuln(vuln);
    setExploitType("");
    // Try to get the IP from the scan history for this vuln's scan
    const scan = scanHistory.find((s) => s.scan_id === vuln.scan_id);
    setExploitTargetIp(scan?.ip ?? "");
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
        action={`Exploit: ${EXPLOIT_TYPES.find((t) => t.value === exploitType)?.label ?? exploitType}`}
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
            <Button variant="outline" size="sm" onClick={fetchHistory} disabled={historyLoading}>
              <RefreshCw className={`h-3 w-3 mr-1 ${historyLoading ? "animate-spin" : ""}`} /> Refresh
            </Button>
          </div>
          {scanHistory.length === 0 && !historyLoading ? (
            <EmptyState message="No scans yet. Start one from the New Scan tab." />
          ) : (
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
                      onClick={() => viewScanResults(s.scan_id)}
                    >
                      <td className="p-3 font-mono text-accent">SCN-{s.scan_id}</td>
                      <td className="p-3 font-mono">{s.ip ?? "—"}</td>
                      <td className="p-3">{s.user ?? "—"}</td>
                      <td className="p-3"><span className={statusColor(s.status)}>{s.status}</span></td>
                      <td className="p-3 text-muted-foreground">{s.start_time ? new Date(s.start_time).toLocaleString() : "—"}</td>
                      <td className="p-3 text-muted-foreground">{s.end_time ? new Date(s.end_time).toLocaleString() : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </TabsContent>

        {/* ── Live Monitor ───────────────────────────────────────── */}
        <TabsContent value="monitor">
          {activeScanId == null || activeScanStatus == null ? (
            <EmptyState message="No active scan. Start a scan from the New Scan tab to monitor it here." />
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="stat-card">
                <div className="flex items-center gap-2 mb-4">
                  {activeScanStatus.status === "running" || activeScanStatus.status === "queued" ? (
                    <span className="h-2 w-2 rounded-full bg-accent animate-pulse" />
                  ) : null}
                  <h2 className="font-semibold">
                    SCN-{activeScanStatus.scan_id} — {activeScanStatus.status}
                  </h2>
                </div>
                <div className="space-y-3">
                  {(activeScanStatus.status === "running" || activeScanStatus.status === "queued") && (
                    <Progress value={activeScanStatus.status === "queued" ? 5 : 50} className="h-2" />
                  )}
                  {activeScanStatus.status === "completed" && (
                    <Progress value={100} className="h-2" />
                  )}
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
                  {activeScanStatus.status === "completed" && (
                    <Button size="sm" variant="outline" onClick={() => viewScanResults(activeScanStatus.scan_id)}>
                      View Full Results
                    </Button>
                  )}
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
                  {activeScanStatus.status === "running" && (
                    <p className="text-accent animate-pulse">Scan in progress...</p>
                  )}
                  {activeScanStatus.status === "queued" && (
                    <p className="text-muted-foreground">Waiting in queue...</p>
                  )}
                  {activeScanStatus.status === "completed" && (
                    <p className="text-success">Scan completed successfully.</p>
                  )}
                  {activeScanStatus.status === "failed" && (
                    <p className="text-destructive">Scan failed.</p>
                  )}
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

              {parsedResults ? (
                <div className="space-y-4">
                  {/* Summary */}
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

                  {/* Per-host details */}
                  {(parsedResults.hosts as Array<{
                    ip: string;
                    state: string;
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
                            <div key={i} className="text-xs font-mono text-muted-foreground mb-1">
                              Port {v.port} — {v.id}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState message={selectedScan.status === "completed" ? "No detailed results available." : "Scan is still in progress."} />
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
              <Button variant="outline" size="sm" onClick={fetchVulns} disabled={vulnsLoading}>
                <RefreshCw className={`h-3 w-3 mr-1 ${vulnsLoading ? "animate-spin" : ""}`} /> Refresh
              </Button>
            </div>

            {/* Exploit selector dialog (inline) */}
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
                      onChange={(e) => setExploitTargetIp(e.target.value)}
                      placeholder="192.168.1.100"
                      disabled={exploitRunning}
                    />
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs">Exploit Type</Label>
                    <Select value={exploitType} onValueChange={setExploitType}>
                      <SelectTrigger><SelectValue placeholder="Select exploit..." /></SelectTrigger>
                      <SelectContent>
                        {EXPLOIT_TYPES.map((t) => (
                          <SelectItem key={t.value} value={t.value}>{t.label}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="flex items-end">
                    <Button
                      className="gap-2 w-full"
                      disabled={!exploitType || !exploitTargetIp.trim() || exploitRunning}
                      onClick={() => setShowExploitDisclaimer(true)}
                    >
                      {exploitRunning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                      Execute
                    </Button>
                  </div>
                </div>
              </div>
            )}

            {allVulns.length === 0 && !vulnsLoading ? (
              <EmptyState message="No vulnerabilities found yet. Run a scan first." />
            ) : (
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
                      <tr key={v.vuln_id} className="border-b border-border last:border-0 hover:bg-muted/30">
                        <td className="p-3 font-mono text-accent">V-{v.vuln_id}</td>
                        <td className="p-3 font-mono">{v.scan_id != null ? `SCN-${v.scan_id}` : "—"}</td>
                        <td className="p-3 font-mono">{v.port}</td>
                        <td className="p-3 font-mono text-xs">{v.script_id}</td>
                        <td className="p-3"><span className={sevBadge(v.severity)}>{v.severity}</span></td>
                        <td className="p-3 text-muted-foreground max-w-xs truncate">{v.description}</td>
                        <td className="p-3 text-muted-foreground text-xs">{new Date(v.timestamp).toLocaleDateString()}</td>
                        <td className="p-3">
                          <Button variant="outline" size="sm" className="gap-1" onClick={() => handleExploitClick(v)}>
                            <Crosshair className="h-3 w-3" /> Exploit
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
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
                    onChange={(e) => setTargetIp(e.target.value)}
                    disabled={scanStarting}
                  />
                  <p className="text-xs text-muted-foreground">
                    Enter the IP of an authorized target. If not yet authorized, request access from an admin first.
                  </p>
                </div>
              </div>
            </div>

            <Button className="gap-2" onClick={handleStartScan} disabled={scanStarting}>
              {scanStarting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              Start Scan
            </Button>

            {/* Request Authorization */}
            <div className="stat-card space-y-4 border-t border-border pt-6 mt-2">
              <h2 className="font-semibold">Request Target Authorization</h2>
              <p className="text-xs text-muted-foreground">
                If your target IP is not yet authorized, submit a request to your administrator.
              </p>
              <div className="space-y-3">
                <div className="space-y-1">
                  <Label>Target IP</Label>
                  <Input
                    placeholder="e.g., 192.168.1.200"
                    value={requestIp}
                    onChange={(e) => setRequestIp(e.target.value)}
                    disabled={requesting}
                  />
                </div>
                <div className="space-y-1">
                  <Label>Reason</Label>
                  <Textarea
                    placeholder="Why do you need to scan this target?"
                    value={requestReason}
                    onChange={(e) => setRequestReason(e.target.value)}
                    disabled={requesting}
                    rows={3}
                  />
                </div>
              </div>
              <Button variant="outline" className="gap-2" onClick={handleRequestAuth} disabled={requesting}>
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
