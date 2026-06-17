import { PageShell } from "@/components/PageShell";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Crosshair, Loader2, Check, X, RotateCcw, Bot } from "lucide-react";
import { useState, useEffect, useCallback, useRef, useSyncExternalStore } from "react";
import { useToast } from "@/hooks/use-toast";
import { EmptyState } from "@/components/EmptyState";
import {
  scans as scansApi,
  vulns as vulnsApi,
  ScanHistoryItem,
  Vulnerability,
} from "@/lib/api";
import {
  attackRecommendationStore,
  AttackRecommendationState,
} from "@/lib/attack-recommendation-store";

// ── Hook to subscribe to the singleton store ───────────────────────
function useAttackRecommendationStore(): AttackRecommendationState {
  return useSyncExternalStore(
    attackRecommendationStore.onChange,
    attackRecommendationStore.getState,
  );
}

// ── Component ──────────────────────────────────────────────────────
const AttackRecommendations = () => {
  const { toast } = useToast();
  const prevErrorRef = useRef("");

  // All AI state comes from the singleton store
  const store = useAttackRecommendationStore();

  // Local-only state (dropdown data)
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);
  const [scanVulns, setScanVulns] = useState<Vulnerability[]>([]);

  // Show toasts for errors from the store
  useEffect(() => {
    if (store.lastError && store.lastError !== prevErrorRef.current) {
      toast({ title: "Error", description: store.lastError, variant: "destructive" });
    }
    prevErrorRef.current = store.lastError;
  }, [store.lastError, toast]);

  // Show toast when generation finishes
  const prevGeneratingRef = useRef(store.generating);
  useEffect(() => {
    if (prevGeneratingRef.current && !store.generating && store.recommendation && !store.lastError) {
      toast({ title: "Recommendations Generated", description: "Model: llama3.2" });
    }
    prevGeneratingRef.current = store.generating;
  }, [store.generating, store.recommendation, store.lastError, toast]);

  // Load scan history
  const fetchScans = useCallback(async () => {
    try {
      const res = await scansApi.history(0, 200);
      setScanHistory(res.items.filter((s) => s.status === "completed"));
    } catch {
      // ignore
    }
  }, []);
  useEffect(() => { fetchScans(); }, [fetchScans]);

  // Load vulns when scan changes
  useEffect(() => {
    if (!store.selectedScanId) { setScanVulns([]); return; }
    vulnsApi.byScan(Number(store.selectedScanId))
      .then(setScanVulns)
      .catch(() => setScanVulns([]));
  }, [store.selectedScanId]);

  // ── Handlers (delegate to store) ─────────────────────────────────

  const handleGenerate = () => attackRecommendationStore.generate();

  const handleReview = (action: "accept" | "reject" | "regenerate") =>
    attackRecommendationStore.review(action);

  // ── Render ───────────────────────────────────────────────────────

  return (
    <PageShell title="Attack Recommendations">
      <p className="text-sm text-muted-foreground mb-6">
        AI-generated attack recommendations based on real scan and vulnerability data
      </p>

      {/* Scan selector */}
      <div className="flex items-end gap-4 mb-6">
        <div className="space-y-1 flex-1 max-w-xs">
          <label className="text-xs font-medium">Select Scan</label>
          <Select value={store.selectedScanId} onValueChange={attackRecommendationStore.setSelectedScanId}>
            <SelectTrigger>
              <SelectValue placeholder="Choose a completed scan..." />
            </SelectTrigger>
            <SelectContent>
              {scanHistory.map((s) => (
                <SelectItem key={s.scan_id} value={String(s.scan_id)}>
                  SCN-{s.scan_id} — {s.ip ?? "Unknown"} ({new Date(s.start_time ?? "").toLocaleDateString()})
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <Button onClick={handleGenerate} disabled={!store.selectedScanId || store.generating} className="gap-2">
          {store.generating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Crosshair className="h-4 w-4" />}
          Generate
        </Button>
      </div>

      {/* Vulnerability summary for selected scan */}
      {scanVulns.length > 0 && (
        <div className="mb-6">
          <p className="text-xs font-medium text-muted-foreground mb-2">
            Vulnerabilities in this scan ({scanVulns.length})
          </p>
          <div className="grid grid-cols-4 gap-3">
            {["critical", "high", "medium", "low"].map((sev) => {
              const count = scanVulns.filter((v) => v.severity.toLowerCase() === sev).length;
              return (
                <div key={sev} className="stat-card text-center">
                  <p className="text-xl font-bold">{count}</p>
                  <p className="text-xs text-muted-foreground capitalize">{sev}</p>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* AI Output */}
      {store.recommendation || store.generating ? (
        <div className="stat-card">
          <div className="flex items-center gap-2 mb-4">
            {store.generating ? (
              <Loader2 className="h-5 w-5 animate-spin text-accent" />
            ) : (
              <Bot className="h-5 w-5 text-accent" />
            )}
            <h2 className="font-semibold">AI Recommendation</h2>
            {store.generating ? (
              <span className="ml-auto text-xs text-muted-foreground">Streaming...</span>
            ) : (
              <span className="ml-auto text-xs text-muted-foreground">
                Model: {store.model} | {store.generatedAt ? new Date(store.generatedAt).toLocaleString() : ""}
              </span>
            )}
          </div>

          <div className="bg-foreground/5 rounded-md p-4 font-mono text-sm whitespace-pre-wrap mb-4 min-h-[100px]">
            {store.recommendation || <span className="text-muted-foreground">Waiting for first tokens...</span>}
          </div>

          {/* Review buttons */}
          {!store.generating && store.recommendation && (
            <div className="flex gap-2">
              <Button
                size="sm"
                variant={store.reviewAction === "accept" ? "default" : "outline"}
                className="gap-1"
                onClick={() => handleReview("accept")}
              >
                <Check className="h-3 w-3" /> Accept
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="gap-1"
                onClick={() => handleReview("reject")}
              >
                <X className="h-3 w-3" /> Reject
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="gap-1"
                onClick={() => handleReview("regenerate")}
              >
                <RotateCcw className="h-3 w-3" /> Regenerate
              </Button>
            </div>
          )}
        </div>
      ) : (
        <EmptyState message="Select a scan and click Generate to get AI attack recommendations." />
      )}
    </PageShell>
  );
};

export default AttackRecommendations;
