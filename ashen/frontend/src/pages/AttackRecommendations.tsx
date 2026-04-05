import { PageShell } from "@/components/PageShell";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Crosshair, Loader2, Check, X, RotateCcw, Bot } from "lucide-react";
import { useState, useEffect, useCallback } from "react";
import { useToast } from "@/hooks/use-toast";
import { EmptyState } from "@/components/EmptyState";
import {
  scans as scansApi,
  ai as aiApi,
  vulns as vulnsApi,
  ScanHistoryItem,
  Vulnerability,
  ApiError,
} from "@/lib/api";

const AttackRecommendations = () => {
  const { toast } = useToast();

  // Scan selector
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");

  // Vulnerabilities for the selected scan
  const [scanVulns, setScanVulns] = useState<Vulnerability[]>([]);

  // AI results
  const [recommendation, setRecommendation] = useState<string>("");
  const [model, setModel] = useState<string>("");
  const [generatedAt, setGeneratedAt] = useState<string>("");
  const [generating, setGenerating] = useState(false);
  const [reviewAction, setReviewAction] = useState<string>("");

  // Load scan history
  const fetchScans = useCallback(async () => {
    try {
      const data = await scansApi.history();
      setScanHistory(data.filter((s) => s.status === "completed"));
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => { fetchScans(); }, [fetchScans]);

  // Load vulns when scan changes
  useEffect(() => {
    if (!selectedScanId) { setScanVulns([]); return; }
    vulnsApi.byScan(Number(selectedScanId))
      .then(setScanVulns)
      .catch(() => setScanVulns([]));
  }, [selectedScanId]);

  // Generate recommendations
  const handleGenerate = async () => {
    if (!selectedScanId) return;
    setGenerating(true);
    setRecommendation("");
    setReviewAction("");
    try {
      const res = await aiApi.recommendAttacks(Number(selectedScanId));
      setRecommendation(res.recommendation);
      setModel(res.model);
      setGeneratedAt(res.generated_at);
      toast({ title: "Recommendations Generated", description: `Model: ${res.model}` });
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Failed to generate recommendations";
      toast({ title: "Error", description: msg, variant: "destructive" });
    } finally {
      setGenerating(false);
    }
  };

  // Review action
  const handleReview = async (action: "accept" | "reject" | "regenerate") => {
    try {
      const res = await aiApi.review(action, Number(selectedScanId));
      setReviewAction(action);
      toast({ title: `Recommendation ${action}ed` });

      if (action === "regenerate" && res.new_recommendation) {
        setRecommendation(res.new_recommendation);
        setReviewAction("");
      }
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Review failed";
      toast({ title: "Error", description: msg, variant: "destructive" });
    }
  };

  return (
    <PageShell title="Attack Recommendations">
      <p className="text-sm text-muted-foreground mb-6">
        AI-generated attack recommendations based on real scan and vulnerability data
      </p>

      {/* Scan selector */}
      <div className="flex items-end gap-4 mb-6">
        <div className="space-y-1 flex-1 max-w-xs">
          <label className="text-xs font-medium">Select Scan</label>
          <Select value={selectedScanId} onValueChange={setSelectedScanId}>
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
        <Button onClick={handleGenerate} disabled={!selectedScanId || generating} className="gap-2">
          {generating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Crosshair className="h-4 w-4" />}
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
      {generating ? (
        <div className="flex flex-col items-center justify-center py-16 gap-3">
          <Loader2 className="h-8 w-8 animate-spin text-accent" />
          <p className="text-sm text-muted-foreground">Generating attack recommendations with AI...</p>
        </div>
      ) : recommendation ? (
        <div className="stat-card">
          <div className="flex items-center gap-2 mb-4">
            <Bot className="h-5 w-5 text-accent" />
            <h2 className="font-semibold">AI Recommendation</h2>
            <span className="ml-auto text-xs text-muted-foreground">
              Model: {model} | {generatedAt ? new Date(generatedAt).toLocaleString() : ""}
            </span>
          </div>

          <div className="bg-foreground/5 rounded-md p-4 font-mono text-sm whitespace-pre-wrap mb-4">
            {recommendation}
          </div>

          {/* Review buttons */}
          <div className="flex gap-2">
            <Button
              size="sm"
              variant={reviewAction === "accept" ? "default" : "outline"}
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
        </div>
      ) : (
        <EmptyState message="Select a scan and click Generate to get AI attack recommendations." />
      )}
    </PageShell>
  );
};

export default AttackRecommendations;
