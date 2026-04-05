import { PageShell } from "@/components/PageShell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Lightbulb, Loader2, Send, Bot, Check, X, RotateCcw } from "lucide-react";
import { useState, useEffect, useCallback, useRef, useSyncExternalStore } from "react";
import { useToast } from "@/hooks/use-toast";
import { EmptyState } from "@/components/EmptyState";
import {
  vulns as vulnsApi,
  exploits as exploitsApi,
  Vulnerability,
  ExploitListItem,
} from "@/lib/api";
import { remediationStore, RemediationState } from "@/lib/remediation-store";

// ── Hook to subscribe to the singleton store ───────────────────────
function useRemediationStore(): RemediationState {
  return useSyncExternalStore(
    remediationStore.onChange,
    remediationStore.getState,
  );
}

// ── Component ──────────────────────────────────────────────────────
const RemediationGuidance = () => {
  const { toast } = useToast();
  const chatEndRef = useRef<HTMLDivElement>(null);
  const prevErrorRef = useRef("");

  // All state comes from the singleton store
  const store = useRemediationStore();

  // Local-only state (not worth persisting)
  const [allVulns, setAllVulns] = useState<Vulnerability[]>([]);
  const [allExploits, setAllExploits] = useState<ExploitListItem[]>([]);
  const [chatInput, setChatInput] = useState("");

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
    if (prevGeneratingRef.current && !store.generating && store.guidance && !store.lastError) {
      toast({ title: "Remediation Generated", description: "Model: tinyllama" });
    }
    prevGeneratingRef.current = store.generating;
  }, [store.generating, store.guidance, store.lastError, toast]);

  // Auto-scroll chat
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [store.chatMessages, store.chatLoading]);

  // Load dropdown data
  const fetchData = useCallback(async () => {
    try {
      const [v, e] = await Promise.allSettled([vulnsApi.all(), exploitsApi.all()]);
      if (v.status === "fulfilled") setAllVulns(v.value);
      if (e.status === "fulfilled") setAllExploits(e.value);
    } catch {
      // ignore
    }
  }, []);
  useEffect(() => { fetchData(); }, [fetchData]);

  // ── Handlers (delegate to store) ─────────────────────────────────

  const handleGenerate = () => remediationStore.generate();

  const handleReview = (action: "accept" | "reject" | "regenerate") =>
    remediationStore.review(action);

  const handleSendChat = () => {
    if (!chatInput.trim()) return;
    remediationStore.sendChat(chatInput.trim());
    setChatInput("");
  };

  // ── Render ───────────────────────────────────────────────────────

  return (
    <PageShell title="AI Remediations">
      <p className="text-sm text-muted-foreground mb-6">AI-powered remediation guidance based on real vulnerability and exploit data</p>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Remediation Panel - Left 2 cols */}
        <div className="lg:col-span-2 space-y-4">
          {/* Selectors */}
          <div className="flex items-end gap-4">
            <div className="space-y-1 flex-1">
              <label className="text-xs font-medium">Vulnerability</label>
              <Select value={store.selectedVulnId} onValueChange={remediationStore.setSelectedVulnId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select vulnerability..." />
                </SelectTrigger>
                <SelectContent>
                  {allVulns.map((v) => (
                    <SelectItem key={v.vuln_id} value={String(v.vuln_id)}>
                      V-{v.vuln_id} — Port {v.port} ({v.severity}) {v.script_id}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1 flex-1">
              <label className="text-xs font-medium">Exploit</label>
              <Select value={store.selectedExploitId} onValueChange={remediationStore.setSelectedExploitId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select exploit..." />
                </SelectTrigger>
                <SelectContent>
                  {allExploits.map((e) => (
                    <SelectItem key={e.exploit_id} value={String(e.exploit_id)}>
                      E-{e.exploit_id} — {e.exploit_type} ({e.status})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button onClick={handleGenerate} disabled={store.generating} className="gap-2">
              {store.generating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lightbulb className="h-4 w-4" />}
              Generate
            </Button>
          </div>

          {/* AI output */}
          {store.guidance || store.generating ? (
            <div className="stat-card">
              <div className="flex items-center gap-2 mb-4">
                {store.generating ? (
                  <Loader2 className="h-5 w-5 animate-spin text-accent" />
                ) : (
                  <Lightbulb className="h-5 w-5 text-accent" />
                )}
                <h2 className="font-semibold">Remediation Guidance</h2>
                {store.generating ? (
                  <span className="ml-auto text-xs text-muted-foreground">Streaming...</span>
                ) : (
                  <span className="ml-auto text-xs text-muted-foreground">
                    Model: {store.model} | {store.generatedAt ? new Date(store.generatedAt).toLocaleString() : ""}
                  </span>
                )}
              </div>

              <div className="bg-foreground/5 rounded-md p-4 font-mono text-sm whitespace-pre-wrap mb-4 min-h-[100px]">
                {store.guidance || <span className="text-muted-foreground">Waiting for first tokens...</span>}
              </div>

              {!store.generating && store.guidance && (
                <div className="flex gap-2">
                  <Button size="sm" variant={store.reviewAction === "accept" ? "default" : "outline"} className="gap-1" onClick={() => handleReview("accept")}>
                    <Check className="h-3 w-3" /> Accept
                  </Button>
                  <Button size="sm" variant="outline" className="gap-1" onClick={() => handleReview("reject")}>
                    <X className="h-3 w-3" /> Reject
                  </Button>
                  <Button size="sm" variant="outline" className="gap-1" onClick={() => handleReview("regenerate")}>
                    <RotateCcw className="h-3 w-3" /> Regenerate
                  </Button>
                </div>
              )}
            </div>
          ) : (
            <EmptyState message="Select a vulnerability or exploit, then click Generate for AI remediation guidance." />
          )}
        </div>

        {/* Chat Panel - Right col */}
        <div className="stat-card flex flex-col h-[600px]">
          <div className="flex items-center gap-2 mb-3 pb-3 border-b border-border">
            <Bot className="h-5 w-5 text-accent" />
            <h2 className="font-semibold">AI Assistant</h2>
          </div>

          <div className="flex-1 overflow-y-auto space-y-3 mb-3">
            {store.chatMessages.map((msg, i) => (
              <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
                <div className={`max-w-[85%] rounded-lg px-3 py-2 text-sm ${
                  msg.role === "user"
                    ? "bg-primary text-primary-foreground"
                    : "bg-muted text-foreground"
                }`}>
                  <p className="whitespace-pre-wrap">{msg.content}</p>
                </div>
              </div>
            ))}
            {store.chatLoading && (
              <div className="flex justify-start">
                <div className="bg-muted rounded-lg px-3 py-2">
                  <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                </div>
              </div>
            )}
            <div ref={chatEndRef} />
          </div>

          <div className="flex gap-2">
            <Input
              placeholder="Ask about remediation..."
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !store.chatLoading && handleSendChat()}
              disabled={store.chatLoading}
            />
            <Button size="icon" onClick={handleSendChat} disabled={store.chatLoading}>
              <Send className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </div>
    </PageShell>
  );
};

export default RemediationGuidance;
