import { PageShell } from "@/components/PageShell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Lightbulb, Loader2, Send, Bot, Check, X, RotateCcw } from "lucide-react";
import { useState, useEffect, useCallback } from "react";
import { useToast } from "@/hooks/use-toast";
import { EmptyState } from "@/components/EmptyState";
import {
  vulns as vulnsApi,
  exploits as exploitsApi,
  ai as aiApi,
  Vulnerability,
  ExploitListItem,
  ApiError,
} from "@/lib/api";

interface ChatMessage {
  role: "user" | "ai";
  content: string;
}

const RemediationGuidance = () => {
  const { toast } = useToast();

  // Data sources
  const [allVulns, setAllVulns] = useState<Vulnerability[]>([]);
  const [allExploits, setAllExploits] = useState<ExploitListItem[]>([]);
  const [selectedVulnId, setSelectedVulnId] = useState<string>("");
  const [selectedExploitId, setSelectedExploitId] = useState<string>("");

  // Remediation result
  const [guidance, setGuidance] = useState<string>("");
  const [model, setModel] = useState<string>("");
  const [generatedAt, setGeneratedAt] = useState<string>("");
  const [generating, setGenerating] = useState(false);
  const [reviewAction, setReviewAction] = useState<string>("");

  // Chat
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    { role: "ai", content: "Hello! I'm your AI remediation assistant. Select a vulnerability or exploit above, then ask me anything." },
  ]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);

  // Load vulns and exploits
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

  // Generate remediation
  const handleGenerate = async () => {
    if (!selectedVulnId && !selectedExploitId) {
      toast({ title: "Error", description: "Select a vulnerability or exploit first.", variant: "destructive" });
      return;
    }
    setGenerating(true);
    setGuidance("");
    setReviewAction("");
    try {
      const res = await aiApi.remediate({
        vuln_id: selectedVulnId ? Number(selectedVulnId) : undefined,
        exploit_id: selectedExploitId ? Number(selectedExploitId) : undefined,
      });
      setGuidance(res.guidance);
      setModel(res.model);
      setGeneratedAt(res.generated_at);
      toast({ title: "Remediation Generated", description: `Model: ${res.model}` });
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Failed to generate remediation";
      toast({ title: "Error", description: msg, variant: "destructive" });
    } finally {
      setGenerating(false);
    }
  };

  // Review
  const handleReview = async (action: "accept" | "reject" | "regenerate") => {
    try {
      await aiApi.review(action);
      setReviewAction(action);
      toast({ title: `Guidance ${action}ed` });
      if (action === "regenerate") {
        handleGenerate();
      }
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Review failed";
      toast({ title: "Error", description: msg, variant: "destructive" });
    }
  };

  // Chat
  const handleSendChat = async () => {
    if (!chatInput.trim()) return;
    const question = chatInput.trim();
    setChatMessages((prev) => [...prev, { role: "user", content: question }]);
    setChatInput("");
    setChatLoading(true);
    try {
      const res = await aiApi.chat(
        question,
        selectedVulnId ? Number(selectedVulnId) : undefined,
        selectedExploitId ? Number(selectedExploitId) : undefined,
      );
      setChatMessages((prev) => [...prev, { role: "ai", content: res.answer }]);
    } catch {
      setChatMessages((prev) => [...prev, { role: "ai", content: "Sorry, I couldn't process that request. Please try again." }]);
    } finally {
      setChatLoading(false);
    }
  };

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
              <Select value={selectedVulnId} onValueChange={setSelectedVulnId}>
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
              <Select value={selectedExploitId} onValueChange={setSelectedExploitId}>
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
            <Button onClick={handleGenerate} disabled={generating} className="gap-2">
              {generating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lightbulb className="h-4 w-4" />}
              Generate
            </Button>
          </div>

          {/* AI output */}
          {generating ? (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <Loader2 className="h-8 w-8 animate-spin text-accent" />
              <p className="text-sm text-muted-foreground">Generating remediation guidance...</p>
            </div>
          ) : guidance ? (
            <div className="stat-card">
              <div className="flex items-center gap-2 mb-4">
                <Lightbulb className="h-5 w-5 text-accent" />
                <h2 className="font-semibold">Remediation Guidance</h2>
                <span className="ml-auto text-xs text-muted-foreground">
                  Model: {model} | {generatedAt ? new Date(generatedAt).toLocaleString() : ""}
                </span>
              </div>

              <div className="bg-foreground/5 rounded-md p-4 font-mono text-sm whitespace-pre-wrap mb-4">
                {guidance}
              </div>

              <div className="flex gap-2">
                <Button size="sm" variant={reviewAction === "accept" ? "default" : "outline"} className="gap-1" onClick={() => handleReview("accept")}>
                  <Check className="h-3 w-3" /> Accept
                </Button>
                <Button size="sm" variant="outline" className="gap-1" onClick={() => handleReview("reject")}>
                  <X className="h-3 w-3" /> Reject
                </Button>
                <Button size="sm" variant="outline" className="gap-1" onClick={() => handleReview("regenerate")}>
                  <RotateCcw className="h-3 w-3" /> Regenerate
                </Button>
              </div>
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
            {chatMessages.map((msg, i) => (
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
            {chatLoading && (
              <div className="flex justify-start">
                <div className="bg-muted rounded-lg px-3 py-2">
                  <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                </div>
              </div>
            )}
          </div>

          <div className="flex gap-2">
            <Input
              placeholder="Ask about remediation..."
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !chatLoading && handleSendChat()}
              disabled={chatLoading}
            />
            <Button size="icon" onClick={handleSendChat} disabled={chatLoading}>
              <Send className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </div>
    </PageShell>
  );
};

export default RemediationGuidance;
