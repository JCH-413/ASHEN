import { PageShell } from "@/components/PageShell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Lightbulb, Check, X, RotateCcw, ChevronDown, ChevronRight, Link2, Send, Bot } from "lucide-react";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";

type GuidanceStatus = "pending" | "accepted" | "rejected";

interface Remediation {
  vuln: string;
  asset: string;
  severity: string;
  eta: string;
  status: GuidanceStatus;
  steps: { step: string; detail: string }[];
  configSuggestions: string[];
  relatedVulns: string[];
}

const initialRemediations: Remediation[] = [
  {
    vuln: "CVE-2024-21762", asset: "fw-edge-01", severity: "Critical", eta: "Immediate", status: "pending",
    steps: [
      { step: "Upgrade FortiOS firmware", detail: "Download and install FortiOS 7.4.3 or later from the Fortinet support portal." },
      { step: "Apply virtual patching", detail: "Enable IPS with signature FG-VD-54610 to block exploitation attempts." },
      { step: "Restrict SSL VPN access", detail: "Limit SSL VPN access to known IP ranges using firewall policies." },
      { step: "Monitor for IoC", detail: "Check logs for suspicious /remote/logincheck requests with oversized payloads." },
      { step: "Verify remediation", detail: "Re-scan the target to confirm the vulnerability is resolved." },
    ],
    configSuggestions: [
      "set ips-sensor \"critical-protect\" status enable",
      "set ssl-vpn-toggle disable  # if VPN not required",
      "config firewall policy → set srcaddr \"trusted-ips-only\"",
    ],
    relatedVulns: ["CVE-2024-23113", "CVE-2024-21759"],
  },
  {
    vuln: "CVE-2024-3400", asset: "pan-gw-02", severity: "Critical", eta: "Immediate", status: "pending",
    steps: [
      { step: "Apply PAN-OS hotfix", detail: "Install PAN-OS hotfix 10.2.9-h1 or later." },
      { step: "Enable Threat Prevention", detail: "Enable Threat Prevention with signature ID 95187 as interim mitigation." },
      { step: "Disable device telemetry", detail: "Disable the device telemetry feature: set deviceconfig system device-telemetry no." },
      { step: "Review access logs", detail: "Check for suspicious requests to /ssl-vpn/hipreport.esp endpoint." },
    ],
    configSuggestions: [
      "set deviceconfig system device-telemetry device-health-performance no",
      "set threat-prevention signature 95187 action reset-both",
    ],
    relatedVulns: ["CVE-2024-3383"],
  },
  {
    vuln: "CVE-2023-20198", asset: "cisco-sw-07", severity: "Critical", eta: "24 hours", status: "pending",
    steps: [
      { step: "Disable HTTP server", detail: "Immediately disable HTTP/HTTPS server: no ip http server / no ip http secure-server." },
      { step: "Upgrade IOS XE", detail: "Upgrade to a patched IOS XE release." },
      { step: "Audit local accounts", detail: "Check for unauthorized local accounts created via the web UI." },
      { step: "Enable access-class restrictions", detail: "Restrict web UI access via ACLs to management networks only." },
    ],
    configSuggestions: [
      "no ip http server",
      "no ip http secure-server",
      "ip http access-class 99  # ACL for management IPs only",
    ],
    relatedVulns: ["CVE-2023-20273"],
  },
];

interface ChatMessage {
  role: "user" | "ai";
  content: string;
}

const aiResponses: Record<string, string> = {
  "default": "I can help with remediation guidance. Try asking about a specific CVE, hardening steps, or configuration best practices.",
  "cve": "Based on the vulnerability data, I recommend prioritizing firmware upgrades for critical CVEs. Would you like step-by-step instructions for a specific device?",
  "harden": "For system hardening, I suggest: 1) Disable unnecessary services, 2) Apply principle of least privilege, 3) Enable logging and monitoring, 4) Implement network segmentation.",
  "config": "Here's a recommended configuration template for firewall hardening:\n\n```\nset strict-mode enable\nset logging all\nset access-policy deny-default\n```",
};

const RemediationGuidance = () => {
  const [remediations, setRemediations] = useState(initialRemediations);
  const [expanded, setExpanded] = useState<string | null>("CVE-2024-21762");
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    { role: "ai", content: "Hello! I'm your AI remediation assistant. I can help with security hardening, configuration guidance, and vulnerability remediation strategies. What would you like help with?" },
  ]);
  const [chatInput, setChatInput] = useState("");
  const { toast } = useToast();

  const updateStatus = (vuln: string, status: GuidanceStatus) => {
    setRemediations(prev => prev.map(r => r.vuln === vuln ? { ...r, status } : r));
    toast({
      title: status === "accepted" ? "Guidance Accepted" : status === "rejected" ? "Guidance Rejected" : "Guidance Regenerated",
      description: `Remediation for ${vuln} has been ${status}.`,
    });
  };

  const handleSendChat = () => {
    if (!chatInput.trim()) return;
    const msg = chatInput.trim().toLowerCase();
    setChatMessages(prev => [...prev, { role: "user", content: chatInput.trim() }]);
    setChatInput("");

    setTimeout(() => {
      let response = aiResponses.default;
      if (msg.includes("cve") || msg.includes("vuln")) response = aiResponses.cve;
      else if (msg.includes("harden") || msg.includes("secure")) response = aiResponses.harden;
      else if (msg.includes("config") || msg.includes("setting")) response = aiResponses.config;
      setChatMessages(prev => [...prev, { role: "ai", content: response }]);
    }, 800);
  };

  const statusLabel = (s: GuidanceStatus) =>
    s === "accepted" ? "status-badge-low" : s === "rejected" ? "status-badge-critical" : "status-badge-medium";

  return (
    <PageShell title="AI Remediations">
      <p className="text-sm text-muted-foreground mb-6">Post-attack security improvement guidance with AI-assisted recommendations</p>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Remediation Cards - Left 2 cols */}
        <div className="lg:col-span-2 space-y-4">
          <div className="grid grid-cols-3 gap-4 mb-4">
            <div className="stat-card text-center">
              <p className="text-2xl font-bold text-warning">{remediations.filter(r => r.status === "pending").length}</p>
              <p className="text-xs text-muted-foreground">Pending</p>
            </div>
            <div className="stat-card text-center">
              <p className="text-2xl font-bold text-success">{remediations.filter(r => r.status === "accepted").length}</p>
              <p className="text-xs text-muted-foreground">Accepted</p>
            </div>
            <div className="stat-card text-center">
              <p className="text-2xl font-bold text-primary">{remediations.filter(r => r.status === "rejected").length}</p>
              <p className="text-xs text-muted-foreground">Rejected</p>
            </div>
          </div>

          {remediations.map(r => (
            <div key={r.vuln} className="stat-card">
              <button
                className="w-full flex items-start gap-4 text-left"
                onClick={() => setExpanded(expanded === r.vuln ? null : r.vuln)}
              >
                <div className="h-10 w-10 rounded-lg bg-accent/10 flex items-center justify-center shrink-0">
                  <Lightbulb className="h-5 w-5 text-accent" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-1">
                    <span className="font-mono text-sm font-medium">{r.vuln}</span>
                    <span className="status-badge-critical">{r.severity}</span>
                    <span className={statusLabel(r.status)}>{r.status}</span>
                    <span className="text-xs text-muted-foreground ml-auto">ETA: {r.eta}</span>
                    {expanded === r.vuln ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                  </div>
                  <p className="text-xs text-muted-foreground">Asset: <span className="font-mono">{r.asset}</span></p>
                </div>
              </button>

              {expanded === r.vuln && (
                <div className="mt-4 ml-14 space-y-5 border-t border-border pt-4">
                  <div>
                    <p className="section-title mb-3">Remediation Steps</p>
                    <div className="space-y-3">
                      {r.steps.map((step, i) => (
                        <div key={i} className="flex gap-3">
                          <div className="h-6 w-6 rounded-full bg-accent/10 flex items-center justify-center shrink-0 text-xs font-bold text-accent">{i + 1}</div>
                          <div>
                            <p className="text-sm font-medium">{step.step}</p>
                            <p className="text-xs text-muted-foreground mt-0.5">{step.detail}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div>
                    <p className="section-title mb-2">Configuration Suggestions</p>
                    <div className="bg-foreground/5 rounded-md p-3 font-mono text-xs space-y-1">
                      {r.configSuggestions.map((cfg, i) => (<p key={i} className="text-muted-foreground">{cfg}</p>))}
                    </div>
                  </div>

                  {r.relatedVulns.length > 0 && (
                    <div>
                      <p className="section-title mb-2">Related Vulnerabilities</p>
                      <div className="flex gap-2">
                        {r.relatedVulns.map(rv => (
                          <span key={rv} className="inline-flex items-center gap-1 bg-muted px-2 py-1 rounded text-xs font-mono">
                            <Link2 className="h-3 w-3" /> {rv}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="flex gap-2 pt-2">
                    <Button size="sm" variant={r.status === "accepted" ? "default" : "outline"} className="gap-1" onClick={() => updateStatus(r.vuln, "accepted")}>
                      <Check className="h-3 w-3" /> Accept
                    </Button>
                    <Button size="sm" variant="outline" className="gap-1" onClick={() => updateStatus(r.vuln, "rejected")}>
                      <X className="h-3 w-3" /> Reject
                    </Button>
                    <Button size="sm" variant="outline" className="gap-1" onClick={() => updateStatus(r.vuln, "pending")}>
                      <RotateCcw className="h-3 w-3" /> Regenerate
                    </Button>
                  </div>
                </div>
              )}
            </div>
          ))}
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
          </div>

          <div className="flex gap-2">
            <Input
              placeholder="Ask about remediation..."
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSendChat()}
            />
            <Button size="icon" onClick={handleSendChat}><Send className="h-4 w-4" /></Button>
          </div>
        </div>
      </div>
    </PageShell>
  );
};

export default RemediationGuidance;
