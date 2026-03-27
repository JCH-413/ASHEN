import { PageShell } from "@/components/PageShell";
import { Button } from "@/components/ui/button";
import { Crosshair, ChevronDown, ChevronRight, Zap, AlertTriangle } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useToast } from "@/hooks/use-toast";
import { ConfirmDialog } from "@/components/ConfirmDialog";

const recommendations = [
  {
    id: "REC-001", target: "fw-edge-01", vuln: "CVE-2024-21762", technique: "T1190 - Exploit Public-Facing Application",
    confidence: "High", priority: 1, riskScore: 9.8,
    description: "FortiOS SSL VPN endpoint is vulnerable to out-of-bound write. Exploitation requires no authentication and can yield remote code execution with root privileges.",
    attackMethod: "Heap overflow via crafted HTTP request to /remote/logincheck",
    steps: [
      "1. Craft HTTP request targeting /remote/logincheck endpoint",
      "2. Send overflow payload in username field (>2048 bytes)",
      "3. Trigger heap corruption to achieve code execution",
      "4. Establish reverse shell connection",
    ],
    mitre: [
      { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
      { id: "T1059.004", name: "Unix Shell", tactic: "Execution" },
    ],
  },
  {
    id: "REC-002", target: "pan-gw-02", vuln: "CVE-2024-3400", technique: "T1059.004 - Unix Shell",
    confidence: "High", priority: 1, riskScore: 10.0,
    description: "PAN-OS GlobalProtect gateway vulnerable to OS command injection. Unauthenticated attacker can execute arbitrary commands with root privileges.",
    attackMethod: "Command injection via SESSID cookie in GlobalProtect gateway",
    steps: [
      "1. Send crafted SESSID cookie to /ssl-vpn/hipreport.esp",
      "2. Inject OS command via directory traversal in cookie value",
      "3. Command executes as root in telemetry subsystem",
      "4. Exfiltrate data or establish persistence",
    ],
    mitre: [
      { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
      { id: "T1059.004", name: "Unix Shell", tactic: "Execution" },
    ],
  },
  {
    id: "REC-003", target: "screen-connect-01", vuln: "CVE-2024-1709", technique: "T1078 - Valid Accounts",
    confidence: "Medium", priority: 2, riskScore: 8.4,
    description: "ScreenConnect server allows authentication bypass via exposed setup wizard.",
    attackMethod: "Setup wizard bypass to create rogue admin account",
    steps: [
      "1. Navigate to /SetupWizard.aspx endpoint",
      "2. Create new administrative account",
      "3. Access admin console",
      "4. Deploy remote access agent",
    ],
    mitre: [
      { id: "T1078", name: "Valid Accounts", tactic: "Initial Access" },
      { id: "T1219", name: "Remote Access Software", tactic: "Command and Control" },
    ],
  },
  {
    id: "REC-004", target: "cisco-sw-07", vuln: "CVE-2023-20198", technique: "T1548 - Abuse Elevation Control",
    confidence: "High", priority: 1, riskScore: 10.0,
    description: "Cisco IOS XE web UI allows unauthenticated privilege escalation.",
    attackMethod: "Web UI exploitation to create local admin account",
    steps: [
      "1. Send POST to /webui endpoint to create local account",
      "2. Authenticate with newly created credentials",
      "3. Access privileged EXEC mode",
      "4. Modify running configuration",
    ],
    mitre: [
      { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
      { id: "T1136", name: "Create Account", tactic: "Persistence" },
    ],
  },
];

const AttackRecommendations = () => {
  const [expanded, setExpanded] = useState<string | null>("REC-001");
  const [confirmAttack, setConfirmAttack] = useState<string | null>(null);
  const navigate = useNavigate();
  const { toast } = useToast();

  const handleExecuteAttack = () => {
    toast({ title: "Attack Executed", description: `Simulated attack on ${confirmAttack} — navigating to remediations.` });
    setConfirmAttack(null);
    setTimeout(() => navigate("/remediations"), 600);
  };

  return (
    <PageShell title="Recommendations">
      <p className="text-sm text-muted-foreground mb-6">AI-prioritized vulnerabilities with recommended attack methods</p>

      <ConfirmDialog
        open={!!confirmAttack}
        onConfirm={handleExecuteAttack}
        onCancel={() => setConfirmAttack(null)}
        title="Execute Attack"
        description={`Are you sure you want to execute the simulated attack on ${confirmAttack}? This action will be logged and should only be performed on authorized targets.`}
        confirmLabel="Execute"
        variant="destructive"
      />

      <div className="grid grid-cols-4 gap-4 mb-6">
        <div className="stat-card text-center">
          <p className="text-2xl font-bold text-primary">{recommendations.filter(r => r.priority === 1).length}</p>
          <p className="text-xs text-muted-foreground">Priority 1</p>
        </div>
        <div className="stat-card text-center">
          <p className="text-2xl font-bold text-foreground">{recommendations.length}</p>
          <p className="text-xs text-muted-foreground">Total Recommendations</p>
        </div>
        <div className="stat-card text-center">
          <p className="text-2xl font-bold text-accent">{recommendations.filter(r => r.confidence === "High").length}</p>
          <p className="text-xs text-muted-foreground">High Confidence</p>
        </div>
        <div className="stat-card text-center">
          <p className="text-2xl font-bold text-foreground">10</p>
          <p className="text-xs text-muted-foreground">MITRE Techniques</p>
        </div>
      </div>

      <div className="space-y-3">
        {recommendations.map(r => (
          <div key={r.id} className="stat-card">
            <button
              className="w-full flex items-start gap-4 text-left"
              onClick={() => setExpanded(expanded === r.id ? null : r.id)}
            >
              <div className="h-10 w-10 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                <Crosshair className="h-5 w-5 text-primary" />
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-1">
                  <span className="font-mono text-sm font-medium">{r.id}</span>
                  <span className="status-badge-critical">Priority {r.priority}</span>
                  <span className={r.confidence === "High" ? "status-badge-high" : "status-badge-medium"}>{r.confidence}</span>
                  <span className="text-xs text-muted-foreground ml-auto">Risk: {r.riskScore}</span>
                  {expanded === r.id ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                </div>
                <p className="text-sm"><span className="text-muted-foreground">Target:</span> <span className="font-mono">{r.target}</span> — {r.vuln}</p>
                <p className="text-xs text-accent mt-1">{r.technique}</p>
              </div>
            </button>

            {expanded === r.id && (
              <div className="mt-4 ml-14 space-y-4 border-t border-border pt-4">
                <div>
                  <p className="section-title mb-1">Description</p>
                  <p className="text-sm text-muted-foreground">{r.description}</p>
                </div>

                <div>
                  <p className="section-title mb-1">Recommended Attack Method</p>
                  <p className="text-sm font-medium">{r.attackMethod}</p>
                </div>

                <div>
                  <p className="section-title mb-2">Attack Steps</p>
                  <div className="bg-muted rounded-md p-3 space-y-1.5">
                    {r.steps.map((step, i) => (
                      <p key={i} className="text-xs font-mono text-muted-foreground">{step}</p>
                    ))}
                  </div>
                </div>

                <div>
                  <p className="section-title mb-2">MITRE ATT&CK Mapping</p>
                  <div className="flex flex-wrap gap-2">
                    {r.mitre.map(m => (
                      <span key={m.id} className="inline-flex items-center gap-1 bg-accent/10 text-accent border border-accent/20 px-2 py-1 rounded text-xs font-mono">
                        {m.id} — {m.name}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Risk indicator */}
                <div className="flex items-center gap-3 p-3 rounded-lg bg-primary/5 border border-primary/20">
                  <AlertTriangle className="h-4 w-4 text-primary shrink-0" />
                  <p className="text-xs text-muted-foreground">Risk Score: <span className="font-bold text-primary">{r.riskScore}/10</span> — Ensure target authorization before execution.</p>
                </div>

                <div className="flex gap-2">
                  <Button size="sm" className="gap-2" onClick={() => setConfirmAttack(r.target)}>
                    <Zap className="h-3 w-3" /> Execute Attack
                  </Button>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </PageShell>
  );
};

export default AttackRecommendations;
