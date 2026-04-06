import { PageShell } from "@/components/PageShell";
import { ShieldAlert, Radar, Crosshair, Bot, AlertTriangle, Play, Database, ArrowRight, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { Link } from "react-router-dom";
import { useEffect, useState, useCallback } from "react";
import {
  scans as scansApi,
  vulns as vulnsApi,
  exploits as exploitsApi,
  ScanHistoryItem,
  Vulnerability,
  ExploitListItem,
} from "@/lib/api";
import { useAuth } from "@/contexts/AuthContext";

// Workflow steps (static)
const workflowSteps = [
  { label: "Scan", icon: Radar, to: "/scan", color: "bg-accent/10 text-accent" },
  { label: "Recommend", icon: Crosshair, to: "/recommendations", color: "bg-primary/10 text-primary" },
  { label: "Remediate", icon: Bot, to: "/remediations", color: "bg-accent/10 text-accent" },
  { label: "Logs", icon: Database, to: "/data-logs", color: "bg-muted text-muted-foreground" },
];

const SEV_COLORS: Record<string, string> = {
  critical: "hsl(355, 73%, 51%)",
  high: "hsl(25, 95%, 53%)",
  medium: "hsl(45, 93%, 47%)",
  low: "hsl(142, 71%, 45%)",
};

const Dashboard = () => {
  const { user } = useAuth();
  const [loading, setLoading] = useState(true);
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);
  const [allVulns, setAllVulns] = useState<Vulnerability[]>([]);
  const [allExploits, setAllExploits] = useState<ExploitListItem[]>([]);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [scans, vulns, exploits] = await Promise.allSettled([
        scansApi.history(0, 200),
        vulnsApi.all({ limit: 200 }),
        exploitsApi.all(),
      ]);
      if (scans.status === "fulfilled") setScanHistory(scans.value.items);
      if (vulns.status === "fulfilled") setAllVulns(vulns.value.items);
      if (exploits.status === "fulfilled") setAllExploits(exploits.value);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  // Compute stats
  const totalScans = scanHistory.length;
  const totalVulns = allVulns.length;
  const highSev = allVulns.filter((v) => {
    const s = v.severity.toLowerCase();
    return s === "critical" || s === "high";
  }).length;
  const totalExploits = allExploits.length;

  // Severity distribution for pie chart
  const sevCounts: Record<string, number> = {};
  allVulns.forEach((v) => {
    const s = v.severity.toLowerCase();
    sevCounts[s] = (sevCounts[s] || 0) + 1;
  });
  const severityPie = Object.entries(sevCounts).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
    color: SEV_COLORS[name] || "hsl(0,0%,60%)",
  }));

  // Recent scans (last 5)
  const recentScans = scanHistory.slice(0, 5);

  const stats = [
    { label: "Total Scans", value: totalScans, icon: Radar },
    { label: "Vulnerabilities", value: totalVulns, icon: ShieldAlert },
    { label: "High / Critical", value: highSev, icon: AlertTriangle },
    { label: "Exploits Run", value: totalExploits, icon: Crosshair },
  ];

  if (loading) {
    return (
      <PageShell title="Dashboard">
        <div className="flex justify-center py-20">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </PageShell>
    );
  }

  return (
    <PageShell title="Dashboard">
      {/* Workflow Banner */}
      <div className="stat-card mb-6">
        <p className="section-title mb-3">Workflow</p>
        <div className="flex items-center gap-2">
          {workflowSteps.map((step, i) => (
            <div key={step.label} className="flex items-center gap-2">
              <Link to={step.to} className={`flex items-center gap-2 px-4 py-2 rounded-lg ${step.color} hover:opacity-80 transition-opacity`}>
                <step.icon className="h-4 w-4" />
                <span className="text-sm font-medium">{step.label}</span>
              </Link>
              {i < workflowSteps.length - 1 && <ArrowRight className="h-4 w-4 text-muted-foreground" />}
            </div>
          ))}
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {stats.map((s) => (
          <div key={s.label} className="stat-card flex items-start gap-4">
            <div className="h-10 w-10 rounded-lg bg-accent/10 flex items-center justify-center shrink-0">
              <s.icon className="h-5 w-5 text-accent" />
            </div>
            <div>
              <p className="text-2xl font-bold">{s.value}</p>
              <p className="text-xs text-muted-foreground">{s.label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Quick Actions */}
      <div className="flex flex-wrap gap-2 mb-6">
        <Button asChild size="sm" className="gap-2"><Link to="/scan"><Play className="h-3 w-3" /> Start Scan</Link></Button>
        <Button asChild variant="outline" size="sm" className="gap-2"><Link to="/data-logs"><Database className="h-3 w-3" /> View Logs</Link></Button>
        <Button asChild variant="outline" size="sm" className="gap-2"><Link to="/recommendations"><Crosshair className="h-3 w-3" /> View Recommendations</Link></Button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <div className="stat-card">
          <h2 className="font-semibold mb-2">Severity Distribution</h2>
          {severityPie.length > 0 ? (
            <>
              <div className="h-48">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={severityPie} cx="50%" cy="50%" innerRadius={45} outerRadius={75} paddingAngle={3} dataKey="value">
                      {severityPie.map((entry, i) => (<Cell key={i} fill={entry.color} />))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="flex justify-center gap-4 mt-2">
                {severityPie.map((s) => (
                  <div key={s.name} className="flex items-center gap-1.5 text-xs">
                    <span className="h-2 w-2 rounded-full" style={{ backgroundColor: s.color }} />
                    {s.name} ({s.value})
                  </div>
                ))}
              </div>
            </>
          ) : (
            <p className="text-sm text-muted-foreground py-8 text-center">No vulnerability data yet.</p>
          )}
        </div>

        {/* Recent Scans */}
        <div className="stat-card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-semibold">Recent Scans</h2>
            <Button asChild variant="ghost" size="sm"><Link to="/scan">View all <ArrowRight className="h-3 w-3 ml-1" /></Link></Button>
          </div>
          {recentScans.length > 0 ? (
            <div className="space-y-3">
              {recentScans.map((s) => (
                <div key={s.scan_id} className="flex items-center justify-between py-2 border-b border-border last:border-0">
                  <div>
                    <p className="text-sm font-medium font-mono">SCN-{s.scan_id}</p>
                    <p className="text-xs text-muted-foreground">{s.ip ?? "Unknown"} — {s.user ?? ""}</p>
                  </div>
                  <span className={`text-xs px-2 py-0.5 rounded ${s.status === "completed" ? "bg-success/10 text-success" : s.status === "running" ? "bg-accent/10 text-accent" : "bg-muted text-muted-foreground"}`}>
                    {s.status}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground py-8 text-center">No scans yet. Start your first scan.</p>
          )}
        </div>
      </div>
    </PageShell>
  );
};

export default Dashboard;
