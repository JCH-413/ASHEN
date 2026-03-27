import { PageShell } from "@/components/PageShell";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { FileBarChart, Download, Plus, Eye, X, Clock, CheckCircle2 } from "lucide-react";
import { useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";

const reports = [
  { id: "RPT-001", title: "Weekly Vulnerability Summary", type: "Automated", generated: "2024-12-15", pages: 12, format: "PDF", status: "Ready" },
  { id: "RPT-002", title: "Penetration Test — DMZ Segment", type: "Manual", generated: "2024-12-14", pages: 34, format: "PDF", status: "Ready" },
  { id: "RPT-003", title: "Compliance Audit — PCI DSS", type: "Automated", generated: "2024-12-13", pages: 28, format: "PDF", status: "Ready" },
  { id: "RPT-004", title: "Incident Response Report — FW Breach", type: "Manual", generated: "2024-12-12", pages: 8, format: "DOCX", status: "Ready" },
  { id: "RPT-005", title: "Monthly Executive Summary", type: "Automated", generated: "2024-12-10", pages: 6, format: "PDF", status: "Generating" },
];

const previewSections = [
  { title: "1. Executive Summary", content: "This report provides an overview of the security posture of the Production DMZ network segment (192.168.1.0/24). During the assessment period, 23 vulnerabilities were identified across 6 hosts, including 3 critical findings requiring immediate attention." },
  { title: "2. Scope & Methodology", content: "The assessment covered all hosts within the 192.168.1.0/24 CIDR range. Testing methodologies included automated vulnerability scanning, manual verification, and proof-of-concept validation using ASHEN's integrated testing framework." },
  { title: "3. Critical Findings", content: "CVE-2024-21762 (CVSS 9.8) — FortiOS SSL VPN out-of-bound write vulnerability on fw-edge-01. Confirmed exploitable with remote code execution. Immediate patching recommended.\n\nCVE-2024-3400 (CVSS 10.0) — PAN-OS GlobalProtect command injection on pan-gw-02. Active exploitation in the wild. Priority 1 remediation." },
  { title: "4. Recommendations", content: "1. Immediately patch FortiOS to version 7.4.3 or later\n2. Apply PAN-OS hotfix 10.2.9-h1\n3. Disable Cisco IOS XE web UI on cisco-sw-07\n4. Implement network segmentation for critical infrastructure\n5. Deploy IPS signatures for interim protection" },
  { title: "5. Appendix — Full Vulnerability List", content: "See attached tables for complete vulnerability inventory with CVSS scores, affected assets, and remediation timelines." },
];

const Reports = () => {
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewReport, setPreviewReport] = useState(reports[1]);

  return (
    <PageShell title="Reports">
      <Dialog open={previewOpen} onOpenChange={setPreviewOpen}>
        <DialogContent className="sm:max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <FileBarChart className="h-5 w-5 text-accent" />
              {previewReport.title}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-6 py-4">
            <div className="flex items-center gap-4 text-xs text-muted-foreground bg-muted rounded-lg p-3">
              <span>Generated: {previewReport.generated}</span>
              <span>Pages: {previewReport.pages}</span>
              <span>Format: {previewReport.format}</span>
              <span>Type: {previewReport.type}</span>
            </div>
            {previewSections.map((s, i) => (
              <div key={i}>
                <h3 className="font-semibold mb-2">{s.title}</h3>
                <p className="text-sm text-muted-foreground whitespace-pre-line">{s.content}</p>
              </div>
            ))}
            <div className="flex gap-2 pt-4 border-t border-border">
              <Button className="gap-2"><Download className="h-4 w-4" /> Download {previewReport.format}</Button>
              <Button variant="outline" onClick={() => setPreviewOpen(false)}>Close</Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      <div className="flex items-center justify-between mb-6">
        <p className="text-sm text-muted-foreground">Generate, preview, and download security reports</p>
        <Button className="gap-2"><Plus className="h-4 w-4" /> Generate Report</Button>
      </div>

      <div className="grid grid-cols-4 gap-4 mb-6">
        <div className="stat-card text-center">
          <p className="text-2xl font-bold">{reports.length}</p>
          <p className="text-xs text-muted-foreground">Total Reports</p>
        </div>
        <div className="stat-card text-center">
          <p className="text-2xl font-bold text-accent">{reports.filter(r => r.type === "Automated").length}</p>
          <p className="text-xs text-muted-foreground">Automated</p>
        </div>
        <div className="stat-card text-center">
          <p className="text-2xl font-bold text-foreground">{reports.filter(r => r.type === "Manual").length}</p>
          <p className="text-xs text-muted-foreground">Manual</p>
        </div>
        <div className="stat-card text-center">
          <p className="text-2xl font-bold text-warning">{reports.filter(r => r.status === "Generating").length}</p>
          <p className="text-xs text-muted-foreground">In Progress</p>
        </div>
      </div>

      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/50">
              {["ID", "Title", "Type", "Generated", "Pages", "Status", "Actions"].map(h => (
                <th key={h} className="text-left p-3 font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {reports.map(r => (
              <tr key={r.id} className="border-b border-border last:border-0 hover:bg-muted/30">
                <td className="p-3 font-mono text-accent">{r.id}</td>
                <td className="p-3 font-medium">{r.title}</td>
                <td className="p-3"><span className="status-badge-info">{r.type}</span></td>
                <td className="p-3 text-muted-foreground">{r.generated}</td>
                <td className="p-3 text-muted-foreground">{r.pages} pages</td>
                <td className="p-3">
                  {r.status === "Ready" ? (
                    <span className="status-badge-low"><CheckCircle2 className="h-3 w-3 inline mr-1" />Ready</span>
                  ) : (
                    <span className="status-badge-medium"><Clock className="h-3 w-3 inline mr-1 animate-pulse-slow" />Generating</span>
                  )}
                </td>
                <td className="p-3">
                  <div className="flex gap-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="gap-1"
                      onClick={() => { setPreviewReport(r); setPreviewOpen(true); }}
                      disabled={r.status !== "Ready"}
                    >
                      <Eye className="h-3 w-3" /> Preview
                    </Button>
                    <Button variant="ghost" size="sm" className="gap-1" disabled={r.status !== "Ready"}>
                      <Download className="h-3 w-3" /> {r.format}
                    </Button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </PageShell>
  );
};

export default Reports;
