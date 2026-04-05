import { PageShell } from "@/components/PageShell";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { FileBarChart, Download, Plus, Eye, Loader2 } from "lucide-react";
import { useState, useEffect, useCallback } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { EmptyState } from "@/components/EmptyState";
import {
  scans as scansApi,
  reports as reportsApi,
  ScanHistoryItem,
  ReportItem,
  ReportDetail,
  ApiError,
} from "@/lib/api";

const Reports = () => {
  const { toast } = useToast();

  // Scan selector for generation
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [selectedFormat, setSelectedFormat] = useState<string>("html");
  const [generating, setGenerating] = useState(false);

  // Report list
  const [reportList, setReportList] = useState<ReportItem[]>([]);
  const [listLoading, setListLoading] = useState(false);

  // Preview
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewReport, setPreviewReport] = useState<ReportDetail | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  const fetchScans = useCallback(async () => {
    try {
      const data = await scansApi.history();
      setScanHistory(data.filter((s) => s.status === "completed"));
    } catch { /* ignore */ }
  }, []);

  const fetchReports = useCallback(async () => {
    setListLoading(true);
    try {
      setReportList(await reportsApi.list());
    } catch { /* ignore */ }
    finally { setListLoading(false); }
  }, []);

  useEffect(() => { fetchScans(); fetchReports(); }, [fetchScans, fetchReports]);

  const handleGenerate = async () => {
    if (!selectedScanId) {
      toast({ title: "Error", description: "Select a scan first.", variant: "destructive" });
      return;
    }
    setGenerating(true);
    try {
      const res = await reportsApi.generate(Number(selectedScanId), selectedFormat);
      toast({ title: "Report Generated", description: res.message });
      fetchReports();
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Failed to generate report";
      toast({ title: "Error", description: msg, variant: "destructive" });
    } finally {
      setGenerating(false);
    }
  };

  const handlePreview = async (reportId: number) => {
    setPreviewLoading(true);
    setPreviewOpen(true);
    try {
      const detail = await reportsApi.get(reportId);
      setPreviewReport(detail);
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Failed to load report";
      toast({ title: "Error", description: msg, variant: "destructive" });
      setPreviewOpen(false);
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleDownload = (reportId: number) => {
    const token = localStorage.getItem("ashen_token");
    const url = reportsApi.downloadUrl(reportId);
    // Open in new tab with auth header via fetch + blob
    fetch(url, { headers: { Authorization: `Bearer ${token ?? ""}` } })
      .then((res) => res.blob())
      .then((blob) => {
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `ashen_report_${reportId}.${reportList.find((r) => r.report_id === reportId)?.format ?? "html"}`;
        a.click();
        URL.revokeObjectURL(a.href);
      })
      .catch(() => toast({ title: "Error", description: "Download failed", variant: "destructive" }));
  };

  return (
    <PageShell title="Reports">
      {/* Preview Dialog */}
      <Dialog open={previewOpen} onOpenChange={setPreviewOpen}>
        <DialogContent className="sm:max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <FileBarChart className="h-5 w-5 text-accent" />
              Report Preview {previewReport ? `(RPT-${previewReport.report_id})` : ""}
            </DialogTitle>
          </DialogHeader>
          {previewLoading ? (
            <div className="flex justify-center py-12"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>
          ) : previewReport ? (
            <div className="space-y-4 py-4">
              <div className="flex items-center gap-4 text-xs text-muted-foreground bg-muted rounded-lg p-3">
                <span>Scan: SCN-{previewReport.scan_id}</span>
                <span>Format: {previewReport.format.toUpperCase()}</span>
                <span>By: {previewReport.generated_by}</span>
                <span>{new Date(previewReport.created_at).toLocaleString()}</span>
              </div>
              {previewReport.format === "html" ? (
                <div
                  className="border border-border rounded-lg p-4 bg-white text-black"
                  dangerouslySetInnerHTML={{ __html: previewReport.content }}
                />
              ) : (
                <pre className="bg-foreground/5 rounded-md p-4 text-xs font-mono overflow-x-auto whitespace-pre">
                  {previewReport.content}
                </pre>
              )}
              <div className="flex gap-2 pt-4 border-t border-border">
                <Button className="gap-2" onClick={() => handleDownload(previewReport.report_id)}>
                  <Download className="h-4 w-4" /> Download
                </Button>
                <Button variant="outline" onClick={() => setPreviewOpen(false)}>Close</Button>
              </div>
            </div>
          ) : null}
        </DialogContent>
      </Dialog>

      {/* Generate section */}
      <div className="flex items-center justify-between mb-6">
        <p className="text-sm text-muted-foreground">Generate, preview, and download security reports from real scan data</p>
      </div>

      <div className="flex items-end gap-4 mb-6">
        <div className="space-y-1 flex-1 max-w-xs">
          <label className="text-xs font-medium">Scan</label>
          <Select value={selectedScanId} onValueChange={setSelectedScanId}>
            <SelectTrigger>
              <SelectValue placeholder="Select a completed scan..." />
            </SelectTrigger>
            <SelectContent>
              {scanHistory.map((s) => (
                <SelectItem key={s.scan_id} value={String(s.scan_id)}>
                  SCN-{s.scan_id} — {s.ip ?? "Unknown"}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1 w-32">
          <label className="text-xs font-medium">Format</label>
          <Select value={selectedFormat} onValueChange={setSelectedFormat}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="html">HTML</SelectItem>
              <SelectItem value="csv">CSV</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <Button className="gap-2" onClick={handleGenerate} disabled={generating}>
          {generating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
          Generate Report
        </Button>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="stat-card text-center">
          <p className="text-2xl font-bold">{reportList.length}</p>
          <p className="text-xs text-muted-foreground">Total Reports</p>
        </div>
        <div className="stat-card text-center">
          <p className="text-2xl font-bold text-accent">{reportList.filter((r) => r.format === "html").length}</p>
          <p className="text-xs text-muted-foreground">HTML</p>
        </div>
        <div className="stat-card text-center">
          <p className="text-2xl font-bold text-foreground">{reportList.filter((r) => r.format === "csv").length}</p>
          <p className="text-xs text-muted-foreground">CSV</p>
        </div>
      </div>

      {/* Report list */}
      {listLoading ? (
        <div className="flex justify-center py-12"><Loader2 className="h-6 w-6 animate-spin text-muted-foreground" /></div>
      ) : reportList.length === 0 ? (
        <EmptyState message="No reports generated yet. Select a scan and generate one above." />
      ) : (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                {["ID", "Scan", "Format", "Generated By", "Created", "Actions"].map((h) => (
                  <th key={h} className="text-left p-3 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {reportList.map((r) => (
                <tr key={r.report_id} className="border-b border-border last:border-0 hover:bg-muted/30">
                  <td className="p-3 font-mono text-accent">RPT-{r.report_id}</td>
                  <td className="p-3 font-mono">SCN-{r.scan_id}</td>
                  <td className="p-3"><span className="status-badge-info">{r.format.toUpperCase()}</span></td>
                  <td className="p-3">{r.generated_by}</td>
                  <td className="p-3 text-muted-foreground">{new Date(r.created_at).toLocaleString()}</td>
                  <td className="p-3">
                    <div className="flex gap-1">
                      <Button variant="ghost" size="sm" className="gap-1" onClick={() => handlePreview(r.report_id)}>
                        <Eye className="h-3 w-3" /> Preview
                      </Button>
                      <Button variant="ghost" size="sm" className="gap-1" onClick={() => handleDownload(r.report_id)}>
                        <Download className="h-3 w-3" /> Download
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </PageShell>
  );
};

export default Reports;
