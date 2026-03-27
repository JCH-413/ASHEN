import { PageShell } from "@/components/PageShell";
import { Button } from "@/components/ui/button";
import { RefreshCw, Check, X, Loader2 } from "lucide-react";
import { useState, useEffect, useCallback } from "react";
import { useToast } from "@/hooks/use-toast";
import { EmptyState } from "@/components/EmptyState";
import { admin as adminApi, ScanRequestItem, ApiError } from "@/lib/api";

const AdminScanRequests = () => {
  const { toast } = useToast();
  const [requests, setRequests] = useState<ScanRequestItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [reviewing, setReviewing] = useState<number | null>(null);

  const fetchRequests = useCallback(async () => {
    setLoading(true);
    try { setRequests(await adminApi.scanRequests()); } catch { /* silent */ }
    setLoading(false);
  }, []);

  useEffect(() => { fetchRequests(); }, [fetchRequests]);

  const handleReview = async (requestId: number, approve: boolean) => {
    setReviewing(requestId);
    try {
      const res = await adminApi.reviewScanRequest(requestId, approve);
      toast({ title: approve ? "Approved" : "Denied", description: res.message });
      fetchRequests();
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Review failed";
      toast({ title: "Error", description: msg, variant: "destructive" });
    } finally {
      setReviewing(null);
    }
  };

  return (
    <PageShell title="Scan Requests">
      <div className="flex items-center justify-between mb-6">
        <p className="text-sm text-muted-foreground">Pending scan authorization requests from analysts.</p>
        <Button variant="outline" size="sm" onClick={fetchRequests} disabled={loading}>
          <RefreshCw className={`h-3 w-3 mr-1 ${loading ? "animate-spin" : ""}`} /> Refresh
        </Button>
      </div>

      {requests.length === 0 && !loading ? (
        <EmptyState message="No pending scan requests." />
      ) : (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                {["ID", "Target IP", "Requested By", "Status", "Created", "Actions"].map((h) => (
                  <th key={h} className="text-left p-3 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {requests.map((r) => (
                <tr key={r.request_id} className="border-b border-border last:border-0 hover:bg-muted/30">
                  <td className="p-3 font-mono text-accent">{r.request_id}</td>
                  <td className="p-3 font-mono">{r.target_ip}</td>
                  <td className="p-3">User #{r.requested_by}</td>
                  <td className="p-3"><span className="status-badge-medium">{r.status}</span></td>
                  <td className="p-3 text-muted-foreground text-xs">{new Date(r.created_at).toLocaleString()}</td>
                  <td className="p-3">
                    <div className="flex gap-1">
                      <Button
                        variant="outline"
                        size="sm"
                        className="gap-1 text-success"
                        onClick={() => handleReview(r.request_id, true)}
                        disabled={reviewing === r.request_id}
                      >
                        {reviewing === r.request_id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Check className="h-3 w-3" />}
                        Approve
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        className="gap-1 text-destructive"
                        onClick={() => handleReview(r.request_id, false)}
                        disabled={reviewing === r.request_id}
                      >
                        <X className="h-3 w-3" /> Deny
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

export default AdminScanRequests;
