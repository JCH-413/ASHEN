import { PageShell } from "@/components/PageShell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Plus, Loader2, RefreshCw } from "lucide-react";
import { useState, useEffect, useCallback } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { EmptyState } from "@/components/EmptyState";
import { admin as adminApi, TargetItem, ApiError } from "@/lib/api";

const AdminTargets = () => {
  const { toast } = useToast();
  const [targets, setTargets] = useState<TargetItem[]>([]);
  const [loading, setLoading] = useState(false);

  const fetchTargets = useCallback(async () => {
    setLoading(true);
    try { setTargets(await adminApi.targets()); } catch { /* silent */ }
    setLoading(false);
  }, []);

  useEffect(() => { fetchTargets(); }, [fetchTargets]);

  // Add target dialog
  const [showAdd, setShowAdd] = useState(false);
  const [newIp, setNewIp] = useState("");
  const [adding, setAdding] = useState(false);

  const handleAdd = async () => {
    if (!newIp.trim()) {
      toast({ title: "Error", description: "Enter an IP address.", variant: "destructive" });
      return;
    }
    setAdding(true);
    try {
      const res = await adminApi.addTarget(newIp.trim());
      toast({ title: "Target Added", description: res.message });
      setShowAdd(false);
      setNewIp("");
      fetchTargets();
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Failed to add target";
      toast({ title: "Error", description: msg, variant: "destructive" });
    } finally {
      setAdding(false);
    }
  };

  return (
    <PageShell title="Authorized Targets">
      <Dialog open={showAdd} onOpenChange={setShowAdd}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Authorize Target IP</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1">
              <Label>IP Address</Label>
              <Input value={newIp} onChange={(e) => setNewIp(e.target.value)} placeholder="e.g., 192.168.1.100" disabled={adding} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAdd(false)} disabled={adding}>Cancel</Button>
            <Button onClick={handleAdd} disabled={adding}>
              {adding ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Authorize
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <div className="flex items-center justify-between mb-6">
        <p className="text-sm text-muted-foreground">IPs authorized for scanning by analysts.</p>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={fetchTargets} disabled={loading}>
            <RefreshCw className={`h-3 w-3 mr-1 ${loading ? "animate-spin" : ""}`} /> Refresh
          </Button>
          <Button className="gap-2" onClick={() => setShowAdd(true)}>
            <Plus className="h-4 w-4" /> Add Target
          </Button>
        </div>
      </div>

      {targets.length === 0 && !loading ? (
        <EmptyState message="No authorized targets yet. Add one to allow analysts to scan." />
      ) : (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                {["ID", "IP Address", "Authorized", "Created"].map((h) => (
                  <th key={h} className="text-left p-3 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {targets.map((t) => (
                <tr key={t.target_id} className="border-b border-border last:border-0 hover:bg-muted/30">
                  <td className="p-3 font-mono text-accent">{t.target_id}</td>
                  <td className="p-3 font-mono">{t.ip}</td>
                  <td className="p-3">
                    <span className={t.authorized ? "status-badge-low" : "status-badge-medium"}>
                      {t.authorized ? "Yes" : "No"}
                    </span>
                  </td>
                  <td className="p-3 text-muted-foreground text-xs">{new Date(t.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </PageShell>
  );
};

export default AdminTargets;
