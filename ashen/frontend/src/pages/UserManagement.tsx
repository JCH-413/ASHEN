import { PageShell } from "@/components/PageShell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Plus, Loader2, RefreshCw } from "lucide-react";
import { useState, useEffect, useCallback } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { EmptyState } from "@/components/EmptyState";
import {
  auth as authApi,
  admin as adminApi,
  SessionItem,
  ApiError,
} from "@/lib/api";

const UserManagement = () => {
  const { toast } = useToast();

  // ── Sessions list (shows who has logged in) ──────────────────────
  const [sessions, setSessions] = useState<SessionItem[]>([]);
  const [sessionsLoading, setSessionsLoading] = useState(false);

  const fetchSessions = useCallback(async () => {
    setSessionsLoading(true);
    try {
      setSessions(await adminApi.sessions({ limit: 100 }));
    } catch { /* silent */ }
    setSessionsLoading(false);
  }, []);

  useEffect(() => { fetchSessions(); }, [fetchSessions]);

  // ── Create user dialog ───────────────────────────────────────────
  const [showCreate, setShowCreate] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createEmail, setCreateEmail] = useState("");
  const [createPassword, setCreatePassword] = useState("");
  const [creating, setCreating] = useState(false);

  const handleCreateUser = async () => {
    if (!createName || !createEmail || !createPassword) {
      toast({ title: "Error", description: "All fields are required.", variant: "destructive" });
      return;
    }
    if (createPassword.length < 6) {
      toast({ title: "Error", description: "Password must be at least 6 characters.", variant: "destructive" });
      return;
    }
    setCreating(true);
    try {
      const res = await authApi.createUser(createName, createEmail, createPassword);
      toast({ title: "User Created", description: res.message });
      setShowCreate(false);
      setCreateName("");
      setCreateEmail("");
      setCreatePassword("");
      fetchSessions();
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : "Failed to create user";
      toast({ title: "Error", description: msg, variant: "destructive" });
    } finally {
      setCreating(false);
    }
  };

  return (
    <PageShell title="User Management">
      {/* Create Analyst Dialog */}
      <Dialog open={showCreate} onOpenChange={setShowCreate}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Analyst Account</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-1">
              <Label>Full Name</Label>
              <Input value={createName} onChange={(e) => setCreateName(e.target.value)} placeholder="Jane Doe" disabled={creating} />
            </div>
            <div className="space-y-1">
              <Label>Email</Label>
              <Input value={createEmail} onChange={(e) => setCreateEmail(e.target.value)} placeholder="analyst@ashen.io" type="email" disabled={creating} />
            </div>
            <div className="space-y-1">
              <Label>Password</Label>
              <Input value={createPassword} onChange={(e) => setCreatePassword(e.target.value)} type="password" placeholder="Min 6 characters" disabled={creating} />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreate(false)} disabled={creating}>Cancel</Button>
            <Button onClick={handleCreateUser} disabled={creating}>
              {creating ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Create Analyst
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <div className="flex items-center justify-between mb-6">
        <p className="text-sm text-muted-foreground">Create analyst accounts and view login sessions.</p>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={fetchSessions} disabled={sessionsLoading}>
            <RefreshCw className={`h-3 w-3 mr-1 ${sessionsLoading ? "animate-spin" : ""}`} /> Refresh
          </Button>
          <Button className="gap-2" onClick={() => setShowCreate(true)}>
            <Plus className="h-4 w-4" /> Create Analyst
          </Button>
        </div>
      </div>

      <h2 className="font-semibold mb-3">Login Sessions</h2>
      {sessions.length === 0 && !sessionsLoading ? (
        <EmptyState message="No sessions recorded yet." />
      ) : (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                {["Session", "Name", "Email", "Login", "Logout", "Status"].map((h) => (
                  <th key={h} className="text-left p-3 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.session_id} className="border-b border-border last:border-0 hover:bg-muted/30">
                  <td className="p-3 font-mono text-accent">{s.session_id}</td>
                  <td className="p-3 font-medium">{s.user_name ?? "—"}</td>
                  <td className="p-3 text-muted-foreground">{s.user_email ?? "—"}</td>
                  <td className="p-3 text-muted-foreground text-xs">{s.login_time ? new Date(s.login_time).toLocaleString() : "—"}</td>
                  <td className="p-3 text-muted-foreground text-xs">{s.logout_time ? new Date(s.logout_time).toLocaleString() : "—"}</td>
                  <td className="p-3">
                    <span className={s.status === "Active" ? "status-badge-low" : "status-badge-medium"}>{s.status}</span>
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

export default UserManagement;
