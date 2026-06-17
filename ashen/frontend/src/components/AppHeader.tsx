import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/contexts/AuthContext";
import { Bell, LogOut, User } from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { useToast } from "@/hooks/use-toast";
import { useNotifications, refreshNotifications, notifications } from "@/lib/notifications-store";

interface AppHeaderProps {
  title: string;
}

export function AppHeader({ title }: AppHeaderProps) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();
  const [showLogoutConfirm, setShowLogoutConfirm] = useState(false);
  const { items, unread } = useNotifications();

  // Poll analyst-visible data so the bell reflects scans/exploits/approvals.
  useEffect(() => {
    refreshNotifications();
    const id = setInterval(refreshNotifications, 20000);
    return () => clearInterval(id);
  }, []);

  const handleLogout = async () => {
    setShowLogoutConfirm(false);
    await logout();
    toast({ title: "Logged out", description: "You have been signed out successfully." });
    navigate("/login", { replace: true });
  };

  return (
    <>
      <ConfirmDialog
        open={showLogoutConfirm}
        onConfirm={handleLogout}
        onCancel={() => setShowLogoutConfirm(false)}
        title="Confirm Logout"
        description="Are you sure you want to log out? Your current session will be ended."
        confirmLabel="Log Out"
        variant="destructive"
      />

      <header className="h-16 border-b border-border bg-card flex items-center justify-between px-6 shrink-0">
        <h1 className="page-header">{title}</h1>

        <div className="flex items-center gap-4">
          {/* Session indicator */}
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <span className="h-2 w-2 rounded-full bg-success animate-pulse-slow" />
            Session Active
          </div>

          {/* Notifications */}
          <DropdownMenu onOpenChange={(open) => open && notifications.markAllRead()}>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="relative">
                <Bell className="h-4 w-4" />
                {unread > 0 && (
                  <span className="absolute -top-0.5 -right-0.5 h-4 w-4 rounded-full bg-primary text-[10px] text-primary-foreground flex items-center justify-center font-bold">
                    {unread > 9 ? "9+" : unread}
                  </span>
                )}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-80">
              <DropdownMenuLabel className="flex items-center justify-between">
                Notifications
                {unread > 0 && <span className="text-xs text-muted-foreground">{unread} new</span>}
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              {items.length === 0 ? (
                <div className="px-2 py-6 text-center text-sm text-muted-foreground">
                  No notifications yet
                </div>
              ) : (
                <div className="max-h-80 overflow-auto">
                  {items.map((n) => (
                    <div key={n.id} className="px-2 py-2 border-b border-border/50 last:border-0">
                      <p className="text-sm leading-snug">{n.message}</p>
                      <p className="text-[11px] text-muted-foreground mt-0.5">
                        {new Date(n.ts).toLocaleString()}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </DropdownMenuContent>
          </DropdownMenu>

          {/* Profile */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" className="gap-2 px-2">
                <div className="h-8 w-8 rounded-full bg-accent-dark flex items-center justify-center">
                  <User className="h-4 w-4 text-accent-foreground" />
                </div>
                <div className="text-left hidden sm:block">
                  <p className="text-sm font-medium leading-none">{user?.name}</p>
                  <p className="text-xs text-muted-foreground capitalize">{user?.role}</p>
                </div>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              <DropdownMenuLabel>
                <div>
                  <p className="font-medium">{user?.name}</p>
                  <p className="text-xs text-muted-foreground">{user?.email}</p>
                </div>
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={() => setShowLogoutConfirm(true)} className="text-destructive">
                <LogOut className="mr-2 h-4 w-4" />
                Log Out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </header>
    </>
  );
}
