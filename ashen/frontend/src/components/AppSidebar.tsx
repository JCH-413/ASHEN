import { useLocation, Link } from "react-router-dom";
import { useAuth } from "@/contexts/AuthContext";
import { navigationConfig } from "@/config/navigation";
import { cn } from "@/lib/utils";
import { ChevronLeft } from "lucide-react";
import { useState } from "react";
import ashenIcon from "../../icon/ashen-icon.png";

export function AppSidebar() {
  const { user } = useAuth();
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      className={cn(
        "flex flex-col bg-sidebar text-sidebar-foreground border-r border-sidebar-border transition-all duration-300 h-screen sticky top-0",
        collapsed ? "w-16" : "w-64"
      )}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 h-16 border-b border-sidebar-border shrink-0">
        <img
          src={ashenIcon}
          alt="ASHEN logo"
          className="h-7 w-7 shrink-0 object-contain"
        />
        {!collapsed && (
          <span className="text-lg font-bold tracking-wider text-sidebar-foreground">
            ASHEN
          </span>
        )}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="ml-auto p-1 rounded hover:bg-sidebar-muted transition-colors"
        >
          <ChevronLeft
            className={cn(
              "h-4 w-4 transition-transform text-sidebar-foreground/60",
              collapsed && "rotate-180"
            )}
          />
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4 space-y-6">
        {navigationConfig.map((group) => {
          if (group.adminOnly && user?.role !== "admin") return null;
          return (
            <div key={group.label}>
              {!collapsed && (
                <p
                  className={cn(
                    "px-4 mb-2 text-[10px] font-semibold uppercase tracking-[0.15em]",
                    group.adminOnly
                      ? "text-primary/70"
                      : "text-sidebar-foreground/40"
                  )}
                >
                  {group.label}
                </p>
              )}
              {group.adminOnly && !collapsed && (
                <div className="mx-4 mb-2 h-px bg-primary/20" />
              )}
              <ul className="space-y-0.5">
                {group.items.map((item) => {
                  if (item.adminOnly && user?.role !== "admin") return null;
                  const active = location.pathname === item.url;
                  return (
                    <li key={item.url}>
                      <Link
                        to={item.url}
                        title={item.title}
                        className={cn(
                          "flex items-center gap-3 mx-2 px-3 py-2 rounded-md text-sm font-medium transition-colors",
                          active
                            ? "bg-sidebar-accent text-sidebar-accent-foreground"
                            : "text-sidebar-foreground/70 hover:bg-sidebar-muted hover:text-sidebar-foreground"
                        )}
                      >
                        <item.icon className="h-4 w-4 shrink-0" />
                        {!collapsed && <span>{item.title}</span>}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          );
        })}
      </nav>

      {/* Footer */}
      {!collapsed && (
        <div className="px-4 py-3 border-t border-sidebar-border text-[10px] text-sidebar-foreground/30">
          ASHEN v1.0.0 — Prototype
        </div>
      )}
    </aside>
  );
}
