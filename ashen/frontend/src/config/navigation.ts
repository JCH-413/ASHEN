import {
  LayoutDashboard,
  Radar,
  Crosshair,
  Bot,
  Database,
  Users,
  Target,
  ShieldCheck,
  LucideIcon,
} from "lucide-react";

export interface NavItem {
  title: string;
  url: string;
  icon: LucideIcon;
  adminOnly?: boolean;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
  adminOnly?: boolean;
}

export const navigationConfig: NavGroup[] = [
  {
    label: "Main",
    items: [
      { title: "Dashboard", url: "/dashboard", icon: LayoutDashboard },
      { title: "Network Scan", url: "/scan", icon: Radar },
      { title: "Recommendations", url: "/recommendations", icon: Crosshair },
      { title: "AI Remediations", url: "/remediations", icon: Bot },
      { title: "Data / Logs", url: "/data-logs", icon: Database },
    ],
  },
  {
    label: "Administration",
    adminOnly: true,
    items: [
      { title: "User Management", url: "/admin/users", icon: Users, adminOnly: true },
      { title: "Targets", url: "/admin/targets", icon: Target, adminOnly: true },
      { title: "Scan Requests", url: "/admin/scan-requests", icon: ShieldCheck, adminOnly: true },
    ],
  },
];
