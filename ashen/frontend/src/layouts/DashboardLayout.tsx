import { Outlet } from "react-router-dom";
import { AppSidebar } from "@/components/AppSidebar";

export function DashboardLayout() {
  return (
    <div className="flex min-h-screen w-full bg-secondary">
      <AppSidebar />
      <div className="flex-1 flex flex-col min-w-0">
        <Outlet />
      </div>
    </div>
  );
}
