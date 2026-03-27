import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider } from "@/contexts/AuthContext";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import { DashboardLayout } from "@/layouts/DashboardLayout";
import Login from "./pages/Login";
import SignUp from "./pages/SignUp";
import Dashboard from "./pages/Dashboard";
import NetworkScans from "./pages/NetworkScans";
import AttackRecommendations from "./pages/AttackRecommendations";
import RemediationGuidance from "./pages/RemediationGuidance";
import DataLogs from "./pages/DataLogs";
import UserManagement from "./pages/UserManagement";
import AdminTargets from "./pages/AdminTargets";
import AdminScanRequests from "./pages/AdminScanRequests";
import Reports from "./pages/Reports";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <AuthProvider>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            {/* Public */}
            <Route path="/login" element={<Login />} />
            <Route path="/signup" element={<SignUp />} />
            <Route path="/" element={<Navigate to="/login" replace />} />

            {/* Authenticated */}
            <Route element={<ProtectedRoute />}>
              <Route element={<DashboardLayout />}>
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/scan" element={<NetworkScans />} />
                <Route path="/recommendations" element={<AttackRecommendations />} />
                <Route path="/remediations" element={<RemediationGuidance />} />
                <Route path="/data-logs" element={<DataLogs />} />
                <Route path="/reports" element={<Reports />} />

                {/* Admin only */}
                <Route element={<ProtectedRoute requiredRole="admin" />}>
                  <Route path="/admin/users" element={<UserManagement />} />
                  <Route path="/admin/targets" element={<AdminTargets />} />
                  <Route path="/admin/scan-requests" element={<AdminScanRequests />} />
                </Route>
              </Route>
            </Route>

            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </AuthProvider>
  </QueryClientProvider>
);

export default App;
