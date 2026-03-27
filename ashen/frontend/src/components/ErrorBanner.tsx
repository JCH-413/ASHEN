import { AlertTriangle, XCircle, Info, X } from "lucide-react";
import { useState } from "react";

interface ErrorBannerProps {
  variant?: "error" | "warning" | "info";
  title: string;
  message: string;
  dismissible?: boolean;
}

const config = {
  error: { icon: XCircle, bg: "bg-primary/5 border-primary/20", text: "text-primary", iconColor: "text-primary" },
  warning: { icon: AlertTriangle, bg: "bg-warning/5 border-warning/20", text: "text-warning", iconColor: "text-warning" },
  info: { icon: Info, bg: "bg-accent/5 border-accent/20", text: "text-accent", iconColor: "text-accent" },
};

export function ErrorBanner({ variant = "error", title, message, dismissible = true }: ErrorBannerProps) {
  const [visible, setVisible] = useState(true);
  if (!visible) return null;
  const c = config[variant];
  const Icon = c.icon;

  return (
    <div className={`flex items-start gap-3 p-4 rounded-lg border ${c.bg} mb-4`}>
      <Icon className={`h-5 w-5 ${c.iconColor} shrink-0 mt-0.5`} />
      <div className="flex-1">
        <p className={`text-sm font-medium ${c.text}`}>{title}</p>
        <p className="text-xs text-muted-foreground mt-0.5">{message}</p>
      </div>
      {dismissible && (
        <button onClick={() => setVisible(false)} className="text-muted-foreground hover:text-foreground">
          <X className="h-4 w-4" />
        </button>
      )}
    </div>
  );
}
