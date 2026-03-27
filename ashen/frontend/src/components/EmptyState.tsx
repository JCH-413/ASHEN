import { Inbox, Search, ShieldOff, FileX } from "lucide-react";
import { Button } from "@/components/ui/button";
import { LucideIcon } from "lucide-react";

interface EmptyStateProps {
  icon?: LucideIcon;
  title?: string;
  description?: string;
  /** Shorthand: if you only need one line */
  message?: string;
  actionLabel?: string;
  onAction?: () => void;
}

export function EmptyState({ icon: Icon = Inbox, title, description, message, actionLabel, onAction }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="h-14 w-14 rounded-full bg-muted flex items-center justify-center mb-4">
        <Icon className="h-7 w-7 text-muted-foreground" />
      </div>
      {title && <h3 className="font-semibold text-lg mb-1">{title}</h3>}
      {description && <p className="text-sm text-muted-foreground max-w-sm mb-4">{description}</p>}
      {message && !title && !description && (
        <p className="text-sm text-muted-foreground max-w-sm mb-4">{message}</p>
      )}
      {actionLabel && onAction && (
        <Button onClick={onAction}>{actionLabel}</Button>
      )}
    </div>
  );
}
