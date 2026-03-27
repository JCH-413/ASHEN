import { AlertTriangle, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface EthicalDisclaimerProps {
  open: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  action: string;
  target?: string;
}

export function EthicalDisclaimer({ open, onConfirm, onCancel, action, target }: EthicalDisclaimerProps) {
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onCancel()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <div className="mx-auto h-12 w-12 rounded-full bg-warning/10 flex items-center justify-center mb-2">
            <AlertTriangle className="h-6 w-6 text-warning" />
          </div>
          <DialogTitle className="text-center">Ethical Compliance Confirmation</DialogTitle>
          <DialogDescription className="text-center">
            You are about to perform a sensitive security operation.
          </DialogDescription>
        </DialogHeader>
        <div className="bg-muted rounded-lg p-4 text-sm space-y-2">
          <p><span className="font-medium">Action:</span> {action}</p>
          {target && <p><span className="font-medium">Target:</span> <span className="font-mono">{target}</span></p>}
          <div className="mt-3 pt-3 border-t border-border">
            <div className="flex items-start gap-2">
              <ShieldAlert className="h-4 w-4 text-primary mt-0.5 shrink-0" />
              <p className="text-xs text-muted-foreground">
                By proceeding, you confirm this action is authorized under your organization's security testing policy
                and applicable legal frameworks. All actions are logged and auditable.
              </p>
            </div>
          </div>
        </div>
        <DialogFooter className="gap-2 sm:gap-0">
          <Button variant="outline" onClick={onCancel}>Cancel</Button>
          <Button variant="destructive" onClick={onConfirm}>I Understand — Proceed</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
