import { Skeleton } from "@/components/ui/skeleton";

export function TableSkeleton({ rows = 5, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="bg-card border border-border rounded-lg overflow-hidden">
      <div className="border-b border-border bg-muted/50 p-3 flex gap-4">
        {Array.from({ length: cols }).map((_, i) => (
          <Skeleton key={i} className="h-4 flex-1" />
        ))}
      </div>
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="p-3 flex gap-4 border-b border-border last:border-0">
          {Array.from({ length: cols }).map((_, c) => (
            <Skeleton key={c} className="h-4 flex-1" />
          ))}
        </div>
      ))}
    </div>
  );
}

export function StatCardSkeleton() {
  return (
    <div className="stat-card flex items-start gap-4">
      <Skeleton className="h-10 w-10 rounded-lg" />
      <div className="space-y-2 flex-1">
        <Skeleton className="h-6 w-16" />
        <Skeleton className="h-3 w-24" />
      </div>
    </div>
  );
}

export function ChartSkeleton() {
  return (
    <div className="stat-card">
      <Skeleton className="h-4 w-32 mb-4" />
      <div className="flex items-end gap-2 h-40">
        {[40, 65, 30, 80, 55, 70, 45, 90, 60, 75, 35, 85].map((h, i) => (
          <Skeleton key={i} className="flex-1 rounded-t" style={{ height: `${h}%` }} />
        ))}
      </div>
    </div>
  );
}
