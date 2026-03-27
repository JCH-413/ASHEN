import { ReactNode } from "react";
import { AppHeader } from "@/components/AppHeader";

interface PageShellProps {
  title: string;
  children: ReactNode;
}

export function PageShell({ title, children }: PageShellProps) {
  return (
    <>
      <AppHeader title={title} />
      <main className="flex-1 p-6 overflow-auto">{children}</main>
    </>
  );
}
