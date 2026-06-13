import clsx from "clsx";
import { AlertTriangle, Inbox, Loader2 } from "lucide-react";
import type { ReactNode } from "react";

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-line bg-surface-0/80 px-6 py-5 backdrop-blur">
      <div className="min-w-0">
        <h1 className="truncate text-lg font-semibold tracking-tight text-slate-100">{title}</h1>
        {subtitle && <div className="mt-0.5 text-sm text-slate-400">{subtitle}</div>}
      </div>
      {actions && <div className="shrink-0">{actions}</div>}
    </div>
  );
}

export function Card({
  className,
  children,
  padded = true,
}: {
  className?: string;
  children: ReactNode;
  padded?: boolean;
}) {
  return <div className={clsx("card", padded && "p-4", className)}>{children}</div>;
}

export function SectionTitle({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="mb-3 flex items-center justify-between">
      <h2 className="text-sm font-semibold text-slate-200">{children}</h2>
      {right}
    </div>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 p-8 text-sm text-slate-400">
      <Loader2 className="h-4 w-4 animate-spin" /> {label}
    </div>
  );
}

export function ErrorState({ error }: { error: unknown }) {
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div className="m-6 flex items-start gap-3 rounded-lg border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-200">
      <AlertTriangle className="h-5 w-5 shrink-0" />
      <div>
        <div className="font-medium">Couldn’t load data</div>
        <div className="text-rose-300/80">{msg}</div>
        <div className="mt-1 text-rose-300/60">Is the API up and Postgres reachable?</div>
      </div>
    </div>
  );
}

export function Empty({ label }: { label: string }) {
  return (
    <div className="flex flex-col items-center gap-2 p-12 text-slate-500">
      <Inbox className="h-8 w-8" />
      <span className="text-sm">{label}</span>
    </div>
  );
}
