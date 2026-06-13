import clsx from "clsx";
import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

export function KpiCard({
  label,
  value,
  sub,
  icon: Icon,
  accent = "text-slate-100",
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  icon?: LucideIcon;
  accent?: string;
}) {
  return (
    <div className="card p-4">
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500">{label}</span>
        {Icon && <Icon className="h-4 w-4 text-slate-600" />}
      </div>
      <div className={clsx("mt-2 text-2xl font-semibold tabular-nums", accent)}>{value}</div>
      {sub && <div className="mt-1 text-xs text-slate-500">{sub}</div>}
    </div>
  );
}
