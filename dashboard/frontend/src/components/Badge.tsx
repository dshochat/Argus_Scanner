import clsx from "clsx";
import type { ReactNode } from "react";
import { confidenceTone, riskTone, severityTone, statusTone, tone, verdictTone } from "../lib/colors";
import { titleCase } from "../lib/format";

export function Badge({
  toneClass,
  children,
  className,
}: {
  toneClass: string;
  children: ReactNode;
  className?: string;
}) {
  return <span className={clsx("badge", toneClass, className)}>{children}</span>;
}

export function SeverityBadge({ value }: { value?: string | null }) {
  return <Badge toneClass={tone(severityTone, value).badge}>{titleCase(value)}</Badge>;
}

export function VerdictBadge({ value }: { value?: string | null }) {
  return <Badge toneClass={tone(verdictTone, value).badge}>{titleCase(value)}</Badge>;
}

export function RiskBadge({ value }: { value?: string | null }) {
  return <Badge toneClass={tone(riskTone, value).badge}>{titleCase(value)}</Badge>;
}

export function StatusBadge({ value }: { value?: string | null }) {
  return <Badge toneClass={tone(statusTone, value).badge}>{titleCase(value)}</Badge>;
}

export function ConfidenceBadge({ value }: { value?: string | null }) {
  if (!value) return <span className="text-xs text-slate-500">—</span>;
  return <Badge toneClass={tone(confidenceTone, value).badge}>{titleCase(value)}</Badge>;
}
