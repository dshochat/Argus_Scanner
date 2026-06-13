// Semantic color tones → Tailwind class fragments. One source of truth so
// severity/status/verdict/confidence read consistently everywhere.

export interface Tone {
  badge: string; // bg + text + ring for a .badge
  dot: string; // a small status dot bg
  text: string; // standalone text color
  chart: string; // hex for Recharts
}

function t(badge: string, dot: string, text: string, chart: string): Tone {
  return { badge, dot, text, chart };
}

const SLATE = t("bg-slate-500/15 text-slate-300 ring-slate-500/30", "bg-slate-400", "text-slate-300", "#94a3b8");

export const severityTone: Record<string, Tone> = {
  critical: t("bg-rose-500/15 text-rose-300 ring-rose-500/30", "bg-rose-400", "text-rose-300", "#fb7185"),
  high: t("bg-orange-500/15 text-orange-300 ring-orange-500/30", "bg-orange-400", "text-orange-300", "#fb923c"),
  medium: t("bg-amber-500/15 text-amber-300 ring-amber-500/30", "bg-amber-400", "text-amber-300", "#fbbf24"),
  low: t("bg-sky-500/15 text-sky-300 ring-sky-500/30", "bg-sky-400", "text-sky-300", "#38bdf8"),
};

export const verdictTone: Record<string, Tone> = {
  clean: t("bg-emerald-500/15 text-emerald-300 ring-emerald-500/30", "bg-emerald-400", "text-emerald-300", "#34d399"),
  informational: t("bg-sky-500/15 text-sky-300 ring-sky-500/30", "bg-sky-400", "text-sky-300", "#38bdf8"),
  suspicious: t("bg-amber-500/15 text-amber-300 ring-amber-500/30", "bg-amber-400", "text-amber-300", "#fbbf24"),
  malicious: t("bg-orange-500/15 text-orange-300 ring-orange-500/30", "bg-orange-400", "text-orange-300", "#fb923c"),
  critical_malicious: t("bg-rose-500/15 text-rose-300 ring-rose-500/30", "bg-rose-400", "text-rose-300", "#fb7185"),
};

export const riskTone: Record<string, Tone> = {
  none: t("bg-emerald-500/15 text-emerald-300 ring-emerald-500/30", "bg-emerald-400", "text-emerald-300", "#34d399"),
  low: t("bg-sky-500/15 text-sky-300 ring-sky-500/30", "bg-sky-400", "text-sky-300", "#38bdf8"),
  medium: t("bg-amber-500/15 text-amber-300 ring-amber-500/30", "bg-amber-400", "text-amber-300", "#fbbf24"),
  high: t("bg-orange-500/15 text-orange-300 ring-orange-500/30", "bg-orange-400", "text-orange-300", "#fb923c"),
  critical: t("bg-rose-500/15 text-rose-300 ring-rose-500/30", "bg-rose-400", "text-rose-300", "#fb7185"),
};

// DAST disposition. CONFIRMED = exploit fired (bad); BLOCKED = app defended (good).
export const statusTone: Record<string, Tone> = {
  CONFIRMED: t("bg-rose-500/15 text-rose-300 ring-rose-500/30", "bg-rose-400", "text-rose-300", "#fb7185"),
  BLOCKED: t("bg-emerald-500/15 text-emerald-300 ring-emerald-500/30", "bg-emerald-400", "text-emerald-300", "#34d399"),
  REJECTED: SLATE,
  UNREACHED: SLATE,
  NOT_TESTED: t("bg-zinc-500/15 text-zinc-400 ring-zinc-500/30", "bg-zinc-500", "text-zinc-400", "#71717a"),
};

// Remediation confidence + post-patch status.
export const confidenceTone: Record<string, Tone> = {
  HIGH: t("bg-emerald-500/15 text-emerald-300 ring-emerald-500/30", "bg-emerald-400", "text-emerald-300", "#34d399"),
  MEDIUM: t("bg-amber-500/15 text-amber-300 ring-amber-500/30", "bg-amber-400", "text-amber-300", "#fbbf24"),
  LOW: t("bg-slate-500/15 text-slate-300 ring-slate-500/30", "bg-slate-400", "text-slate-300", "#94a3b8"),
  FAILED: t("bg-rose-500/15 text-rose-300 ring-rose-500/30", "bg-rose-400", "text-rose-300", "#fb7185"),
  NEUTRALIZED: t("bg-emerald-500/15 text-emerald-300 ring-emerald-500/30", "bg-emerald-400", "text-emerald-300", "#34d399"),
  STILL_EXPLOITABLE: t("bg-rose-500/15 text-rose-300 ring-rose-500/30", "bg-rose-400", "text-rose-300", "#fb7185"),
  UNVERIFIABLE: t("bg-amber-500/15 text-amber-300 ring-amber-500/30", "bg-amber-400", "text-amber-300", "#fbbf24"),
};

export function tone(map: Record<string, Tone>, key: string | null | undefined): Tone {
  if (!key) return SLATE;
  return map[key] || map[key.toUpperCase()] || map[key.toLowerCase()] || SLATE;
}

export { SLATE };
