import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import {
  ArrowLeft,
  Check,
  CircleDollarSign,
  FlaskConical,
  Search,
  ShieldCheck,
  X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { ConfidenceBadge, RiskBadge, SeverityBadge, StatusBadge, VerdictBadge } from "../components/Badge";
import { CodeBlock, InlineCode } from "../components/CodeBlock";
import { ErrorState, Loading, PageHeader } from "../components/ui";
import { confidenceTone, tone } from "../lib/colors";
import { baseName, formatCost, formatDuration, titleCase } from "../lib/format";
import type {
  ModelCall,
  PerFindingValidation,
  PhaseC,
  RawScanResult,
  Variant,
  Vulnerability,
} from "../types";

function Label({ children }: { children: ReactNode }) {
  return <div className="mb-1 text-[11px] font-medium uppercase tracking-wider text-slate-500">{children}</div>;
}

function Stage({
  n,
  title,
  subtitle,
  icon: Icon,
  ringClass,
  last,
  children,
}: {
  n: number;
  title: string;
  subtitle?: ReactNode;
  icon: LucideIcon;
  ringClass: string;
  last?: boolean;
  children: ReactNode;
}) {
  return (
    <li className="relative pl-14">
      {!last && <span className="absolute left-[22px] top-11 bottom-[-1.25rem] w-px bg-line" />}
      <span
        className={clsx(
          "absolute left-0 top-0 flex h-11 w-11 items-center justify-center rounded-full border bg-surface-1",
          ringClass,
        )}
      >
        <Icon className="h-5 w-5" />
      </span>
      <div className="card p-4">
        <div className="mb-3 flex items-center justify-between gap-3">
          <div>
            <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Stage {n}</div>
            <div className="text-sm font-semibold text-slate-100">{title}</div>
          </div>
          {subtitle && <div className="text-right text-xs text-slate-400">{subtitle}</div>}
        </div>
        {children}
      </div>
    </li>
  );
}

function FindingCard({ v }: { v: Vulnerability }) {
  return (
    <div className="rounded-lg border border-line bg-surface-0/40 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <SeverityBadge value={v.severity} />
          <span className="font-medium text-slate-200">{titleCase(v.type)}</span>
          {v.cwe && <span className="text-xs text-slate-500">{v.cwe}</span>}
        </div>
        {typeof v.line === "number" && <span className="text-xs text-slate-500">line {v.line}</span>}
      </div>
      {v.explanation && <p className="mt-2 text-sm leading-relaxed text-slate-400">{v.explanation}</p>}
      {v.code && <CodeBlock code={v.code} maxHeight="max-h-40" className="mt-2" />}
      {v.proof_of_concept && (
        <div className="mt-2">
          <Label>Proof of concept</Label>
          <CodeBlock code={v.proof_of_concept} maxHeight="max-h-28" />
        </div>
      )}
      {v.data_flow_trace && (
        <div className="mt-2 text-xs text-slate-500">
          <span className="text-slate-400">Data flow: </span>
          {v.data_flow_trace}
        </div>
      )}
    </div>
  );
}

function ValidationRow({ v }: { v: PerFindingValidation }) {
  return (
    <div className="flex items-start gap-3 rounded-lg border border-line bg-surface-0/40 p-3">
      <div className="pt-0.5">
        <StatusBadge value={v.status} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <span className="font-medium text-slate-200">{titleCase(v.type)}</span>
          {v.cwe && <span className="text-xs text-slate-500">{v.cwe}</span>}
          {v.finding_id && <span className="text-xs text-slate-600">{v.finding_id}</span>}
        </div>
        {v.runtime_evidence && <p className="mt-1 text-sm text-slate-400">{v.runtime_evidence}</p>}
        {v.rejection_reason && <p className="mt-1 text-sm text-slate-500">{v.rejection_reason}</p>}
        {v.not_tested_reason && <p className="mt-1 text-xs text-slate-500">reason: {v.not_tested_reason}</p>}
        {v.proof_of_concept && (
          <div className="mt-1.5">
            <InlineCode>{v.proof_of_concept}</InlineCode>
          </div>
        )}
      </div>
    </div>
  );
}

function VariantTable({ variants }: { variants: Variant[] }) {
  return (
    <div className="overflow-hidden rounded-lg border border-line">
      <table className="w-full text-xs">
        <thead className="bg-surface-0/60 text-left text-[11px] uppercase tracking-wider text-slate-500">
          <tr>
            <th className="px-3 py-2 font-medium">Technique</th>
            <th className="px-3 py-2 font-medium">Payload</th>
            <th className="px-3 py-2 text-right font-medium">Result</th>
          </tr>
        </thead>
        <tbody>
          {variants.map((vt, i) => {
            const fired = (vt.result || "").toUpperCase().includes("FIRE") || (vt.result || "").toUpperCase() === "REACHED";
            return (
              <tr key={i} className="border-t border-line/60">
                <td className="px-3 py-2 text-slate-300">{vt.description || "—"}</td>
                <td className="px-3 py-2">
                  <code className="break-all font-mono text-[11px] text-slate-400">{vt.payload || "—"}</code>
                </td>
                <td className="px-3 py-2 text-right">
                  <span
                    className={clsx(
                      "badge",
                      fired
                        ? "bg-rose-500/15 text-rose-300 ring-rose-500/30"
                        : "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
                    )}
                  >
                    {fired ? "Exploited" : "Blocked"}
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function GateChip({ ok, label }: { ok: boolean | null | undefined; label: string }) {
  if (ok === null || ok === undefined) {
    return <span className="badge bg-zinc-500/15 text-zinc-400 ring-zinc-500/30">{label}: n/a</span>;
  }
  return (
    <span
      className={clsx(
        "badge",
        ok ? "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30" : "bg-rose-500/15 text-rose-300 ring-rose-500/30",
      )}
    >
      {ok ? <Check className="h-3 w-3" /> : <X className="h-3 w-3" />} {label}
    </span>
  );
}

function RemediationPanel({ pc }: { pc: PhaseC }) {
  const v = pc.verification;
  if (pc.skipped_reason) {
    return <p className="text-sm text-slate-500">Remediation not run — {pc.skipped_reason.replace(/_/g, " ")}.</p>;
  }
  if (!pc.attempted) {
    return <p className="text-sm text-slate-500">No remediation attempted.</p>;
  }
  return (
    <div className="space-y-4">
      {v?.confidence && (
        <div className="flex items-center gap-3 rounded-lg border border-line bg-surface-0/40 p-3">
          <span className="text-sm text-slate-400">Verified confidence</span>
          <ConfidenceBadge value={v.confidence} />
          <div className="ml-auto flex flex-wrap gap-2">
            <GateChip ok={v.functional_ok} label="Functional preserved" />
            {typeof v.variants_total === "number" && (
              <span
                className={clsx(
                  "badge",
                  (v.variants_fired ?? 0) > 0
                    ? "bg-rose-500/15 text-rose-300 ring-rose-500/30"
                    : "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
                )}
              >
                {(v.variants_total ?? 0) - (v.variants_fired ?? 0)}/{v.variants_total} variants blocked
              </span>
            )}
          </div>
        </div>
      )}

      {pc.fix_summary && <p className="text-sm leading-relaxed text-slate-300">{pc.fix_summary}</p>}

      {pc.per_finding && pc.per_finding.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {pc.per_finding.map((f, i) => (
            <span key={i} className="badge bg-surface-3 text-slate-300 ring-line">
              {f.finding_ref}: {titleCase(f.post_patch_status)}
            </span>
          ))}
        </div>
      )}

      {v?.variants && v.variants.length > 0 && (
        <div>
          <Label>Adversarial variants (same-class bypass attempts)</Label>
          <VariantTable variants={v.variants} />
        </div>
      )}

      {pc.patched_source && (
        <details className="group">
          <summary className="cursor-pointer text-xs text-brand hover:underline">Show patched source</summary>
          <CodeBlock code={pc.patched_source} maxHeight="max-h-96" className="mt-2" />
        </details>
      )}
    </div>
  );
}

function CostBreakdown({ calls, total }: { calls: ModelCall[]; total: number | null | undefined }) {
  const byStage = new Map<string, number>();
  for (const c of calls) {
    const key = c.stage || "other";
    byStage.set(key, (byStage.get(key) ?? 0) + (c.cost_usd ?? 0));
  }
  const rows = [...byStage.entries()].sort((a, b) => b[1] - a[1]);
  const peak = Math.max(1e-9, ...rows.map((r) => r[1]));
  return (
    <div className="space-y-2">
      {rows.map(([stage, cost]) => (
        <div key={stage} className="flex items-center gap-3">
          <div className="w-32 shrink-0 truncate text-xs text-slate-400">{titleCase(stage)}</div>
          <div className="relative h-4 flex-1 overflow-hidden rounded bg-surface-3">
            <div className="h-full rounded bg-brand-dim" style={{ width: `${(cost / peak) * 100}%` }} />
          </div>
          <div className="w-20 shrink-0 text-right text-xs tabular-nums text-slate-300">{formatCost(cost)}</div>
        </div>
      ))}
      <div className="flex items-center justify-between border-t border-line pt-2 text-sm">
        <span className="text-slate-400">Total</span>
        <span className="font-semibold tabular-nums text-slate-100">{formatCost(total)}</span>
      </div>
    </div>
  );
}

function SummaryBand({ raw, headline }: { raw: RawScanResult; headline: { findings: number; confirmed: number; confidence: string | null } }) {
  return (
    <div className="card p-5">
      <div className="flex flex-wrap items-center gap-3">
        <VerdictBadge value={raw.final_verdict} />
        <RiskBadge value={raw.risk_level} />
        {raw.language && <span className="text-xs text-slate-500">{raw.language}</span>}
        {raw.triage_classification && (
          <span className="text-xs text-slate-500">triage: {raw.triage_classification}</span>
        )}
        <div className="ml-auto flex items-center gap-4 text-xs text-slate-400">
          <span>{formatCost(raw.total_cost_usd)}</span>
          <span>{formatDuration(raw.total_duration_ms)}</span>
        </div>
      </div>

      <p className="mt-4 text-sm text-slate-300">
        <span className="font-semibold text-slate-100">{headline.findings}</span> finding
        {headline.findings === 1 ? "" : "s"} ·{" "}
        <span className={clsx("font-semibold", headline.confirmed > 0 ? "text-rose-300" : "text-slate-300")}>
          {headline.confirmed}
        </span>{" "}
        confirmed exploitable ·{" "}
        {headline.confidence ? (
          <>
            remediation{" "}
            <span className={clsx("font-semibold", tone(confidenceTone, headline.confidence).text)}>
              {headline.confidence}
            </span>
          </>
        ) : (
          <span className="text-slate-500">no verified remediation</span>
        )}
      </p>

      {raw.scan_path && raw.scan_path.length > 0 && (
        <div className="mt-4 flex flex-wrap items-center gap-1.5">
          {raw.scan_path.map((step, i) => (
            <span key={i} className="flex items-center gap-1.5">
              <span className="rounded-md bg-surface-3 px-2 py-0.5 text-[11px] text-slate-400">{step}</span>
              {i < raw.scan_path!.length - 1 && <span className="text-slate-600">→</span>}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export default function ScanDetail() {
  const { id } = useParams();
  const scan = useQuery({ queryKey: ["scan", id], queryFn: () => api.scan(id!), enabled: !!id });

  if (scan.isLoading) return <Loading />;
  if (scan.error) return <ErrorState error={scan.error} />;
  if (!scan.data) return null;

  const raw = scan.data.raw || {};
  const vulns = raw.vulnerabilities ?? [];
  const validations = raw.per_finding_validation ?? [];
  const pc = raw.phase_c ?? null;
  const calls = raw.model_calls ?? [];

  return (
    <div>
      <PageHeader
        title={baseName(scan.data.filename)}
        subtitle={scan.data.filename}
        actions={
          <Link to="/scans" className="flex items-center gap-1.5 text-sm text-slate-400 hover:text-slate-200">
            <ArrowLeft className="h-4 w-4" /> Scans
          </Link>
        }
      />
      <div className="mx-auto max-w-4xl space-y-6 p-6">
        <SummaryBand
          raw={raw}
          headline={{
            findings: scan.data.n_findings,
            confirmed: scan.data.n_confirmed,
            confidence: scan.data.remediation_confidence,
          }}
        />

        <ol className="space-y-5">
          <Stage
            n={1}
            title="Scan — SAST detection"
            icon={Search}
            ringClass="border-sky-500/40 text-sky-300"
            subtitle={`${vulns.length} finding${vulns.length === 1 ? "" : "s"}`}
          >
            {vulns.length > 0 ? (
              <div className="space-y-2.5">
                {vulns.map((v, i) => (
                  <FindingCard key={i} v={v} />
                ))}
              </div>
            ) : (
              <p className="text-sm text-slate-500">No vulnerabilities reported by L1 analysis.</p>
            )}
          </Stage>

          <Stage
            n={2}
            title="Validation — DAST sandbox"
            icon={FlaskConical}
            ringClass="border-amber-500/40 text-amber-300"
            subtitle={
              raw.dast_attempted
                ? `${validations.filter((v) => (v.status || "").toUpperCase() === "CONFIRMED").length} confirmed`
                : "not run"
            }
          >
            {raw.dast_attempted && validations.length > 0 ? (
              <div className="space-y-2.5">
                {validations.map((v, i) => (
                  <ValidationRow key={i} v={v} />
                ))}
              </div>
            ) : (
              <p className="text-sm text-slate-500">
                DAST validation did not run for this file (it triggers on suspicious / malicious verdicts).
              </p>
            )}
          </Stage>

          <Stage
            n={3}
            title="Remediation — verified auto-fix"
            icon={ShieldCheck}
            ringClass="border-emerald-500/40 text-emerald-300"
            subtitle={pc?.verification?.confidence ? <ConfidenceBadge value={pc.verification.confidence} /> : undefined}
            last
          >
            {pc ? <RemediationPanel pc={pc} /> : <p className="text-sm text-slate-500">No remediation stage ran.</p>}
          </Stage>
        </ol>

        {calls.length > 0 && (
          <div className="card p-4">
            <div className="mb-3 flex items-center gap-2">
              <CircleDollarSign className="h-4 w-4 text-slate-500" />
              <h2 className="text-sm font-semibold text-slate-200">Cost &amp; telemetry</h2>
              <span className="text-xs text-slate-500">{calls.length} model calls</span>
            </div>
            <CostBreakdown calls={calls} total={raw.total_cost_usd} />
          </div>
        )}
      </div>
    </div>
  );
}
