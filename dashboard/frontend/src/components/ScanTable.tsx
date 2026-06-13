import { Link } from "react-router-dom";
import { baseName, formatCost, relativeTime } from "../lib/format";
import type { ScanSummary } from "../types";
import { ConfidenceBadge, RiskBadge, VerdictBadge } from "./Badge";

const TH = "px-3 py-2 font-medium";

export function ScanTable({ items }: { items: ScanSummary[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-line text-left text-[11px] uppercase tracking-wider text-slate-500">
            <th className={TH}>File</th>
            <th className={TH}>Lang</th>
            <th className={TH}>Verdict</th>
            <th className={TH}>Risk</th>
            <th className={TH}>Findings</th>
            <th className={TH}>Confirmed</th>
            <th className={TH}>Remediation</th>
            <th className={`${TH} text-right`}>Cost</th>
            <th className={`${TH} text-right`}>When</th>
          </tr>
        </thead>
        <tbody>
          {items.map((s) => (
            <tr key={s.id} className="group border-b border-line/60 last:border-0 hover:bg-surface-2/50">
              <td className="px-3 py-2.5">
                <Link
                  to={`/scans/${s.id}`}
                  className="font-medium text-slate-200 group-hover:text-brand"
                  title={s.filename}
                >
                  {baseName(s.filename)}
                </Link>
              </td>
              <td className="px-3 py-2.5 text-slate-400">{s.language || "—"}</td>
              <td className="px-3 py-2.5">
                <VerdictBadge value={s.final_verdict} />
              </td>
              <td className="px-3 py-2.5">
                <RiskBadge value={s.risk_level} />
              </td>
              <td className="px-3 py-2.5 tabular-nums text-slate-300">{s.n_findings}</td>
              <td className="px-3 py-2.5 tabular-nums">
                {s.n_confirmed > 0 ? (
                  <span className="text-rose-300">{s.n_confirmed}</span>
                ) : (
                  <span className="text-slate-500">0</span>
                )}
              </td>
              <td className="px-3 py-2.5">
                <ConfidenceBadge value={s.remediation_confidence} />
              </td>
              <td className="px-3 py-2.5 text-right tabular-nums text-slate-400">{formatCost(s.total_cost_usd)}</td>
              <td className="px-3 py-2.5 text-right text-slate-500" title={s.created_at}>
                {relativeTime(s.created_at)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
