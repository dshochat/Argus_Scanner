import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { VerdictBadge } from "../components/Badge";
import { Card, Empty, ErrorState, Loading, PageHeader } from "../components/ui";
import { formatCost, relativeTime } from "../lib/format";

const TH = "px-3 py-2 font-medium";

export default function Runs() {
  const runs = useQuery({ queryKey: ["runs"], queryFn: api.runs });

  return (
    <div>
      <PageHeader title="Runs" subtitle="Repository scans, grouped by run." />
      <div className="p-6">
        <Card padded={false} className="overflow-hidden">
          {runs.isLoading ? (
            <Loading />
          ) : runs.error ? (
            <ErrorState error={runs.error} />
          ) : runs.data && runs.data.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-line text-left text-[11px] uppercase tracking-wider text-slate-500">
                    <th className={TH}>Run</th>
                    <th className={TH}>Files</th>
                    <th className={TH}>Findings</th>
                    <th className={TH}>Confirmed</th>
                    <th className={TH}>Worst verdict</th>
                    <th className={`${TH} text-right`}>Cost</th>
                    <th className={`${TH} text-right`}>When</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.data.map((r) => (
                    <tr key={r.run_id} className="border-b border-line/60 last:border-0 hover:bg-surface-2/50">
                      <td className="px-3 py-2.5">
                        <div className="font-medium text-slate-200" title={r.run_label || r.run_id}>
                          {r.run_label || r.run_id.slice(0, 12)}
                        </div>
                      </td>
                      <td className="px-3 py-2.5 tabular-nums text-slate-300">{r.n_files}</td>
                      <td className="px-3 py-2.5 tabular-nums text-slate-300">{r.n_findings}</td>
                      <td className="px-3 py-2.5 tabular-nums">
                        {r.n_confirmed > 0 ? (
                          <span className="text-rose-300">{r.n_confirmed}</span>
                        ) : (
                          <span className="text-slate-500">0</span>
                        )}
                      </td>
                      <td className="px-3 py-2.5">
                        <VerdictBadge value={r.worst_verdict} />
                      </td>
                      <td className="px-3 py-2.5 text-right tabular-nums text-slate-400">{formatCost(r.total_cost_usd)}</td>
                      <td className="px-3 py-2.5 text-right text-slate-500" title={r.created_at}>
                        {relativeTime(r.created_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty label="No repository runs yet. `argus scan-repo <path>` with ARGUS_DB_URL set creates a run." />
          )}
        </Card>
      </div>
    </div>
  );
}
