import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { useState } from "react";
import { api, type ScanQuery } from "../api";
import { ScanTable } from "../components/ScanTable";
import { Card, Empty, ErrorState, Loading, PageHeader } from "../components/ui";
import { titleCase } from "../lib/format";

const VERDICTS = ["clean", "informational", "suspicious", "malicious", "critical_malicious"];
const RISKS = ["none", "low", "medium", "high", "critical"];
const FIELD =
  "rounded-lg border border-line bg-surface-0 px-3 py-1.5 text-sm text-slate-200 focus:border-brand focus:outline-none";
const LIMIT = 25;

export default function Scans() {
  const [q, setQ] = useState("");
  const [verdict, setVerdict] = useState("");
  const [risk, setRisk] = useState("");
  const [offset, setOffset] = useState(0);

  const query: ScanQuery = { q, verdict, risk_level: risk, limit: LIMIT, offset };
  const scans = useQuery({
    queryKey: ["scans", query],
    queryFn: () => api.scans(query),
    placeholderData: keepPreviousData,
  });

  const total = scans.data?.total ?? 0;
  const reset = (fn: () => void) => {
    fn();
    setOffset(0);
  };
  const page = Math.floor(offset / LIMIT) + 1;
  const pages = Math.max(1, Math.ceil(total / LIMIT));

  return (
    <div>
      <PageHeader title="Scans" subtitle={`${total} result${total === 1 ? "" : "s"}`} />
      <div className="space-y-4 p-6">
        <Card>
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-2 h-4 w-4 text-slate-500" />
              <input
                value={q}
                onChange={(e) => reset(() => setQ(e.target.value))}
                placeholder="Search filename…"
                className={`${FIELD} pl-8`}
              />
            </div>
            <select value={verdict} onChange={(e) => reset(() => setVerdict(e.target.value))} className={FIELD}>
              <option value="">All verdicts</option>
              {VERDICTS.map((v) => (
                <option key={v} value={v}>
                  {titleCase(v)}
                </option>
              ))}
            </select>
            <select value={risk} onChange={(e) => reset(() => setRisk(e.target.value))} className={FIELD}>
              <option value="">All risk levels</option>
              {RISKS.map((r) => (
                <option key={r} value={r}>
                  {titleCase(r)}
                </option>
              ))}
            </select>
          </div>
        </Card>

        <Card padded={false} className="overflow-hidden">
          {scans.isLoading ? (
            <Loading />
          ) : scans.error ? (
            <ErrorState error={scans.error} />
          ) : scans.data && scans.data.items.length > 0 ? (
            <>
              <ScanTable items={scans.data.items} />
              <div className="flex items-center justify-between border-t border-line px-4 py-3 text-xs text-slate-400">
                <span>
                  Page {page} of {pages}
                </span>
                <div className="flex gap-2">
                  <button
                    onClick={() => setOffset(Math.max(0, offset - LIMIT))}
                    disabled={offset === 0}
                    className="rounded-md border border-line px-3 py-1 hover:bg-surface-2 disabled:opacity-40"
                  >
                    Previous
                  </button>
                  <button
                    onClick={() => setOffset(offset + LIMIT)}
                    disabled={offset + LIMIT >= total}
                    className="rounded-md border border-line px-3 py-1 hover:bg-surface-2 disabled:opacity-40"
                  >
                    Next
                  </button>
                </div>
              </div>
            </>
          ) : (
            <Empty label="No scans match these filters." />
          )}
        </Card>
      </div>
    </div>
  );
}
