import { useQuery } from "@tanstack/react-query";
import { Bug, DollarSign, ScanLine, ShieldAlert, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { BarList, Donut, Trend } from "../components/charts";
import { KpiCard } from "../components/KpiCard";
import { ScanTable } from "../components/ScanTable";
import { Card, Empty, ErrorState, Loading, PageHeader, SectionTitle } from "../components/ui";
import { confidenceTone, severityTone, tone, verdictTone } from "../lib/colors";
import { formatCost } from "../lib/format";

export default function Overview() {
  const stats = useQuery({ queryKey: ["stats"], queryFn: api.stats });
  const recent = useQuery({ queryKey: ["scans", "recent"], queryFn: () => api.scans({ limit: 8 }) });

  return (
    <div>
      <PageHeader title="Overview" subtitle="Detection, sandbox validation, and verified remediation across all results." />
      <div className="space-y-6 p-6">
        {stats.isLoading ? (
          <Loading />
        ) : stats.error ? (
          <ErrorState error={stats.error} />
        ) : stats.data ? (
          <>
            <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
              <KpiCard label="Scans" value={stats.data.total_scans} icon={ScanLine} />
              <KpiCard
                label="Files at risk"
                value={stats.data.files_at_risk}
                icon={ShieldAlert}
                accent="text-amber-300"
              />
              <KpiCard
                label="Confirmed exploitable"
                value={stats.data.confirmed_exploitable}
                icon={Bug}
                accent="text-rose-300"
                sub="validated in the sandbox"
              />
              <KpiCard
                label="Auto-remediated"
                value={stats.data.auto_remediated_high}
                icon={ShieldCheck}
                accent="text-emerald-300"
                sub="verified HIGH"
              />
              <KpiCard label="API spend" value={formatCost(stats.data.total_cost_usd)} icon={DollarSign} />
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <Card>
                <SectionTitle>Verdicts</SectionTitle>
                <Donut data={stats.data.by_verdict} colorFor={(k) => tone(verdictTone, k).chart} />
              </Card>
              <Card>
                <SectionTitle>Remediation confidence</SectionTitle>
                <Donut data={stats.data.by_remediation_confidence} colorFor={(k) => tone(confidenceTone, k).chart} />
              </Card>
              <Card>
                <SectionTitle>Scans over time</SectionTitle>
                <Trend data={stats.data.over_time} />
              </Card>
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <Card>
                <SectionTitle>Findings by severity</SectionTitle>
                <BarList data={stats.data.by_severity} colorFor={(k) => tone(severityTone, k).chart} />
              </Card>
              <Card>
                <SectionTitle>Top vulnerability types</SectionTitle>
                <BarList data={stats.data.top_vuln_types} colorFor={() => "#6ea8fe"} max={8} />
              </Card>
            </div>
          </>
        ) : null}

        <Card padded={false}>
          <div className="flex items-center justify-between px-4 pt-4">
            <h2 className="text-sm font-semibold text-slate-200">Recent scans</h2>
            <Link to="/scans" className="text-xs text-brand hover:underline">
              View all →
            </Link>
          </div>
          <div className="mt-3">
            {recent.isLoading ? (
              <Loading />
            ) : recent.error ? (
              <ErrorState error={recent.error} />
            ) : recent.data && recent.data.items.length > 0 ? (
              <ScanTable items={recent.data.items} />
            ) : (
              <Empty label="No scans yet — run a scan with ARGUS_DB_URL set, or `argus dashboard ingest <path>`." />
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}
