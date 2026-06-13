import { Area, AreaChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { titleCase } from "../lib/format";
import type { CountItem, TimeBucket } from "../types";

function ChartEmpty() {
  return <div className="flex h-40 items-center justify-center text-sm text-slate-600">No data yet</div>;
}

interface TipEntry {
  name?: string | number;
  value?: string | number;
  payload?: { key?: string; date?: string; count?: number; cost?: number };
}

function DonutTip({ active, payload }: { active?: boolean; payload?: TipEntry[] }) {
  if (!active || !payload?.length) return null;
  const p = payload[0];
  return (
    <div className="rounded-md border border-line bg-surface-2 px-2.5 py-1.5 text-xs shadow-card">
      <span className="text-slate-300">{titleCase(String(p.payload?.key ?? p.name ?? ""))}</span>
      <span className="ml-2 font-semibold tabular-nums text-slate-100">{p.value}</span>
    </div>
  );
}

function TrendTip({ active, payload }: { active?: boolean; payload?: TipEntry[] }) {
  if (!active || !payload?.length) return null;
  const d = payload[0]?.payload;
  return (
    <div className="rounded-md border border-line bg-surface-2 px-2.5 py-1.5 text-xs shadow-card">
      <div className="text-slate-400">{d?.date}</div>
      <div className="text-slate-200">
        {d?.count} scan{d?.count === 1 ? "" : "s"} · ${Number(d?.cost ?? 0).toFixed(2)}
      </div>
    </div>
  );
}

export function Donut({ data, colorFor }: { data: CountItem[]; colorFor: (k: string) => string }) {
  const total = data.reduce((s, d) => s + d.count, 0);
  if (!total) return <ChartEmpty />;
  return (
    <div>
      <div className="relative">
        <ResponsiveContainer width="100%" height={190}>
          <PieChart>
            <Pie
              data={data}
              dataKey="count"
              nameKey="key"
              innerRadius={56}
              outerRadius={82}
              paddingAngle={2}
              stroke="none"
            >
              {data.map((d) => (
                <Cell key={d.key} fill={colorFor(d.key)} />
              ))}
            </Pie>
            <Tooltip content={<DonutTip />} />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <div className="text-2xl font-semibold tabular-nums text-slate-100">{total}</div>
          <div className="text-[11px] uppercase tracking-wider text-slate-500">total</div>
        </div>
      </div>
      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5">
        {data.map((d) => (
          <div key={d.key} className="flex items-center gap-1.5 text-xs text-slate-400">
            <span className="h-2.5 w-2.5 rounded-sm" style={{ background: colorFor(d.key) }} />
            {titleCase(d.key)}
            <span className="tabular-nums text-slate-500">{d.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function BarList({
  data,
  colorFor,
  max,
}: {
  data: CountItem[];
  colorFor: (k: string) => string;
  max?: number;
}) {
  const rows = max ? data.slice(0, max) : data;
  if (!rows.length) return <ChartEmpty />;
  const peak = Math.max(1, ...rows.map((d) => d.count));
  return (
    <div className="space-y-2">
      {rows.map((d) => (
        <div key={d.key} className="flex items-center gap-3">
          <div className="w-28 shrink-0 truncate text-xs text-slate-400" title={titleCase(d.key)}>
            {titleCase(d.key)}
          </div>
          <div className="relative h-5 flex-1 overflow-hidden rounded bg-surface-3">
            <div
              className="h-full rounded"
              style={{ width: `${(d.count / peak) * 100}%`, background: colorFor(d.key) }}
            />
          </div>
          <div className="w-8 shrink-0 text-right text-xs tabular-nums text-slate-300">{d.count}</div>
        </div>
      ))}
    </div>
  );
}

export function Trend({ data }: { data: TimeBucket[] }) {
  if (!data.length) return <ChartEmpty />;
  return (
    <ResponsiveContainer width="100%" height={190}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
        <defs>
          <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#6ea8fe" stopOpacity={0.35} />
            <stop offset="100%" stopColor="#6ea8fe" stopOpacity={0} />
          </linearGradient>
        </defs>
        <XAxis dataKey="date" tick={{ fill: "#64748b", fontSize: 11 }} tickLine={false} axisLine={{ stroke: "#222c41" }} />
        <YAxis tick={{ fill: "#64748b", fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} width={28} />
        <Tooltip content={<TrendTip />} cursor={{ stroke: "#334155" }} />
        <Area type="monotone" dataKey="count" stroke="#6ea8fe" strokeWidth={2} fill="url(#trendFill)" />
      </AreaChart>
    </ResponsiveContainer>
  );
}
