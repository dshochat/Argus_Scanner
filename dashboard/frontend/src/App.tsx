import clsx from "clsx";
import { FolderGit2, LayoutDashboard, ListChecks, ShieldCheck } from "lucide-react";
import { NavLink, Route, Routes } from "react-router-dom";
import Overview from "./pages/Overview";
import Runs from "./pages/Runs";
import ScanDetail from "./pages/ScanDetail";
import Scans from "./pages/Scans";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/scans", label: "Scans", icon: ListChecks, end: false },
  { to: "/runs", label: "Runs", icon: FolderGit2, end: false },
];

export default function App() {
  return (
    <div className="flex h-full">
      <aside className="flex w-60 shrink-0 flex-col border-r border-line bg-surface-1">
        <div className="flex h-16 items-center gap-2.5 border-b border-line px-5">
          <ShieldCheck className="h-6 w-6 text-brand" />
          <div className="leading-tight">
            <div className="font-semibold tracking-tight text-slate-100">Argus</div>
            <div className="text-[11px] uppercase tracking-wider text-slate-500">security dashboard</div>
          </div>
        </div>
        <nav className="space-y-1 p-3">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                clsx(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition",
                  isActive
                    ? "bg-brand-soft text-brand"
                    : "text-slate-400 hover:bg-surface-2 hover:text-slate-200",
                )
              }
            >
              <item.icon className="h-4 w-4" />
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto border-t border-line p-4 text-[11px] leading-relaxed text-slate-500">
          <div className="font-medium text-slate-400">scan → validate → remediate</div>
          SAST detection, sandbox-confirmed exploits, and verified auto-fixes.
        </div>
      </aside>
      <main className="flex-1 overflow-auto">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/scans" element={<Scans />} />
          <Route path="/scans/:id" element={<ScanDetail />} />
          <Route path="/runs" element={<Runs />} />
        </Routes>
      </main>
    </div>
  );
}
