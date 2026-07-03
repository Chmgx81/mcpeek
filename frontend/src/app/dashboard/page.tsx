"use client";

import { useEffect, useState, useCallback } from "react";
import { TrendingUp, AlertTriangle, Clock } from "lucide-react";
import ScanForm from "@/components/ScanForm";
import ScanHistoryTable from "@/components/ScanHistoryTable";
import OnboardingTour from "@/components/OnboardingTour";
import { fetchStats, fetchScans, deleteScan } from "@/lib/api";
import type { StatsResponse, ScanResponse } from "@/lib/types";

export default function DashboardPage() {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [recentScans, setRecentScans] = useState<ScanResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const load = useCallback(() => {
    Promise.all([
      fetchStats().catch(() => null),
      fetchScans(1, 5).catch(() => ({ scans: [], total: 0, page: 1, limit: 5, pages: 0 })),
    ]).then(([s, r]) => {
      setStats(s);
      setRecentScans(r.scans);
      setLoading(false);
    });
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleDelete = async (id: string) => {
    if (!confirm("Delete this scan? This cannot be undone.")) return;
    setDeletingId(id);
    try {
      await deleteScan(id);
      setRecentScans((prev) => prev.filter((s) => s.scan_id !== id));
      setStats((prev) => prev ? { ...prev, total_scans: Math.max(0, prev.total_scans - 1) } : prev);
    } catch {
      // ignore
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="px-5 py-6 md:px-8">
      <OnboardingTour />
      <div className="mx-auto max-w-3xl space-y-6">
        <div>
          <p className="text-[10px] font-medium uppercase tracking-widest mb-1" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>Scanner</p>
          <h1 className="text-lg font-bold" style={{ color: "#fafafa", letterSpacing: "-0.02em" }}>Dashboard</h1>
          <p className="text-[13px] mt-0.5" style={{ color: "#525252" }}>
            Scan MCP server configurations, AI agent skills, and toolchains.
          </p>
        </div>

        <div data-tour="scan-form">
          <ScanForm />
        </div>

        <div data-tour="stats">
          <p className="text-[10px] font-medium uppercase tracking-widest mb-2" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>Overview</p>
          {loading ? (
            <div className="grid grid-cols-3 gap-2">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-16 rounded" style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }} />
              ))}
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
              <StatCard icon={TrendingUp} value={stats?.total_scans ?? 0} label="Total Scans" />
              <StatCard icon={AlertTriangle} value={(stats?.risk_distribution?.critical ?? 0) + (stats?.risk_distribution?.high ?? 0)} label="Critical & High" />
              <StatCard icon={Clock} value={recentScans.length} label="Recent" />
            </div>
          )}
        </div>

        <div>
          <p className="text-[10px] font-medium uppercase tracking-widest mb-2" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>Recent Scans</p>
          <ScanHistoryTable scans={recentScans} loading={loading} onDelete={handleDelete} deletingId={deletingId} />
        </div>
      </div>
    </div>
  );
}

function StatCard({ icon: Icon, value, label }: { icon: React.ElementType; value: number; label: string }) {
  return (
    <div className="flex items-center gap-2.5 p-3" style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}>
      <div className="flex h-8 w-8 items-center justify-center rounded" style={{ background: "rgba(34,197,94,0.08)" }}>
        <Icon className="h-3.5 w-3.5" style={{ color: "#22c55e" }} />
      </div>
      <div>
        <p className="text-base font-bold tabular-nums" style={{ color: "#e5e5e5" }}>{value}</p>
        <p className="text-[11px]" style={{ color: "#525252" }}>{label}</p>
      </div>
    </div>
  );
}
