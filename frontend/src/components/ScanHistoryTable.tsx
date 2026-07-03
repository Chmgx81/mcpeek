"use client";

import { useRouter } from "next/navigation";
import { ArrowRight } from "lucide-react";
import type { ScanResponse } from "@/lib/types";

const TYPE_LABELS: Record<string, string> = {
  mcp_server: "MCP Server",
  agent_skill: "Agent Skill",
  npm_package: "npm",
  pypi_package: "PyPI",
};

const RISK_COLORS: Record<string, { bg: string; text: string }> = {
  critical: { bg: "rgba(239,68,68,0.1)", text: "#ef4444" },
  high: { bg: "rgba(249,115,22,0.1)", text: "#f97316" },
  medium: { bg: "rgba(234,179,8,0.1)", text: "#eab308" },
  low: { bg: "rgba(34,197,94,0.1)", text: "#22c55e" },
  safe: { bg: "rgba(34,197,94,0.1)", text: "#22c55e" },
};

const STATUS_COLORS: Record<string, { bg: string; text: string }> = {
  completed: { bg: "rgba(34,197,94,0.1)", text: "#22c55e" },
  failed: { bg: "rgba(239,68,68,0.1)", text: "#ef4444" },
  pending: { bg: "rgba(234,179,8,0.1)", text: "#eab308" },
  running: { bg: "rgba(59,130,246,0.1)", text: "#3b82f6" },
};

export default function ScanHistoryTable({ scans, loading }: { scans: ScanResponse[]; loading: boolean }) {
  const router = useRouter();

  if (loading) {
    return (
      <div style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}>
        <table className="w-full">
          <thead>
            <tr style={{ borderBottom: "1px solid #1a1a1a" }}>
              {["Target", "Type", "Risk", "Status", "Date"].map((h) => (
                <th key={h} className="px-3 py-2 text-left text-[11px] font-medium" style={{ color: "#525252" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[1, 2, 3].map((i) => (
              <tr key={i} style={{ borderBottom: "1px solid #1a1a1a" }}>
                {[1, 2, 3, 4, 5].map((j) => (
                  <td key={j} className="px-3 py-2">
                    <div className="h-3 w-16 rounded animate-pulse" style={{ background: "#1a1a1a" }} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  if (scans.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12" style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}>
        <p className="text-[13px]" style={{ color: "#525252" }}>No scans yet</p>
        <p className="text-[11px] mt-0.5" style={{ color: "#404040" }}>Submit a scan from the dashboard to get started.</p>
      </div>
    );
  }

  return (
    <div style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}>
      <table className="w-full">
        <thead>
          <tr style={{ borderBottom: "1px solid #1a1a1a" }}>
            <th className="px-3 py-2 text-left text-[11px] font-medium" style={{ color: "#525252" }}>Target</th>
            <th className="px-3 py-2 text-left text-[11px] font-medium hidden sm:table-cell" style={{ color: "#525252" }}>Type</th>
            <th className="px-3 py-2 text-left text-[11px] font-medium" style={{ color: "#525252" }}>Risk</th>
            <th className="px-3 py-2 text-left text-[11px] font-medium" style={{ color: "#525252" }}>Status</th>
            <th className="px-3 py-2 text-left text-[11px] font-medium hidden sm:table-cell" style={{ color: "#525252" }}>Date</th>
            <th className="px-3 py-2 w-6" />
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => {
            const riskStyle = RISK_COLORS[scan.risk_level] || RISK_COLORS.safe;
            const statusStyle = STATUS_COLORS[scan.status] || STATUS_COLORS.pending;
            return (
              <tr
                key={scan.scan_id}
                onClick={() => router.push(`/scan/${scan.scan_id}`)}
                className="cursor-pointer transition-colors"
                style={{ borderBottom: "1px solid #1a1a1a" }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "#141414")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
              >
                <td className="px-3 py-2 text-[12px] font-medium truncate max-w-[180px]" style={{ color: "#e5e5e5" }}>
                  {scan.target}
                </td>
                <td className="px-3 py-2 text-[11px] hidden sm:table-cell" style={{ color: "#525252" }}>
                  {TYPE_LABELS[scan.target_type] || scan.target_type}
                </td>
                <td className="px-3 py-2">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[12px] font-mono font-medium tabular-nums" style={{ color: "#a3a3a3" }}>
                      {scan.overall_risk}
                    </span>
                    <span
                      className="inline-flex px-1.5 py-0.5 text-[8px] font-semibold uppercase"
                      style={{ background: riskStyle.bg, color: riskStyle.text, borderRadius: "2px" }}
                    >
                      {scan.risk_level}
                    </span>
                  </div>
                </td>
                <td className="px-3 py-2">
                  <span
                    className="inline-flex px-1.5 py-0.5 text-[8px] font-semibold uppercase"
                    style={{ background: statusStyle.bg, color: statusStyle.text, borderRadius: "2px" }}
                  >
                    {scan.status}
                  </span>
                </td>
                <td className="px-3 py-2 text-[11px] hidden sm:table-cell" style={{ color: "#525252" }}>
                  {new Date(scan.created_at).toLocaleDateString()}
                </td>
                <td className="px-3 py-2">
                  <ArrowRight className="h-3 w-3" style={{ color: "#404040" }} />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
