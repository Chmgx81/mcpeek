"use client";

import { Lock, ChevronRight } from "lucide-react";
import Logo from "@/components/Logo";

export default function HeroMockup() {
  return (
    <div
      className="relative mx-auto w-full max-w-4xl overflow-hidden"
      style={{
        borderRadius: "12px",
        border: "1px solid #262626",
        boxShadow: "0 0 0 1px rgba(34,197,94,0.05), 0 32px 64px -16px rgba(0,0,0,0.7)",
      }}
    >
      <div
        className="flex items-center gap-2.5 px-3 py-2"
        style={{ background: "#111111", borderBottom: "1px solid #1a1a1a" }}
      >
        <div className="flex gap-1.5">
          <div className="h-2.5 w-2.5 rounded-full" style={{ background: "#ef4444" }} />
          <div className="h-2.5 w-2.5 rounded-full" style={{ background: "#eab308" }} />
          <div className="h-2.5 w-2.5 rounded-full" style={{ background: "#22c55e" }} />
        </div>
        <div className="flex-1 flex justify-center">
          <div className="flex items-center gap-1.5 rounded px-3 py-0.5" style={{ background: "#1a1a1a", width: "220px" }}>
            <Lock className="h-2.5 w-2.5 shrink-0" style={{ color: "#525252" }} />
            <span className="text-[10px]" style={{ color: "#525252" }}>localhost:3000/dashboard</span>
          </div>
        </div>
      </div>
      <div className="flex" style={{ background: "#0a0a0a", minHeight: "340px" }}>
        <div
          className="hidden md:flex flex-col w-[150px] shrink-0 py-3 px-2"
          style={{ borderRight: "1px solid #1a1a1a" }}
        >
          <div className="flex items-center gap-1.5 px-2 py-1.5 mb-4">
            <Logo size={12} />
            <span className="text-[10px] font-semibold" style={{ color: "#e5e5e5" }}>MCPeek</span>
          </div>
          {[
            { label: "Dashboard", active: true },
            { label: "History", active: false },
          ].map((item) => (
            <div
              key={item.label}
              className="flex items-center gap-2 rounded px-2 py-1.5 mb-0.5"
              style={{
                background: item.active ? "rgba(34,197,94,0.08)" : "transparent",
                color: item.active ? "#22c55e" : "#525252",
              }}
            >
              <div className="h-3 w-3 rounded-sm" style={{ background: item.active ? "#22c55e" : "#333" }} />
              <span className="text-[10px] font-medium">{item.label}</span>
            </div>
          ))}
        </div>
        <div className="flex-1 p-4 space-y-3">
          <div>
            <div className="text-[9px] font-medium uppercase tracking-widest mb-0.5" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>Scanner</div>
            <div className="text-[12px] font-semibold" style={{ color: "#e5e5e5" }}>Dashboard</div>
          </div>
          <div className="rounded p-3" style={{ border: "1px solid #1a1a1a", background: "#111111" }}>
            <div className="text-[10px] font-medium mb-2" style={{ color: "#a3a3a3" }}>New Scan</div>
            <div className="flex gap-1.5">
              <div className="rounded px-2 py-1.5 text-[9px] font-medium shrink-0" style={{ background: "#1a1a1a", border: "1px solid #262626", color: "#737373" }}>MCP Server</div>
              <div className="flex-1 rounded px-2 py-1.5 text-[9px]" style={{ background: "#0a0a0a", border: "1px solid #262626", color: "#525252" }}>https://github.com/user/repo</div>
              <div className="rounded px-3 py-1.5 text-[9px] font-medium" style={{ background: "#22c55e", color: "#000" }}>Scan</div>
            </div>
          </div>
          <div className="grid grid-cols-3 gap-2">
            <div className="rounded p-3 text-center" style={{ border: "1px solid #1a1a1a", background: "#111111" }}>
              <svg width="44" height="44" viewBox="0 0 44 44" className="mx-auto -rotate-90">
                <circle cx="22" cy="22" r="18" fill="none" stroke="#1a1a1a" strokeWidth="3" />
                <circle cx="22" cy="22" r="18" fill="none" stroke="#eab308" strokeWidth="3" strokeDasharray="113.1" strokeDashoffset="39.6" strokeLinecap="round" />
              </svg>
              <div className="text-[13px] font-bold mt-1" style={{ color: "#eab308" }}>65</div>
              <div className="text-[8px] font-medium uppercase tracking-wider" style={{ color: "#525252" }}>Security</div>
            </div>
            <div className="rounded p-3 text-center" style={{ border: "1px solid #1a1a1a", background: "#111111" }}>
              <svg width="44" height="44" viewBox="0 0 44 44" className="mx-auto -rotate-90">
                <circle cx="22" cy="22" r="18" fill="none" stroke="#1a1a1a" strokeWidth="3" />
                <circle cx="22" cy="22" r="18" fill="none" stroke="#22c55e" strokeWidth="3" strokeDasharray="113.1" strokeDashoffset="11.3" strokeLinecap="round" />
              </svg>
              <div className="text-[13px] font-bold mt-1" style={{ color: "#22c55e" }}>90</div>
              <div className="text-[8px] font-medium uppercase tracking-wider" style={{ color: "#525252" }}>Trust</div>
            </div>
            <div className="rounded p-3" style={{ border: "1px solid #1a1a1a", background: "#111111" }}>
              <div className="text-[18px] font-bold" style={{ color: "#e5e5e5" }}>12</div>
              <div className="text-[9px] mb-1.5" style={{ color: "#525252" }}>Findings</div>
              <div className="space-y-1">
                <div className="flex items-center gap-1"><div className="h-1 w-1 rounded-full" style={{ background: "#ef4444" }} /><span className="text-[8px]" style={{ color: "#737373" }}>2 Critical</span></div>
                <div className="flex items-center gap-1"><div className="h-1 w-1 rounded-full" style={{ background: "#f97316" }} /><span className="text-[8px]" style={{ color: "#737373" }}>3 High</span></div>
              </div>
            </div>
          </div>
          <div className="space-y-1.5">
            {[
              { sev: "#ef4444", label: "Critical", title: "Remote script execution via curl | sh" },
              { sev: "#f97316", label: "High", title: "Hardcoded AWS secret key in config" },
              { sev: "#eab308", label: "Medium", title: "Unpinned dependency version" },
            ].map((f, i) => (
              <div key={i} className="flex items-center gap-2 rounded px-2.5 py-2" style={{ border: "1px solid #1a1a1a", background: "#111111" }}>
                <span className="text-[7px] font-semibold px-1 py-0.5 shrink-0 uppercase" style={{ background: `${f.sev}15`, color: f.sev, borderRadius: "2px" }}>{f.label}</span>
                <span className="text-[9px] font-medium truncate" style={{ color: "#a3a3a3" }}>{f.title}</span>
                <ChevronRight className="h-2.5 w-2.5 ml-auto shrink-0" style={{ color: "#404040" }} />
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
