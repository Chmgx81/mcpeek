"use client";

import { Check, X as XIcon } from "lucide-react";

export default function ComparisonTable() {
  const features = [
    { name: "MCP Server scanning", mcpeek: true, generic: false, traditional: false },
    { name: "Agent skill analysis", mcpeek: true, generic: false, traditional: false },
    { name: "Runtime content inspection", mcpeek: true, generic: false, traditional: true },
    { name: "Trust score calculation", mcpeek: true, generic: false, traditional: false },
    { name: "AI attack analysis (optional)", mcpeek: true, generic: false, traditional: false },
    { name: "Prompt injection detection", mcpeek: true, generic: true, traditional: false },
    { name: "Tool poisoning detection (MCP03)", mcpeek: true, generic: false, traditional: false },
    { name: "Scope creep detection (MCP02)", mcpeek: true, generic: false, traditional: false },
    { name: "Intent subversion detection (MCP06)", mcpeek: true, generic: false, traditional: false },
    { name: "SKILLCLOAK / SFS detection", mcpeek: true, generic: false, traditional: false },
    { name: "Supply chain analysis", mcpeek: true, generic: true, traditional: true },
    { name: "Open source / free", mcpeek: true, generic: true, traditional: false },
  ];

  return (
    <section className="px-5 py-20" style={{ background: "#0f0f0f" }}>
      <div className="mx-auto max-w-[800px]">
        <div className="mb-12 text-center">
          <p className="text-[11px] font-medium uppercase tracking-widest mb-3" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>Comparison</p>
          <h2 className="text-2xl md:text-3xl font-bold" style={{ color: "#fafafa", letterSpacing: "-0.03em" }}>
            Why MCPeek
          </h2>
        </div>
        <div className="overflow-x-auto" style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}>
          <div className="min-w-[620px]">
            <div className="grid grid-cols-4 text-[11px] font-medium uppercase tracking-wider" style={{ borderBottom: "1px solid #1a1a1a" }}>
              <div className="px-4 py-3" style={{ color: "#525252" }}>Feature</div>
              <div className="px-4 py-3 text-center" style={{ color: "#22c55e" }}>MCPeek</div>
              <div className="px-4 py-3 text-center" style={{ color: "#737373" }}>Generic Scanner</div>
              <div className="px-4 py-3 text-center" style={{ color: "#737373" }}>Traditional SAST</div>
            </div>
            {features.map((f, i) => (
              <div
                key={f.name}
                className="grid grid-cols-4 text-[12px] items-center"
                style={{ borderBottom: i < features.length - 1 ? "1px solid #1a1a1a" : "none" }}
              >
                <div className="px-4 py-2.5" style={{ color: "#a3a3a3" }}>{f.name}</div>
                <div className="px-4 py-2.5 flex justify-center">
                  {f.mcpeek ? <Check className="h-3.5 w-3.5" style={{ color: "#22c55e" }} /> : <XIcon className="h-3.5 w-3.5" style={{ color: "#333" }} />}
                </div>
                <div className="px-4 py-2.5 flex justify-center">
                  {f.generic ? <Check className="h-3.5 w-3.5" style={{ color: "#525252" }} /> : <XIcon className="h-3.5 w-3.5" style={{ color: "#333" }} />}
                </div>
                <div className="px-4 py-2.5 flex justify-center">
                  {f.traditional ? <Check className="h-3.5 w-3.5" style={{ color: "#525252" }} /> : <XIcon className="h-3.5 w-3.5" style={{ color: "#333" }} />}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
