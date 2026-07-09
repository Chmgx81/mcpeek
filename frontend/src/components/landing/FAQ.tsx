"use client";

import { useState } from "react";
import { ChevronDown } from "lucide-react";

export default function FAQ() {
  const [open, setOpen] = useState<number | null>(null);
  const items = [
    { q: "What MCP servers can MCPeek scan?", a: "MCPeek supports any MCP server configuration — from local stdio servers to remote HTTP-based ones. Paste a GitHub URL, a local file path, or inline config JSON and MCPeek will analyze it." },
    { q: "How is this different from traditional SAST tools?", a: "Traditional SAST tools scan source code. MCPeek scans runtime configurations, install scripts, and trust signals specific to the MCP ecosystem. It catches threats that only manifest when the server actually runs." },
    { q: "Does MCPeek execute any code?", a: "No. MCPeek performs static analysis and pattern matching only. It never executes, installs, or runs any of the code it scans. Your environment stays safe." },
    { q: "Is MCPeek free?", a: "Yes. MCPeek is free and open source. No account required." },
    { q: "What formats can I export reports in?", a: "Reports are available in JSON, Markdown, and plain text formats. JSON includes full structured data for CI/CD integration." },
  ];

  return (
    <section id="faq" className="px-5 py-20">
      <div className="mx-auto max-w-[700px]">
        <div className="mb-12 text-center">
          <p className="text-[11px] font-medium uppercase tracking-widest mb-3" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>FAQ</p>
          <h2 className="text-2xl md:text-3xl font-bold" style={{ color: "#fafafa", letterSpacing: "-0.03em" }}>
            Common questions
          </h2>
        </div>
        <div className="space-y-1">
          {items.map((item, i) => (
            <div key={i} style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}>
              <button
                onClick={() => setOpen(open === i ? null : i)}
                className="flex w-full items-center justify-between gap-3 p-4 text-left"
              >
                <span className="text-[13px] font-medium" style={{ color: "#e5e5e5" }}>{item.q}</span>
                <ChevronDown
                  className="h-4 w-4 shrink-0 transition-transform"
                  style={{ color: "#525252", transform: open === i ? "rotate(180deg)" : "rotate(0)" }}
                />
              </button>
              {open === i && (
                <div className="px-4 pb-4" style={{ borderTop: "1px solid #1a1a1a" }}>
                  <p className="text-[13px] pt-3" style={{ color: "#737373", lineHeight: 1.6 }}>{item.a}</p>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
