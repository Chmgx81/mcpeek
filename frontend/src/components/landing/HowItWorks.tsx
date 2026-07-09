"use client";

import { Terminal, Eye, ShieldCheck } from "lucide-react";

export default function HowItWorks() {
  return (
    <section id="how-it-works" className="px-5 py-20" style={{ background: "#0f0f0f" }}>
      <div className="mx-auto max-w-[1100px]">
        <div className="mb-12">
          <p className="text-[11px] font-medium uppercase tracking-widest mb-3" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>How it works</p>
          <h2 className="text-2xl md:text-3xl font-bold" style={{ color: "#fafafa", letterSpacing: "-0.03em" }}>Three steps to visibility</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 relative">
          <div className="hidden md:block absolute top-8 left-[16.7%] right-[16.7%] h-px" style={{ background: "#262626" }} />
          {[
            { step: "01", title: "Submit a target", desc: "Paste a URL, config file, or package name. Supports MCP servers, agent skills, npm, and PyPI.", icon: Terminal },
            { step: "02", title: "Automated scan", desc: "Static analysis, runtime content inspection, trust signal scoring, and attack simulation.", icon: Eye },
            { step: "03", title: "Get your report", desc: "Risk score, trust score, detailed findings, attack scenarios, and actionable recommendations.", icon: ShieldCheck },
          ].map((item) => (
            <div key={item.step} className="flex flex-col items-center text-center relative">
              <div className="w-16 h-16 rounded-lg flex items-center justify-center mb-4 relative z-10" style={{ background: "#111111", border: "1px solid #262626" }}>
                <item.icon className="h-6 w-6" style={{ color: "#22c55e" }} />
              </div>
              <div className="text-[10px] font-semibold uppercase tracking-widest mb-1.5" style={{ color: "#525252" }}>Step {item.step}</div>
              <h3 className="text-[15px] font-semibold mb-2" style={{ color: "#e5e5e5" }}>{item.title}</h3>
              <p className="text-[13px] max-w-xs" style={{ color: "#737373", lineHeight: 1.5 }}>{item.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
