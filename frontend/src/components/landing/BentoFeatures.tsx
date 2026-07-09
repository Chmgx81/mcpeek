"use client";

import { ArrowRight, FileSearch, Globe, Lock, ShieldCheck, Fingerprint, AlertOctagon } from "lucide-react";

export default function BentoFeatures() {
  const features = [
    {
      title: "Static Analysis",
      desc: "Detect shell execution, prompt injection, hardcoded secrets, and dangerous permissions in any config file.",
      icon: FileSearch,
      accent: "#22c55e",
    },
    {
      title: "Runtime Risks",
      desc: "Identify malicious install scripts, remote code execution, and data exfiltration before they run.",
      icon: Globe,
      accent: "#3b82f6",
    },
    {
      title: "SKILLCLOAK Defense",
      desc: "Detects self-extracting skills (SFS) that hide payloads in hidden directories and unpack at runtime. Catches entropy, decoder patterns, and manifest abuse.",
      icon: Fingerprint,
      accent: "#f97316",
    },
    {
      title: "Trust Scoring",
      desc: "Heuristic risk scoring based on dependency analysis, domain reputation, and supply chain signals.",
      icon: Lock,
      accent: "#a855f7",
    },
    {
      title: "AI Attack Analysis",
      desc: "Optional AI-powered dynamic attack scenarios, threat intelligence mapping, and actionable remediation suggestions via OpenRouter.",
      icon: ShieldCheck,
      accent: "#ef4444",
    },
    {
      title: "Bait-and-Switch Detection",
      desc: "SHA-256 content hashing detects when an attacker swaps a clean config for a malicious one after approval.",
      icon: AlertOctagon,
      accent: "#eab308",
    },
  ];

  return (
    <section id="features" className="px-5 py-20">
      <div className="mx-auto max-w-[1100px]">
        <div className="mb-12">
          <p className="text-[11px] font-medium uppercase tracking-widest mb-3" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>Capabilities</p>
          <h2 className="text-2xl md:text-3xl font-bold" style={{ color: "#fafafa", letterSpacing: "-0.03em" }}>
            Everything you need to audit AI toolchains
          </h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 auto-rows-[180px]">
          {features.map((f) => (
            <div
              key={f.title}
              className="group p-5 flex flex-col justify-between transition-all hover:border-[#262626]"
              style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}
            >
              <div>
                <div className="w-10 h-10 rounded flex items-center justify-center mb-3" style={{ background: `${f.accent}20` }}>
                  <f.icon className="h-5 w-5" style={{ color: f.accent }} />
                </div>
                <h3 className="text-[15px] font-semibold mb-1.5" style={{ color: "#e5e5e5" }}>{f.title}</h3>
                <p className="text-[13px]" style={{ color: "#737373", lineHeight: 1.5 }}>{f.desc}</p>
              </div>
              <div className="flex items-center gap-1 text-[11px] font-medium opacity-0 group-hover:opacity-100 transition-opacity" style={{ color: f.accent }}>
                Learn more <ArrowRight className="h-3 w-3" />
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
