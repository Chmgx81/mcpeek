"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import {
  ArrowRight, FileSearch, Globe, Lock, Terminal, Eye, ChevronDown,
  ShieldCheck, Zap, Users, FileWarning, Check, X as XIcon, ChevronRight,
} from "lucide-react";
import Logo from "@/components/Logo";
import CookieBanner from "@/components/CookieBanner";
import { useScreenSize } from "@/hooks/use-screen-size";
import { PixelTrail } from "@/components/ui/pixel-trail";
import { GooeyFilter } from "@/components/ui/gooey-filter";

/* ─── Animated counter ─── */
function useCountUp(target: number, duration = 2000) {
  const [count, setCount] = useState(0);
  const ref = useRef<HTMLDivElement>(null);
  const started = useRef(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    const startAnimation = () => {
      if (started.current) return;
      started.current = true;
      const start = performance.now();
      const tick = (now: number) => {
        const p = Math.min((now - start) / duration, 1);
        setCount(Math.floor(p * target));
        if (p < 1) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    };

    const obs = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          startAnimation();
        }
      },
      { threshold: 0.1, rootMargin: "100px" }
    );
    obs.observe(el);

    // Also start if already in viewport
    const rect = el.getBoundingClientRect();
    if (rect.top < window.innerHeight && rect.bottom > 0) {
      startAnimation();
    }

    return () => obs.disconnect();
  }, [target, duration]);

  return { count, ref };
}

/* ─── Floating Pill Navbar ─── */
function PillNav() {
  const router = useRouter();
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <div className="fixed top-4 inset-x-0 z-50 flex justify-center px-4">
      <nav
        className="flex items-center justify-between gap-6 px-4 py-2 w-full max-w-2xl transition-all duration-300"
        style={{
          background: scrolled ? "rgba(17,17,17,0.95)" : "rgba(17,17,17,0.8)",
          backdropFilter: "blur(16px)",
          border: "1px solid #1a1a1a",
          borderRadius: "9999px",
          boxShadow: scrolled
            ? "0 8px 32px rgba(0,0,0,0.4), 0 0 0 1px rgba(34,197,94,0.05)"
            : "0 4px 16px rgba(0,0,0,0.2)",
        }}
      >
        <button onClick={() => router.push("/")} className="flex items-center gap-2 shrink-0">
          <Logo size={16} />
          <span className="text-[13px] font-semibold" style={{ color: "#e5e5e5" }}>MCPeek</span>
        </button>
        <div className="hidden sm:flex items-center gap-1">
          {["Features", "How it works", "FAQ"].map((item) => (
            <button
              key={item}
              onClick={() => {
                const id = item.toLowerCase().replace(/\s+/g, "-");
                document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
              }}
              className="px-3 py-1 text-[12px] font-medium transition-colors rounded-full"
              style={{ color: "#737373" }}
              onMouseEnter={(e) => (e.currentTarget.style.color = "#e5e5e5")}
              onMouseLeave={(e) => (e.currentTarget.style.color = "#737373")}
            >
              {item}
            </button>
          ))}
        </div>
        <button
          onClick={() => router.push("/dashboard")}
          className="px-4 py-1.5 text-[12px] font-medium transition-all hover:brightness-110 shrink-0"
          style={{ background: "#22c55e", color: "#000", borderRadius: "9999px" }}
        >
          Get started
        </button>
      </nav>
    </div>
  );
}

/* ─── Hero Mockup (CSS-rendered dashboard) ─── */
function HeroMockup() {
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

/* ─── Stats bar ─── */
function StatsBar() {
  const s1 = useCountUp(15, 1200);
  const s2 = useCountUp(5, 1200);
  const s3 = useCountUp(3, 1200);
  const s4 = useCountUp(4, 1200);

  const stats = [
    { ref: s1.ref, value: s1.count, suffix: "+", label: "Threat categories", color: "#22c55e" },
    { ref: s2.ref, value: s2.count, suffix: "", label: "Demo fixtures", color: "#eab308" },
    { ref: s3.ref, value: s3.count, suffix: "", label: "Export formats", color: "#3b82f6" },
    { ref: s4.ref, value: s4.count, suffix: "", label: "Scan stages", color: "#a855f7" },
  ];

  return (
    <section className="px-5 py-16" style={{ background: "#0f0f0f" }}>
      <div className="mx-auto max-w-[900px] grid grid-cols-2 md:grid-cols-4 gap-8">
        {stats.map((s) => (
          <div key={s.label} ref={s.ref} className="text-center">
            <div className="text-3xl md:text-4xl font-bold tabular-nums" style={{ color: s.color }}>
              {s.value.toLocaleString()}{s.suffix}
            </div>
            <div className="text-[12px] mt-1" style={{ color: "#525252" }}>{s.label}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

/* ─── Bento Features ─── */
function BentoFeatures() {
  const features = [
    {
      title: "Static Analysis",
      desc: "Detect shell execution, prompt injection, hardcoded secrets, and dangerous permissions in any config file.",
      icon: FileSearch,
      span: "col-span-1 md:col-span-2 row-span-1",
      accent: "#22c55e",
    },
    {
      title: "Runtime Risks",
      desc: "Identify malicious install scripts, remote code execution, and data exfiltration before they run.",
      icon: Globe,
      span: "col-span-1 row-span-1",
      accent: "#3b82f6",
    },
    {
      title: "Trust Scoring",
      desc: "Heuristic risk scoring based on dependency analysis, domain reputation, and supply chain signals.",
      icon: Lock,
      span: "col-span-1 row-span-1",
      accent: "#a855f7",
    },
    {
      title: "AI Attack Analysis",
      desc: "Optional AI-powered dynamic attack scenarios, threat intelligence mapping, and actionable remediation suggestions via OpenRouter.",
      icon: ShieldCheck,
      span: "col-span-1 md:col-span-2 row-span-1",
      accent: "#ef4444",
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
              className={`group p-5 flex flex-col justify-between transition-all hover:border-[#262626] ${f.span}`}
              style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}
            >
              <div>
                <div className="w-8 h-8 rounded flex items-center justify-center mb-3" style={{ background: `${f.accent}12` }}>
                  <f.icon className="h-4 w-4" style={{ color: f.accent }} />
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

/* ─── How it works ─── */
function HowItWorks() {
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

/* ─── Demo Evidence ─── */
function DemoEvidence() {
  const samples = [
    {
      name: "Safe MCP control",
      file: "examples/safe-mcp.json",
      result: "SAFE",
      detail: "0 findings, score 100",
      color: "#22c55e",
    },
    {
      name: "Curl-to-shell MCP",
      file: "examples/vulnerable-mcp-curl-shell.json",
      result: "CRITICAL",
      detail: "14 findings, CI exits 2",
      color: "#ef4444",
    },
    {
      name: "Malicious agent skill",
      file: "examples/vulnerable-agent-skill.md",
      result: "CRITICAL",
      detail: "15 findings, CI exits 2",
      color: "#ef4444",
    },
  ];

  return (
    <section className="px-5 py-20">
      <div className="mx-auto max-w-[1100px]">
        <div className="mb-12 text-center">
          <p className="text-[11px] font-medium uppercase tracking-widest mb-3" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>Demo Evidence</p>
          <h2 className="text-2xl md:text-3xl font-bold" style={{ color: "#fafafa", letterSpacing: "-0.03em" }}>
            Verified against included fixtures
          </h2>
          <p className="text-[13px] mt-2 max-w-xl mx-auto" style={{ color: "#737373", lineHeight: 1.6 }}>
            MCPeek ships with safe and intentionally vulnerable samples so judges can reproduce the results locally.
          </p>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {samples.map((sample) => (
            <div
              key={sample.file}
              className="p-5 flex flex-col justify-between"
              style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}
            >
              <div>
                <div className="text-[10px] font-semibold uppercase tracking-widest mb-2" style={{ color: sample.color }}>{sample.result}</div>
                <h3 className="text-[15px] font-semibold mb-1" style={{ color: "#e5e5e5" }}>{sample.name}</h3>
                <p className="text-[12px] font-mono break-all" style={{ color: "#737373" }}>{sample.file}</p>
              </div>
              <div className="mt-5 text-[12px]" style={{ color: "#a3a3a3" }}>
                {sample.detail}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ─── Comparison Table ─── */
function ComparisonTable() {
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

/* ─── FAQ ─── */
function FAQ() {
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

/* ─── CTA Banner ─── */
function CTABanner() {
  const router = useRouter();
  return (
    <section className="px-5 py-20">
      <div
        className="mx-auto max-w-3xl text-center p-10 relative overflow-hidden"
        style={{
          background: "#111111",
          border: "1px solid #1a1a1a",
          borderRadius: "8px",
        }}
      >
        <div
          className="absolute inset-0 pointer-events-none opacity-[0.04]"
          style={{
            backgroundImage: "radial-gradient(circle, #22c55e 1px, transparent 1px)",
            backgroundSize: "16px 16px",
          }}
        />
        <div className="relative z-10">
          <h2 className="text-2xl md:text-3xl font-bold mb-3" style={{ color: "#fafafa", letterSpacing: "-0.03em" }}>
            Don&apos;t ship blind.
          </h2>
          <p className="text-[14px] mb-6" style={{ color: "#737373" }}>
            Your MCP server might be running untrusted code right now.<br />
            Find out in 30 seconds.
          </p>
          <button
            onClick={() => router.push("/dashboard")}
            className="inline-flex items-center gap-1.5 px-6 py-2.5 text-[14px] font-medium transition-all hover:brightness-110"
            style={{ background: "#22c55e", color: "#000", borderRadius: "4px" }}
          >
            Start scanning <ArrowRight className="h-3.5 w-3.5" />
          </button>
          <p className="mt-3 text-[11px]" style={{ color: "#404040" }}>No account required. Free to use.</p>
        </div>
      </div>
    </section>
  );
}

/* ─── Footer ─── */
function Footer() {
  return (
    <footer className="px-5 pt-16 pb-8" style={{ borderTop: "1px solid #1a1a1a" }}>
      <div className="mx-auto max-w-[1100px]">
        <div className="text-center mb-12">
          <div className="inline-flex items-center gap-3 mb-4">
            <Logo size={32} />
            <span className="text-4xl font-bold tracking-tight" style={{ color: "#fafafa", letterSpacing: "-0.04em" }}>MCPeek</span>
          </div>
          <p className="text-[13px] max-w-md mx-auto" style={{ color: "#525252", lineHeight: 1.6 }}>
            Runtime-aware security scanning for MCP servers, AI agent skills, and toolchains. No account required.
          </p>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mb-12">
          <div>
            <p className="text-[10px] font-medium uppercase tracking-widest mb-3" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>Product</p>
            <div className="space-y-2">
              {[
                { label: "Dashboard", href: "/dashboard" },
                { label: "History", href: "/history" },
                { label: "Contact", href: "/contact" },
              ].map((l) => (
                <a key={l.label} href={l.href} className="block text-[12px] transition-colors" style={{ color: "#525252" }}
                  onMouseEnter={(e) => (e.currentTarget.style.color = "#e5e5e5")}
                  onMouseLeave={(e) => (e.currentTarget.style.color = "#525252")}
                >{l.label}</a>
              ))}
            </div>
          </div>
          <div>
            <p className="text-[10px] font-medium uppercase tracking-widest mb-3" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>Resources</p>
            <div className="space-y-2">
              {[
                { label: "Documentation", href: "/blog/introducing-mcpeek" },
                { label: "Demo Guide", href: "/blog/introducing-mcpeek" },
                { label: "GitHub Action", href: "/dashboard" },
              ].map((l) => (
                <a key={l.label} href={l.href} className="block text-[12px] transition-colors" style={{ color: "#525252" }}
                  onMouseEnter={(e) => (e.currentTarget.style.color = "#e5e5e5")}
                  onMouseLeave={(e) => (e.currentTarget.style.color = "#525252")}
                >{l.label}</a>
              ))}
            </div>
          </div>
          <div>
            <p className="text-[10px] font-medium uppercase tracking-widest mb-3" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>Community</p>
            <div className="space-y-2">
              {[
                { label: "Hackathon Demo", href: "/blog/introducing-mcpeek" },
                { label: "Examples", href: "/dashboard" },
                { label: "Contributing", href: "/contact" },
              ].map((l) => (
                <a key={l.label} href={l.href} className="block text-[12px] transition-colors" style={{ color: "#525252" }}
                  onMouseEnter={(e) => (e.currentTarget.style.color = "#e5e5e5")}
                  onMouseLeave={(e) => (e.currentTarget.style.color = "#525252")}
                >{l.label}</a>
              ))}
            </div>
          </div>
          <div>
            <p className="text-[10px] font-medium uppercase tracking-widest mb-3" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>Legal</p>
            <div className="space-y-2">
              {[
                { label: "Privacy", href: "/contact" },
                { label: "Terms", href: "/contact" },
                { label: "License", href: "/blog/introducing-mcpeek" },
              ].map((l) => (
                <a key={l.label} href={l.href} className="block text-[12px] transition-colors" style={{ color: "#525252" }}
                  onMouseEnter={(e) => (e.currentTarget.style.color = "#e5e5e5")}
                  onMouseLeave={(e) => (e.currentTarget.style.color = "#525252")}
                >{l.label}</a>
              ))}
            </div>
          </div>
        </div>
        <div className="flex flex-col md:flex-row items-center justify-between gap-4 pt-6" style={{ borderTop: "1px solid #1a1a1a" }}>
          <p className="text-[11px]" style={{ color: "#404040" }}>&copy; 2026 MCPeek. Open source under MIT License.</p>
          <div className="flex items-center gap-4">
            {[
              { label: "Demo", href: "/dashboard" },
              { label: "Blog", href: "/blog/introducing-mcpeek" },
              { label: "Contact", href: "/contact" },
            ].map((s) => (
              <a key={s.label} href={s.href} className="text-[11px] transition-colors" style={{ color: "#404040" }}
                onMouseEnter={(e) => (e.currentTarget.style.color = "#737373")}
                onMouseLeave={(e) => (e.currentTarget.style.color = "#404040")}
              >{s.label}</a>
            ))}
          </div>
        </div>
      </div>
    </footer>
  );
}

/* ─── Main Landing Page ─── */
export default function LandingPage() {
  const router = useRouter();
  const screenSize = useScreenSize();

  return (
    <div className="min-h-screen" style={{ background: "#0a0a0a" }}>
      <PillNav />

      {/* Hero */}
      <section className="relative flex flex-col items-center px-5 pt-28 pb-0 overflow-hidden">
        {/* Pixel trail background */}
        <GooeyFilter id="hero-gooey" strength={5} />
        <div
          className="absolute inset-0 z-0"
          style={{ filter: "url(#hero-gooey)" }}
        >
          <PixelTrail
            pixelSize={screenSize.lessThan("md") ? 20 : 32}
            fadeDuration={800}
            delay={0}
            pixelClassName="bg-[#22c55e]"
          />
        </div>

        <div
          className="absolute inset-0 pointer-events-none opacity-[0.03]"
          style={{
            backgroundImage: "linear-gradient(#333 1px, transparent 1px), linear-gradient(90deg, #333 1px, transparent 1px)",
            backgroundSize: "48px 48px",
          }}
        />
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-[400px] pointer-events-none" style={{ background: "radial-gradient(ellipse, rgba(34,197,94,0.08) 0%, transparent 70%)" }} />

        <div className="relative z-10 max-w-2xl text-center mb-10">
          <div className="inline-flex items-center gap-1.5 px-3 py-1 mb-6 text-[11px] font-medium uppercase tracking-widest rounded" style={{ background: "rgba(34,197,94,0.08)", color: "#22c55e", border: "1px solid rgba(34,197,94,0.15)" }}>
            <ShieldCheck className="h-3 w-3" />
            Security Scanner
          </div>
          <h1
            className="text-4xl md:text-6xl font-bold tracking-tight"
            style={{ color: "#fafafa", letterSpacing: "-0.04em", lineHeight: 1.05 }}
          >
            Peek beyond
            <br />
            the manifest.
          </h1>
          <p className="mt-5 text-[15px] max-w-lg mx-auto" style={{ color: "#737373", lineHeight: 1.6 }}>
            Runtime-aware security scanning for MCP servers, AI agent skills, and toolchains.
            Detect threats static scanners miss.
          </p>
          <div className="mt-7 flex items-center justify-center gap-3">
            <button
              onClick={() => router.push("/dashboard")}
              className="inline-flex items-center gap-1.5 px-6 py-2.5 text-[14px] font-medium transition-all hover:brightness-110"
              style={{ background: "#22c55e", color: "#000", borderRadius: "4px" }}
            >
              Get started <ArrowRight className="h-3.5 w-3.5" />
            </button>
            <a
              href="#features"
              className="inline-flex items-center gap-1.5 px-6 py-2.5 text-[14px] font-medium transition-colors"
              style={{ color: "#737373", border: "1px solid #262626", borderRadius: "4px" }}
              onMouseEnter={(e) => { e.currentTarget.style.borderColor = "#404040"; e.currentTarget.style.color = "#e5e5e5"; }}
              onMouseLeave={(e) => { e.currentTarget.style.borderColor = "#262626"; e.currentTarget.style.color = "#737373"; }}
            >
              See features
            </a>
          </div>
        </div>

        <div className="relative z-10 w-full max-w-5xl px-2">
          <HeroMockup />
        </div>
        <div className="h-20 w-full" style={{ background: "linear-gradient(to bottom, transparent, #0a0a0a)" }} />
      </section>

      <StatsBar />
      <BentoFeatures />
      <HowItWorks />
      <DemoEvidence />
      <ComparisonTable />
      <FAQ />
      <CTABanner />
      <Footer />
      <CookieBanner />
    </div>
  );
}
