"use client";

import { useState } from "react";
import { ChevronDown } from "lucide-react";

export default function FAQ() {
  const [open, setOpen] = useState<number | null>(null);
  const items = [
    { q: "What is MCP?", a: "MCP (Model Context Protocol) is an open standard that lets AI assistants like Claude, ChatGPT, and Cursor connect to external tools and data sources. Think of it as a USB port for AI — it lets your AI agent read files, query databases, search the web, or control apps by talking to \"MCP servers\" through a standardized interface. MCP servers are configured via JSON files that define what tools are available, what commands run, and what resources are accessed." },
    { q: "Why should I care about MCP security?", a: "MCP config files are the real attack surface for AI agents. An attacker can hide shell commands that execute on startup, embed malicious instructions in tool descriptions that hijack your AI's behavior (called \"tool poisoning\"), or hardcode secrets that get exposed. Traditional security tools scan source code — they miss these threats entirely because the danger lives in the configs, not the code." },
    { q: "What threats does MCPeek detect?", a: "MCPeek catches 15+ threat categories including: shell execution (curl | sh, bash -c, eval), tool poisoning (OWASP MCP03) — hidden instructions in tool descriptions, prompt injection and hierarchy manipulation, hardcoded secrets (AWS, OpenAI, Stripe keys), bait-and-switch attacks where content changes after approval, scope creep (MCP02) — overly broad permissions, and supply chain risks from external dependencies." },
    { q: "What MCP servers can MCPeek scan?", a: "MCPeek supports any MCP server configuration — from local stdio servers to remote HTTP-based ones. Paste a GitHub URL, a local file path, or inline config JSON and MCPeek will analyze it. It also scans AI agent skills (like .cursorrules or AGENTS.md files) and npm/PyPI packages." },
    { q: "How is this different from traditional SAST tools?", a: "Traditional SAST tools scan source code. MCPeek scans runtime configurations, install scripts, and trust signals specific to the MCP ecosystem. It catches threats that only manifest when the server actually runs — like a seemingly innocent tool description that secretly instructs the AI to exfiltrate your data." },
    { q: "What is \"bait-and-switch\" detection?", a: "Bait-and-switch is when an attacker serves clean, safe code initially to pass review, then swaps it for malicious code after approval. MCPeek detects this by storing SHA-256 hashes of every external URL's content. On re-scan, it compares current content against original hashes and flags any changes as critical." },
    { q: "Does MCPeek execute any code?", a: "No. MCPeek performs static analysis and pattern matching only. It never executes, installs, or runs any of the code it scans. Your environment stays safe." },
    { q: "What is the AI analysis feature?", a: "MCPeek can optionally use free AI models (via OpenRouter, no credit card needed) to generate context-specific attack scenarios, plain-English risk narratives, and remediation suggestions based on your actual scan findings. This is entirely optional — the core scanner works without AI." },
    { q: "Is MCPeek free?", a: "Yes. MCPeek is free and open source. No account required. The AI analysis feature uses free OpenRouter models." },
    { q: "What formats can I export reports in?", a: "Reports are available in JSON, Markdown, and plain text formats. JSON includes full structured data for CI/CD integration." },
    { q: "Can I use MCPeek in CI/CD?", a: "Yes. MCPeek has a CLI with a --fail-on flag that exits with code 2 when findings exceed a threshold, plus a GitHub Action for blocking unsafe configs in pull requests. Add it to your pipeline to catch MCP security issues before they reach production." },
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
