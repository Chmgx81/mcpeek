import BlogLayout from "@/components/BlogLayout";

export const metadata = {
  title: "Introducing MCPeek — Runtime-Aware Security for MCP Servers",
  description: "Why we built MCPeek and how it catches threats that static scanners miss.",
};

export default function IntroducingMCPeek() {
  return (
    <BlogLayout
      title="Introducing MCPeek — Runtime-Aware Security for MCP Servers"
      date="July 2026"
    >
      <section id="why">
        <h2 className="text-xl font-bold mt-8 mb-3" style={{ color: "#fafafa", letterSpacing: "-0.02em" }}>Why MCPeek</h2>
        <p className="text-[14px]" style={{ color: "#a3a3a3", lineHeight: 1.7 }}>
          MCP servers are becoming the backbone of AI agent toolchains. They connect language models to
          external tools, databases, and APIs. But most security scanners only look at source code —
          they miss the threats that appear in runtime configurations, install scripts, and trust signals.
        </p>
        <p className="text-[14px] mt-3" style={{ color: "#a3a3a3", lineHeight: 1.7 }}>
          A malicious MCP skill could host a harmless <code style={{ color: "#22c55e" }}>SKILL.md</code> on GitHub
          while serving a payload from a mutable external URL. Traditional SAST tools would never catch this.
          MCPeek does.
        </p>
      </section>

      <section id="how-it-works">
        <h2 className="text-xl font-bold mt-8 mb-3" style={{ color: "#fafafa", letterSpacing: "-0.02em" }}>How it works</h2>
        <p className="text-[14px]" style={{ color: "#a3a3a3", lineHeight: 1.7 }}>
          MCPeek runs a four-stage pipeline on every scan target:
        </p>
        <ol className="list-decimal list-inside space-y-2 mt-3 text-[14px]" style={{ color: "#a3a3a3", lineHeight: 1.7 }}>
          <li><strong style={{ color: "#e5e5e5" }}>Static analysis</strong> — scans config files for shell execution, prompt injection, hardcoded secrets, and dangerous permissions.</li>
          <li><strong style={{ color: "#e5e5e5" }}>Runtime content inspection</strong> — fetches external URLs and analyzes the actual content served, looking for RCE, exfiltration, and C2 patterns.</li>
          <li><strong style={{ color: "#e5e5e5" }}>Trust signal scoring</strong> — evaluates repository metadata, domain reputation, and supply chain integrity.</li>
          <li><strong style={{ color: "#e5e5e5" }}>Attack simulation</strong> — generates realistic attack scenarios for each finding and produces an executive summary.</li>
        </ol>
      </section>

      <section id="detection">
        <h2 className="text-xl font-bold mt-8 mb-3" style={{ color: "#fafafa", letterSpacing: "-0.02em" }}>What we detect</h2>
        <p className="text-[14px]" style={{ color: "#a3a3a3", lineHeight: 1.7 }}>
          MCPeek currently detects 15+ threat categories across static and runtime analysis:
        </p>
        <ul className="list-disc list-inside space-y-1 mt-3 text-[14px]" style={{ color: "#a3a3a3", lineHeight: 1.7 }}>
          <li>Shell execution (<code style={{ color: "#22c55e" }}>curl | sh</code>, <code style={{ color: "#22c55e" }}>bash -c</code>, <code style={{ color: "#22c55e" }}>eval</code>)</li>
          <li>Prompt injection in skill definitions</li>
          <li>Hardcoded AWS, OpenAI, Stripe, and GitHub tokens</li>
          <li>Remote code execution vectors</li>
          <li>Data exfiltration patterns</li>
          <li>Command-and-control communication</li>
          <li>Supply chain signals (typosquatting, mutable URLs)</li>
        </ul>
      </section>

      <section id="getting-started">
        <h2 className="text-xl font-bold mt-8 mb-3" style={{ color: "#fafafa", letterSpacing: "-0.02em" }}>Getting started</h2>
        <p className="text-[14px]" style={{ color: "#a3a3a3", lineHeight: 1.7 }}>
          MCPeek is free and open source. Clone the repo, start the backend and frontend, and scan
          your first target in under a minute:
        </p>
        <pre className="mt-3 p-4 text-[12px] font-mono overflow-x-auto" style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px", color: "#a3a3a3" }}>
{`git clone https://github.com/yourname/mcpeek.git
cd mcpeek/backend && pip install -e ".[dev]"
uvicorn app.main:app --reload --port 8000

# New terminal
cd mcpeek/frontend && npm install && npm run dev`}
        </pre>
      </section>

      <section id="whats-next">
        <h2 className="text-xl font-bold mt-8 mb-3" style={{ color: "#fafafa", letterSpacing: "-0.02em" }}>What&apos;s next</h2>
        <p className="text-[14px]" style={{ color: "#a3a3a3", lineHeight: 1.7 }}>
          We&apos;re building toward continuous monitoring — scheduled scans, webhook alerts, and CI/CD
          integration so you catch new threats as soon as they appear in your dependencies.
        </p>
        <p className="text-[14px] mt-3" style={{ color: "#a3a3a3", lineHeight: 1.7 }}>
          Follow along on GitHub or reach out at{" "}
          <a href="/contact" style={{ color: "#22c55e" }}>our contact page</a>.
        </p>
      </section>
    </BlogLayout>
  );
}
