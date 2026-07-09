"use client";

export default function DemoEvidence() {
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
