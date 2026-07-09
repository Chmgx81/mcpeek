"use client";

import Logo from "@/components/Logo";

export default function Footer() {
  return (
    <footer className="px-5 pt-16 pb-8" style={{ borderTop: "1px solid #1a1a1a" }}>
      <div className="mx-auto max-w-[1100px]">
        <div className="text-center mb-12">
          <div className="inline-flex items-center gap-3 mb-4">
            <Logo size={40} />
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
