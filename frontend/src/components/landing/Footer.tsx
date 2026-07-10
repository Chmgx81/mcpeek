"use client";

import Logo from "@/components/Logo";
import { Github, ExternalLink } from "lucide-react";

const links = {
  product: [
    { label: "Dashboard", href: "/dashboard" },
    { label: "Blog", href: "/blog/introducing-mcpeek" },
    { label: "Live Demo", href: "https://frontend-lake-eight-70.vercel.app", external: true },
  ],
  developers: [
    { label: "GitHub", href: "https://github.com/Chmgx81/mcpeek", external: true },
    { label: "GitHub Action", href: "https://github.com/Chmgx81/mcpeek/tree/main/.github/workflows", external: true },
    { label: "API Docs", href: "https://mcpeek-api-production.up.railway.app/docs", external: true },
  ],
  community: [
    { label: "Hackathon Demo", href: "https://youtu.be/mQXrpGpstA8", external: true },
    { label: "HACKHAZARDS '26", href: "https://hackhazards.devpost.com", external: true },
    { label: "Report Issue", href: "https://github.com/Chmgx81/mcpeek/issues", external: true },
  ],
};

function FooterLink({ label, href, external }: { label: string; href: string; external?: boolean }) {
  return (
    <a
      href={href}
      target={external ? "_blank" : undefined}
      rel={external ? "noopener noreferrer" : undefined}
      className="inline-flex items-center gap-1 text-[12px] transition-colors"
      style={{ color: "#525252" }}
      onMouseEnter={(e) => (e.currentTarget.style.color = "#e5e5e5")}
      onMouseLeave={(e) => (e.currentTarget.style.color = "#525252")}
    >
      {label}
      {external && <ExternalLink className="h-2.5 w-2.5 opacity-40" />}
    </a>
  );
}

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

        <div className="grid grid-cols-3 gap-8 mb-12 max-w-2xl mx-auto">
          <div>
            <p className="text-[10px] font-medium uppercase tracking-widest mb-3" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>Product</p>
            <div className="space-y-2">
              {links.product.map((l) => (
                <FooterLink key={l.label} {...l} />
              ))}
            </div>
          </div>
          <div>
            <p className="text-[10px] font-medium uppercase tracking-widest mb-3" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>Developers</p>
            <div className="space-y-2">
              {links.developers.map((l) => (
                <FooterLink key={l.label} {...l} />
              ))}
            </div>
          </div>
          <div>
            <p className="text-[10px] font-medium uppercase tracking-widest mb-3" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>Community</p>
            <div className="space-y-2">
              {links.community.map((l) => (
                <FooterLink key={l.label} {...l} />
              ))}
            </div>
          </div>
        </div>

        <div className="flex flex-col md:flex-row items-center justify-between gap-4 pt-6" style={{ borderTop: "1px solid #1a1a1a" }}>
          <p className="text-[11px]" style={{ color: "#404040" }}>&copy; 2026 MCPeek. Open source under MIT License.</p>
          <div className="flex items-center gap-4">
            <a
              href="https://github.com/Chmgx81/mcpeek"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 text-[11px] transition-colors"
              style={{ color: "#404040" }}
              onMouseEnter={(e) => (e.currentTarget.style.color = "#737373")}
              onMouseLeave={(e) => (e.currentTarget.style.color = "#404040")}
            >
              <Github className="h-3 w-3" />
              Source
            </a>
            <a
              href="https://frontend-lake-eight-70.vercel.app/dashboard"
              className="text-[11px] transition-colors"
              style={{ color: "#404040" }}
              onMouseEnter={(e) => (e.currentTarget.style.color = "#737373")}
              onMouseLeave={(e) => (e.currentTarget.style.color = "#404040")}
            >
              Try MCPeek
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
