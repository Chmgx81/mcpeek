"use client";

import { useState } from "react";
import { ChevronDown, ChevronUp, ExternalLink } from "lucide-react";
import SeverityBadge from "./SeverityBadge";
import type { Finding } from "@/lib/types";

const CAT_LABELS: Record<string, string> = {
  shell_execution: "Shell Execution",
  hardcoded_secret: "Hardcoded Secret",
  prompt_injection: "Prompt Injection",
  exfiltration: "Exfiltration",
  remote_code_execution: "Remote Code Execution",
  system_modification: "System Modification",
  external_dependencies: "External Dependencies",
  unpinned_packages: "Unpinned Packages",
  suspicious_domain: "Suspicious Domain",
  unofficial_source: "Unofficial Source",
  network_access: "Network Access",
  filesystem_access: "Filesystem Access",
  permissions: "Permissions",
  secrets: "Secrets",
  supply_chain: "Supply Chain",
  execution: "Execution",
  external_resources: "External Resources",
  manifest: "Manifest",
  package: "Package",
  code_execution: "Code Execution",
  obfuscation: "Obfuscation",
};

export default function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);

  return (
    <div style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}>
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-2.5 p-3 text-left transition-colors"
        style={{ background: open ? "#141414" : "transparent" }}
      >
        <SeverityBadge severity={finding.severity} />
        <span className="truncate text-[13px] font-medium flex-1" style={{ color: "#e5e5e5" }}>
          {finding.title}
        </span>
        <span className="hidden sm:inline shrink-0 text-[9px] uppercase tracking-wider" style={{ color: "#525252" }}>
          {CAT_LABELS[finding.category] || finding.category}
        </span>
        {open ? <ChevronUp className="h-3.5 w-3.5 shrink-0" style={{ color: "#525252" }} /> : <ChevronDown className="h-3.5 w-3.5 shrink-0" style={{ color: "#525252" }} />}
      </button>
      {open && (
        <div className="p-3 space-y-2.5" style={{ borderTop: "1px solid #1a1a1a" }}>
          <p className="text-[13px]" style={{ color: "#a3a3a3", lineHeight: 1.5 }}>
            {finding.description}
          </p>
          {finding.evidence && (
            <pre className="p-2.5 text-[11px] overflow-x-auto font-mono whitespace-pre-wrap" style={{ background: "#0a0a0a", border: "1px solid #1a1a1a", color: "#a3a3a3", borderRadius: "4px" }}>
              {finding.evidence}
            </pre>
          )}
          {finding.remediation && (
            <div className="text-[12px]" style={{ color: "#525252" }}>
              <span className="font-medium" style={{ color: "#737373" }}>Remediation: </span>
              {finding.remediation}
            </div>
          )}
          {finding.references?.length ? (
            <div className="flex flex-wrap gap-1.5">
              {finding.references.map((ref, i) => (
                <a
                  key={i}
                  href={ref}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 px-2 py-1 text-[10px] transition-colors"
                  style={{ border: "1px solid #262626", color: "#737373", borderRadius: "3px" }}
                >
                  <ExternalLink className="h-2.5 w-2.5" />
                  {ref.replace(/^https?:\/\//, "").slice(0, 40)}
                </a>
              ))}
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}
