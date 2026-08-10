"use client";

import { SEVERITY_COLORS } from "@/lib/constants";

export default function SeverityBadge({ severity }: { severity: string }) {
  const style = SEVERITY_COLORS[severity] || SEVERITY_COLORS.info;
  return (
    <span
      className="inline-flex items-center px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide"
      style={{ background: style.bg, color: style.text, borderRadius: "2px" }}
    >
      {severity}
    </span>
  );
}
