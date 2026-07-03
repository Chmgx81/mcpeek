"use client";

const STYLES: Record<string, { bg: string; text: string }> = {
  critical: { bg: "rgba(239,68,68,0.1)", text: "#ef4444" },
  high: { bg: "rgba(249,115,22,0.1)", text: "#f97316" },
  medium: { bg: "rgba(234,179,8,0.1)", text: "#eab308" },
  low: { bg: "rgba(34,197,94,0.1)", text: "#22c55e" },
  info: { bg: "rgba(115,115,115,0.1)", text: "#737373" },
};

export default function SeverityBadge({ severity }: { severity: string }) {
  const style = STYLES[severity] || STYLES.info;
  return (
    <span
      className="inline-flex items-center px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide"
      style={{ background: style.bg, color: style.text, borderRadius: "2px" }}
    >
      {severity}
    </span>
  );
}
