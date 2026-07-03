"use client";

function riskColor(score: number, isTrust: boolean = false): string {
  if (isTrust) {
    if (score >= 90) return "#22c55e";
    if (score >= 70) return "#4ade80";
    if (score >= 50) return "#eab308";
    if (score >= 25) return "#f97316";
    return "#ef4444";
  }
  if (score <= 20) return "#22c55e";
  if (score <= 40) return "#4ade80";
  if (score <= 60) return "#eab308";
  if (score <= 80) return "#f97316";
  return "#ef4444";
}

const SIZES = {
  sm: { s: 44, sw: 3, fs: 12 },
  md: { s: 64, sw: 4, fs: 16 },
  lg: { s: 88, sw: 5, fs: 22 },
} as const;

export default function RiskScore({ score, size = "md", isTrust = false }: { score: number; size?: "sm" | "md" | "lg"; isTrust?: boolean }) {
  const { s, sw, fs } = SIZES[size];
  const r = (s - sw) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const color = riskColor(score, isTrust);

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: s, height: s }}>
      <svg width={s} height={s} className="-rotate-90">
        <circle cx={s / 2} cy={s / 2} r={r} fill="none" stroke="#1a1a1a" strokeWidth={sw} />
        <circle cx={s / 2} cy={s / 2} r={r} fill="none" stroke={color} strokeWidth={sw}
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
          className="transition-all duration-500" />
      </svg>
      <span className="absolute font-bold tabular-nums" style={{ fontSize: fs, color }}>
        {score}
      </span>
    </div>
  );
}
