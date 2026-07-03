"use client";

export function SkeletonBlock({ className = "", style = {} }: { className?: string; style?: React.CSSProperties }) {
  return (
    <div
      className={`relative overflow-hidden ${className}`}
      style={{
        background: "#1a1a1a",
        borderRadius: "4px",
        ...style,
      }}
    >
      <div
        className="absolute inset-0 -translate-x-full animate-[shimmer_1.5s_infinite]"
        style={{
          background: "linear-gradient(90deg, transparent, rgba(255,255,255,0.04), transparent)",
        }}
      />
    </div>
  );
}

export function DashboardSkeleton() {
  return (
    <div className="p-6 space-y-6">
      {/* Header skeleton */}
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <SkeletonBlock className="w-20 h-3" />
          <SkeletonBlock className="w-40 h-5" />
        </div>
        <SkeletonBlock className="w-24 h-8" />
      </div>

      {/* Stats skeleton */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="p-4 space-y-2" style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}>
            <SkeletonBlock className="w-12 h-3" />
            <SkeletonBlock className="w-16 h-6" />
          </div>
        ))}
      </div>

      {/* Table skeleton */}
      <div style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}>
        <div className="p-4" style={{ borderBottom: "1px solid #1a1a1a" }}>
          <SkeletonBlock className="w-32 h-4" />
        </div>
        {[1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="flex items-center gap-4 p-4" style={{ borderBottom: i < 5 ? "1px solid #1a1a1a" : "none" }}>
            <SkeletonBlock className="w-16 h-3 shrink-0" />
            <SkeletonBlock className="flex-1 h-3" />
            <SkeletonBlock className="w-20 h-3 shrink-0" />
            <SkeletonBlock className="w-12 h-3 shrink-0" />
          </div>
        ))}
      </div>
    </div>
  );
}

export function ScanResultSkeleton() {
  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="space-y-2">
          <SkeletonBlock className="w-48 h-5" />
          <SkeletonBlock className="w-24 h-3" />
        </div>
        <div className="flex gap-6">
          <SkeletonBlock className="w-12 h-12 rounded-full" />
          <SkeletonBlock className="w-12 h-12 rounded-full" />
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="p-3 text-center space-y-2" style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}>
            <SkeletonBlock className="w-8 h-8 mx-auto rounded-full" />
            <SkeletonBlock className="w-10 h-5 mx-auto" />
            <SkeletonBlock className="w-14 h-2 mx-auto" />
          </div>
        ))}
      </div>

      {/* Findings skeleton */}
      <div className="space-y-1.5">
        {[1, 2, 3].map((i) => (
          <div key={i} className="flex items-center gap-3 p-3" style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}>
            <SkeletonBlock className="w-14 h-4 shrink-0" />
            <SkeletonBlock className="flex-1 h-3" />
            <SkeletonBlock className="w-6 h-6 shrink-0" />
          </div>
        ))}
      </div>
    </div>
  );
}
