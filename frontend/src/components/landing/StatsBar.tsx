"use client";

import { useCountUp } from "@/hooks/use-count-up";

export default function StatsBar() {
  const s1 = useCountUp(15, 1200);
  const s2 = useCountUp(5, 1200);
  const s3 = useCountUp(3, 1200);
  const s4 = useCountUp(4, 1200);

  const stats = [
    { ref: s1.ref, value: s1.count, suffix: "+", label: "Threat categories", color: "#22c55e" },
    { ref: s2.ref, value: s2.count, suffix: "", label: "Demo fixtures", color: "#eab308" },
    { ref: s3.ref, value: s3.count, suffix: "", label: "Export formats", color: "#3b82f6" },
    { ref: s4.ref, value: s4.count, suffix: "", label: "Scan stages", color: "#a855f7" },
  ];

  return (
    <section className="px-5 py-16" style={{ background: "#0f0f0f" }}>
      <div className="mx-auto max-w-[900px] grid grid-cols-2 md:grid-cols-4 gap-8">
        {stats.map((s) => (
          <div key={s.label} ref={s.ref} className="text-center">
            <div className="text-3xl md:text-4xl font-bold tabular-nums" style={{ color: s.color }}>
              {s.value.toLocaleString()}{s.suffix}
            </div>
            <div className="text-[12px] mt-1" style={{ color: "#525252" }}>{s.label}</div>
          </div>
        ))}
      </div>
    </section>
  );
}
