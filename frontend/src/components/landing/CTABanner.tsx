"use client";

import { useRouter } from "next/navigation";
import { ArrowRight } from "lucide-react";

export default function CTABanner() {
  const router = useRouter();
  return (
    <section className="px-5 py-20">
      <div
        className="mx-auto max-w-3xl text-center p-10 relative overflow-hidden"
        style={{
          background: "#111111",
          border: "1px solid #1a1a1a",
          borderRadius: "8px",
        }}
      >
        <div
          className="absolute inset-0 pointer-events-none opacity-[0.04]"
          style={{
            backgroundImage: "radial-gradient(circle, #22c55e 1px, transparent 1px)",
            backgroundSize: "16px 16px",
          }}
        />
        <div className="relative z-10">
          <h2 className="text-2xl md:text-3xl font-bold mb-3" style={{ color: "#fafafa", letterSpacing: "-0.03em" }}>
            Don&apos;t ship blind.
          </h2>
          <p className="text-[14px] mb-6" style={{ color: "#737373" }}>
            Your MCP server might be running untrusted code right now.<br />
            Find out in 30 seconds.
          </p>
          <button
            onClick={() => router.push("/dashboard")}
            className="inline-flex items-center gap-1.5 px-6 py-2.5 text-[14px] font-medium transition-all hover:brightness-110"
            style={{ background: "#22c55e", color: "#000", borderRadius: "4px" }}
          >
            Start scanning <ArrowRight className="h-3.5 w-3.5" />
          </button>
          <p className="mt-3 text-[11px]" style={{ color: "#404040" }}>No account required. Free to use.</p>
        </div>
      </div>
    </section>
  );
}
