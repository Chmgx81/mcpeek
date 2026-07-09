"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import Logo from "@/components/Logo";

export default function PillNav() {
  const router = useRouter();
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <div className="fixed top-4 inset-x-0 z-50 flex justify-center px-4">
      <nav
        className="flex items-center justify-between gap-6 px-4 py-2 w-full max-w-2xl transition-all duration-300"
        style={{
          background: scrolled ? "rgba(17,17,17,0.95)" : "rgba(17,17,17,0.8)",
          backdropFilter: "blur(16px)",
          border: "1px solid #1a1a1a",
          borderRadius: "9999px",
          boxShadow: scrolled
            ? "0 8px 32px rgba(0,0,0,0.4), 0 0 0 1px rgba(34,197,94,0.05)"
            : "0 4px 16px rgba(0,0,0,0.2)",
        }}
      >
        <button onClick={() => router.push("/")} className="flex items-center gap-2 shrink-0">
          <Logo size={16} />
          <span className="text-[13px] font-semibold" style={{ color: "#e5e5e5" }}>MCPeek</span>
        </button>
        <div className="hidden sm:flex items-center gap-1">
          {["Features", "How it works", "FAQ"].map((item) => (
            <button
              key={item}
              onClick={() => {
                const id = item.toLowerCase().replace(/\s+/g, "-");
                document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
              }}
              className="px-3 py-1 text-[12px] font-medium transition-colors rounded-full"
              style={{ color: "#737373" }}
              onMouseEnter={(e) => (e.currentTarget.style.color = "#e5e5e5")}
              onMouseLeave={(e) => (e.currentTarget.style.color = "#737373")}
            >
              {item}
            </button>
          ))}
        </div>
        <button
          onClick={() => router.push("/dashboard")}
          className="px-4 py-1.5 text-[12px] font-medium transition-all hover:brightness-110 shrink-0"
          style={{ background: "#22c55e", color: "#000", borderRadius: "9999px" }}
        >
          Get started
        </button>
      </nav>
    </div>
  );
}
