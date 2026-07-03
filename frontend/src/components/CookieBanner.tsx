"use client";

import { useState, useEffect } from "react";
import { X, Cookie } from "lucide-react";

export default function CookieBanner() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const accepted = localStorage.getItem("mcpeek-cookie-accepted");
    if (!accepted) setVisible(true);
  }, []);

  const accept = () => {
    localStorage.setItem("mcpeek-cookie-accepted", "true");
    setVisible(false);
  };

  const reject = () => {
    localStorage.setItem("mcpeek-cookie-accepted", "false");
    setVisible(false);
  };

  if (!visible) return null;

  return (
    <div
      className="fixed bottom-4 right-4 z-50 w-[320px] p-4"
      style={{
        background: "#111111",
        border: "1px solid #1a1a1a",
        borderRadius: "6px",
        boxShadow: "0 8px 32px rgba(0,0,0,0.4)",
      }}
    >
      <button
        onClick={reject}
        className="absolute top-3 right-3"
        style={{ color: "#525252" }}
      >
        <X className="h-3.5 w-3.5" />
      </button>

      <div className="flex items-start gap-2.5 mb-3">
        <Cookie className="h-4 w-4 mt-0.5 shrink-0" style={{ color: "#22c55e" }} />
        <div>
          <p className="text-[13px] font-medium" style={{ color: "#e5e5e5" }}>
            We use cookies
          </p>
          <p className="text-[11px] mt-1" style={{ color: "#737373", lineHeight: 1.5 }}>
            Essential cookies only. No tracking, no analytics, no third-party scripts.
          </p>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={accept}
          className="flex-1 px-3 py-1.5 text-[12px] font-medium transition-all hover:brightness-110"
          style={{ background: "#22c55e", color: "#000", borderRadius: "4px" }}
        >
          Accept
        </button>
        <button
          onClick={reject}
          className="px-3 py-1.5 text-[12px] font-medium transition-colors"
          style={{ color: "#737373", border: "1px solid #262626", borderRadius: "4px" }}
        >
          Reject
        </button>
      </div>

      <button
        onClick={reject}
        className="mt-2 text-[10px] underline"
        style={{ color: "#525252" }}
      >
        Learn more
      </button>
    </div>
  );
}
