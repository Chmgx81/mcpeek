"use client";

import { useState } from "react";
import { ArrowLeft, Send, Check } from "lucide-react";
import Link from "next/link";
import Logo from "@/components/Logo";

export default function ContactPage() {
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitted(true);
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-5" style={{ background: "#0a0a0a" }}>
      <Link
        href="/"
        className="fixed top-6 left-6 inline-flex items-center gap-1 text-[12px] transition-colors"
        style={{ color: "#525252" }}
      >
        <ArrowLeft className="h-3 w-3" /> Back
      </Link>

      <div className="w-full max-w-md">
        <div className="text-center mb-10">
          <div className="flex justify-center mb-5">
            <Logo size={48} />
          </div>
          <h1 className="text-2xl font-bold mb-2" style={{ color: "#fafafa", letterSpacing: "-0.03em" }}>
            Get in touch
          </h1>
          <p className="text-[13px]" style={{ color: "#737373" }}>
            Questions, feedback, or want to contribute? We&apos;d love to hear from you.
          </p>
        </div>

        {submitted ? (
          <div
            className="text-center p-8"
            style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}
          >
            <div className="w-10 h-10 rounded-full flex items-center justify-center mx-auto mb-3" style={{ background: "rgba(34,197,94,0.12)" }}>
              <Check className="h-5 w-5" style={{ color: "#22c55e" }} />
            </div>
            <p className="text-[14px] font-medium" style={{ color: "#e5e5e5" }}>Message sent</p>
            <p className="text-[12px] mt-1" style={{ color: "#525252" }}>We&apos;ll get back to you within 24 hours.</p>
          </div>
        ) : (
          <form
            onSubmit={handleSubmit}
            className="p-6 space-y-4"
            style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}
          >
            <div>
              <label className="block text-[11px] font-medium uppercase tracking-wider mb-1.5" style={{ color: "#525252" }}>
                Name
              </label>
              <input
                type="text"
                required
                className="w-full px-3 py-2 text-[13px] outline-none transition-colors"
                style={{ background: "#0a0a0a", border: "1px solid #262626", color: "#e5e5e5", borderRadius: "4px" }}
                onFocus={(e) => (e.currentTarget.style.borderColor = "#22c55e")}
                onBlur={(e) => (e.currentTarget.style.borderColor = "#262626")}
              />
            </div>
            <div>
              <label className="block text-[11px] font-medium uppercase tracking-wider mb-1.5" style={{ color: "#525252" }}>
                Email
              </label>
              <input
                type="email"
                required
                className="w-full px-3 py-2 text-[13px] outline-none transition-colors"
                style={{ background: "#0a0a0a", border: "1px solid #262626", color: "#e5e5e5", borderRadius: "4px" }}
                onFocus={(e) => (e.currentTarget.style.borderColor = "#22c55e")}
                onBlur={(e) => (e.currentTarget.style.borderColor = "#262626")}
              />
            </div>
            <div>
              <label className="block text-[11px] font-medium uppercase tracking-wider mb-1.5" style={{ color: "#525252" }}>
                Message
              </label>
              <textarea
                required
                rows={4}
                className="w-full px-3 py-2 text-[13px] outline-none transition-colors resize-none"
                style={{ background: "#0a0a0a", border: "1px solid #262626", color: "#e5e5e5", borderRadius: "4px" }}
                onFocus={(e) => (e.currentTarget.style.borderColor = "#22c55e")}
                onBlur={(e) => (e.currentTarget.style.borderColor = "#262626")}
              />
            </div>
            <button
              type="submit"
              className="w-full inline-flex items-center justify-center gap-1.5 px-4 py-2.5 text-[13px] font-medium transition-all hover:brightness-110"
              style={{ background: "#22c55e", color: "#000", borderRadius: "4px" }}
            >
              <Send className="h-3.5 w-3.5" /> Send message
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
