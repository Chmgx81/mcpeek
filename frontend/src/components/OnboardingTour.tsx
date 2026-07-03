"use client";

import { useState, useEffect, useRef } from "react";
import { X, ArrowRight, ChevronRight } from "lucide-react";

interface Step {
  target: string;
  title: string;
  description: string;
}

const STEPS: Step[] = [
  {
    target: "[data-tour='scan-form']",
    title: "Start a scan",
    description: "Paste a GitHub URL, package name, or config file to scan for security threats.",
  },
  {
    target: "[data-tour='stats']",
    title: "Your stats",
    description: "Track total scans, findings by severity, and your risk distribution over time.",
  },
  {
    target: "[data-tour='sidebar']",
    title: "Navigation",
    description: "Jump between Dashboard, History, and your account settings from here.",
  },
];

export default function OnboardingTour() {
  const [step, setStep] = useState(0);
  const [visible, setVisible] = useState(false);
  const [position, setPosition] = useState({ top: 0, left: 0 });
  const tooltipRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const dismissed = localStorage.getItem("mcpeek-onboarding-done");
    if (dismissed) return;

    const timer = setTimeout(() => {
      setVisible(true);
    }, 800);
    return () => clearTimeout(timer);
  }, []);

  useEffect(() => {
    if (!visible) return;
    const current = STEPS[step];
    if (!current) return;

    const updatePosition = () => {
      const el = document.querySelector(current.target);
      if (!el) return;
      const rect = el.getBoundingClientRect();
      setPosition({
        top: rect.top + rect.height / 2,
        left: rect.left + rect.width / 2,
      });
    };

    updatePosition();
    window.addEventListener("resize", updatePosition);
    window.addEventListener("scroll", updatePosition);
    return () => {
      window.removeEventListener("resize", updatePosition);
      window.removeEventListener("scroll", updatePosition);
    };
  }, [visible, step]);

  const next = () => {
    if (step < STEPS.length - 1) {
      setStep(step + 1);
    } else {
      finish();
    }
  };

  const finish = () => {
    localStorage.setItem("mcpeek-onboarding-done", "true");
    setVisible(false);
  };

  if (!visible || step >= STEPS.length) return null;

  const current = STEPS[step];

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-[60] pointer-events-auto"
        style={{ background: "rgba(0,0,0,0.5)" }}
        onClick={finish}
      />

      {/* Highlight ring */}
      <div
        className="fixed z-[61] pointer-events-none transition-all duration-300"
        style={{
          top: position.top - 24,
          left: position.left - 24,
          width: 48,
          height: 48,
          borderRadius: "8px",
          border: "2px solid #22c55e",
          boxShadow: "0 0 0 9999px rgba(0,0,0,0.5)",
        }}
      />

      {/* Tooltip */}
      <div
        ref={tooltipRef}
        className="fixed z-[62] w-[280px] p-4"
        style={{
          top: position.top + 36,
          left: Math.min(position.left - 140, window.innerWidth - 300),
          background: "#111111",
          border: "1px solid #1a1a1a",
          borderRadius: "6px",
          boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
        }}
      >
        <div className="flex items-center justify-between mb-2">
          <span className="text-[10px] font-medium uppercase tracking-wider" style={{ color: "#22c55e" }}>
            Step {step + 1} of {STEPS.length}
          </span>
          <button onClick={finish} style={{ color: "#525252" }}>
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
        <h3 className="text-[14px] font-semibold mb-1" style={{ color: "#e5e5e5" }}>
          {current.title}
        </h3>
        <p className="text-[12px] mb-3" style={{ color: "#737373", lineHeight: 1.5 }}>
          {current.description}
        </p>
        <div className="flex items-center justify-between">
          <button
            onClick={finish}
            className="text-[11px]"
            style={{ color: "#525252" }}
          >
            Skip tour
          </button>
          <button
            onClick={next}
            className="inline-flex items-center gap-1 px-3 py-1.5 text-[12px] font-medium transition-all hover:brightness-110"
            style={{ background: "#22c55e", color: "#000", borderRadius: "4px" }}
          >
            {step < STEPS.length - 1 ? (
              <>Next <ChevronRight className="h-3 w-3" /></>
            ) : (
              <>Got it <ArrowRight className="h-3 w-3" /></>
            )}
          </button>
        </div>
      </div>
    </>
  );
}
