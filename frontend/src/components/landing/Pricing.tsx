"use client";

import { ArrowRight, Check } from "lucide-react";

const plans = [
  {
    name: "Free",
    price: "$0",
    description: "Open-source scanner for individuals, contributors, and self-hosted teams.",
    features: ["Public scan flow", "CLI and GitHub Action", "Static analysis and AI assist", "No account required"],
    cta: "Try MCPeek",
    href: "/dashboard",
    featured: false,
  },
  {
    name: "Enterprise",
    price: "Contact us",
    description: "Workspace auth, API keys, audit visibility, and rollout support for teams.",
    features: ["Workspace-scoped access", "Audit trail and request tracing", "Admin workspace provisioning", "Implementation support"],
    cta: "Talk to us",
    href: "/contact",
    featured: true,
  },
];

export default function Pricing() {
  return (
    <section id="pricing" className="px-5 py-20">
      <div className="mx-auto max-w-5xl">
        <div className="mb-10 text-center">
          <p className="text-[11px] font-medium uppercase tracking-widest mb-3" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>Pricing</p>
          <h2 className="text-2xl md:text-3xl font-bold" style={{ color: "#fafafa", letterSpacing: "-0.03em" }}>
            Free to start. Enterprise when ownership matters.
          </h2>
          <p className="mt-3 text-[14px] max-w-2xl mx-auto" style={{ color: "#737373", lineHeight: 1.6 }}>
            MCPeek stays open and usable for individuals and teams that want the public flow. Enterprises can add workspace auth, API keys, and operational support.
          </p>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          {plans.map((plan) => (
            <div
              key={plan.name}
              className="relative overflow-hidden p-6"
              style={{
                background: plan.featured ? "#111111" : "#0f0f0f",
                border: plan.featured ? "1px solid rgba(34,197,94,0.25)" : "1px solid #1a1a1a",
                borderRadius: "10px",
              }}
            >
              {plan.featured && (
                <div className="absolute right-4 top-4 text-[10px] uppercase tracking-widest px-2 py-1" style={{ color: "#22c55e", border: "1px solid rgba(34,197,94,0.18)", background: "rgba(34,197,94,0.06)" }}>
                  Recommended
                </div>
              )}
              <p className="text-[11px] font-medium uppercase tracking-widest mb-2" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>{plan.name}</p>
              <div className="flex items-end gap-2 mb-3">
                <h3 className="text-3xl font-bold" style={{ color: "#fafafa", letterSpacing: "-0.04em" }}>{plan.price}</h3>
              </div>
              <p className="text-[14px] mb-5" style={{ color: "#737373", lineHeight: 1.6 }}>{plan.description}</p>
              <div className="space-y-2 mb-6">
                {plan.features.map((feature) => (
                  <div key={feature} className="flex items-center gap-2 text-[13px]" style={{ color: "#d4d4d4" }}>
                    <Check className="h-3.5 w-3.5 shrink-0" style={{ color: "#22c55e" }} />
                    {feature}
                  </div>
                ))}
              </div>
              <a
                href={plan.href}
                className="inline-flex items-center gap-1.5 px-5 py-2.5 text-[14px] font-medium transition-all hover:brightness-110"
                style={{ background: plan.featured ? "#22c55e" : "#171717", color: plan.featured ? "#000" : "#e5e5e5", borderRadius: "4px", border: plan.featured ? "none" : "1px solid #262626" }}
              >
                {plan.cta} <ArrowRight className="h-3.5 w-3.5" />
              </a>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}