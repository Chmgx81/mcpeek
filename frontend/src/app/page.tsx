"use client";

import { useRouter } from "next/navigation";
import { ArrowRight, ShieldCheck } from "lucide-react";
import CookieBanner from "@/components/CookieBanner";
import { useScreenSize } from "@/hooks/use-screen-size";
import { PixelTrail } from "@/components/ui/pixel-trail";
import { GooeyFilter } from "@/components/ui/gooey-filter";
import PillNav from "@/components/landing/PillNav";
import HeroMockup from "@/components/landing/HeroMockup";
import StatsBar from "@/components/landing/StatsBar";
import BentoFeatures from "@/components/landing/BentoFeatures";
import HowItWorks from "@/components/landing/HowItWorks";
import DemoEvidence from "@/components/landing/DemoEvidence";
import ComparisonTable from "@/components/landing/ComparisonTable";
import FAQ from "@/components/landing/FAQ";
import CTABanner from "@/components/landing/CTABanner";
import Footer from "@/components/landing/Footer";

export default function LandingPage() {
  const router = useRouter();
  const screenSize = useScreenSize();

  return (
    <div className="min-h-screen" style={{ background: "#0a0a0a" }}>
      <PillNav />

      {/* Hero */}
      <section className="relative flex flex-col items-center px-5 pt-28 pb-0 overflow-hidden">
        <GooeyFilter id="hero-gooey" strength={5} />
        <div
          className="absolute inset-0 z-0"
          style={{ filter: "url(#hero-gooey)" }}
        >
          <PixelTrail
            pixelSize={screenSize.lessThan("md") ? 20 : 32}
            fadeDuration={800}
            delay={0}
            pixelClassName="bg-[#22c55e]"
          />
        </div>

        <div
          className="absolute inset-0 pointer-events-none opacity-[0.03]"
          style={{
            backgroundImage: "linear-gradient(#333 1px, transparent 1px), linear-gradient(90deg, #333 1px, transparent 1px)",
            backgroundSize: "48px 48px",
          }}
        />
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[600px] h-[400px] pointer-events-none" style={{ background: "radial-gradient(ellipse, rgba(34,197,94,0.08) 0%, transparent 70%)" }} />

        <div className="relative z-10 max-w-2xl text-center mb-10">
          <div className="inline-flex items-center gap-1.5 px-3 py-1 mb-6 text-[11px] font-medium uppercase tracking-widest rounded" style={{ background: "rgba(34,197,94,0.08)", color: "#22c55e", border: "1px solid rgba(34,197,94,0.15)" }}>
            <ShieldCheck className="h-3 w-3" />
            Security Scanner
          </div>
          <h1
            className="text-4xl md:text-6xl font-bold tracking-tight"
            style={{ color: "#fafafa", letterSpacing: "-0.04em", lineHeight: 1.05 }}
          >
            Peek beyond
            <br />
            the manifest.
          </h1>
          <p className="mt-5 text-[15px] max-w-lg mx-auto" style={{ color: "#737373", lineHeight: 1.6 }}>
            Runtime-aware security scanning for MCP servers, AI agent skills, and toolchains.
            Detect threats static scanners miss.
          </p>
          <div className="mt-7 flex items-center justify-center gap-3">
            <button
              onClick={() => router.push("/dashboard")}
              className="inline-flex items-center gap-1.5 px-6 py-2.5 text-[14px] font-medium transition-all hover:brightness-110"
              style={{ background: "#22c55e", color: "#000", borderRadius: "4px" }}
            >
              Get started <ArrowRight className="h-3.5 w-3.5" />
            </button>
            <a
              href="#features"
              className="inline-flex items-center gap-1.5 px-6 py-2.5 text-[14px] font-medium transition-colors"
              style={{ color: "#737373", border: "1px solid #262626", borderRadius: "4px" }}
              onMouseEnter={(e) => { e.currentTarget.style.borderColor = "#404040"; e.currentTarget.style.color = "#e5e5e5"; }}
              onMouseLeave={(e) => { e.currentTarget.style.borderColor = "#262626"; e.currentTarget.style.color = "#737373"; }}
            >
              See features
            </a>
          </div>
        </div>

        <div className="relative z-10 w-full max-w-5xl px-2">
          <HeroMockup />
        </div>
        <div className="h-20 w-full" style={{ background: "linear-gradient(to bottom, transparent, #0a0a0a)" }} />
      </section>

      <StatsBar />
      <BentoFeatures />
      <HowItWorks />
      <DemoEvidence />
      <ComparisonTable />
      <FAQ />
      <CTABanner />
      <Footer />
      <CookieBanner />
    </div>
  );
}
