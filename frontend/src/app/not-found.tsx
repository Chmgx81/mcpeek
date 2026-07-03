import Link from "next/link";
import { ShieldAlert, ArrowLeft, Home } from "lucide-react";

export default function NotFound() {
  return (
    <div className="flex min-h-screen items-center justify-center px-5" style={{ background: "#0a0a0a" }}>
      <div className="text-center max-w-md">
        <div className="w-16 h-16 rounded-lg flex items-center justify-center mx-auto mb-6" style={{ background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.15)" }}>
          <ShieldAlert className="h-7 w-7" style={{ color: "#ef4444" }} />
        </div>
        <h1 className="text-5xl font-bold mb-2" style={{ color: "#fafafa", letterSpacing: "-0.04em" }}>404</h1>
        <p className="text-[15px] font-medium mb-1" style={{ color: "#e5e5e5" }}>Page not found</p>
        <p className="text-[13px] mb-8" style={{ color: "#525252", lineHeight: 1.5 }}>
          The page you&apos;re looking for doesn&apos;t exist or has been moved.
        </p>
        <div className="flex items-center justify-center gap-2">
          <Link
            href="/"
            className="inline-flex items-center gap-1.5 px-5 py-2 text-[13px] font-medium transition-colors"
            style={{ background: "#22c55e", color: "#000", borderRadius: "4px" }}
          >
            <Home className="h-3.5 w-3.5" /> Back to home
          </Link>
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-1.5 px-5 py-2 text-[13px] font-medium transition-colors"
            style={{ color: "#737373", border: "1px solid #262626", borderRadius: "4px" }}
          >
            <ArrowLeft className="h-3.5 w-3.5" /> Dashboard
          </Link>
        </div>
      </div>
    </div>
  );
}
