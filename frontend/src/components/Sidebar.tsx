"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { LayoutDashboard, History, Menu, X, Terminal } from "lucide-react";
import Logo from "./Logo";

const NAV = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/history", label: "History", icon: History },
];

export default function Sidebar() {
  const [open, setOpen] = useState(false);
  const pathname = usePathname();

  const links = NAV.map((item) => {
    const active = pathname.startsWith(item.href);
    return (
      <Link
        key={item.href}
        href={item.href}
        onClick={() => setOpen(false)}
        className="flex items-center gap-2.5 px-3 py-2 text-[13px] font-medium transition-colors"
        style={{
          background: active ? "rgba(34,197,94,0.08)" : "transparent",
          color: active ? "#22c55e" : "#737373",
          borderRadius: "4px",
        }}
        onMouseEnter={(e) => {
          if (!active) e.currentTarget.style.background = "rgba(255,255,255,0.03)";
        }}
        onMouseLeave={(e) => {
          if (!active) e.currentTarget.style.background = "transparent";
        }}
      >
        <item.icon className="h-4 w-4" />
        {item.label}
      </Link>
    );
  });

  return (
    <>
      {/* Mobile bar */}
      <div
        className="fixed top-0 inset-x-0 z-50 flex items-center gap-3 px-4 py-2.5 md:hidden"
        style={{ background: "#0f0f0f", borderBottom: "1px solid #1a1a1a" }}
      >
        <button onClick={() => setOpen(!open)} style={{ color: "#737373" }}>
          {open ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
        </button>
        <div className="flex items-center gap-2">
          <Logo size={14} />
          <span className="text-[13px] font-semibold" style={{ color: "#e5e5e5" }}>MCPeek</span>
        </div>
      </div>

      {/* Mobile overlay */}
      {open && (
        <div className="fixed inset-0 z-40 md:hidden" style={{ background: "rgba(0,0,0,0.6)" }} onClick={() => setOpen(false)} />
      )}

      {/* Mobile drawer */}
      <div
        className={`fixed top-0 left-0 z-50 h-full w-56 p-3 pt-12 transition-transform duration-150 md:hidden ${open ? "translate-x-0" : "-translate-x-full"}`}
        style={{ background: "#0f0f0f", borderRight: "1px solid #1a1a1a" }}
      >
        <nav className="flex flex-col gap-0.5">{links}</nav>
      </div>

      {/* Desktop sidebar */}
      <aside
        data-tour="sidebar"
        className="fixed top-0 left-0 z-40 hidden h-full w-56 flex flex-col py-4 px-2 md:flex"
        style={{ background: "#0f0f0f", borderRight: "1px solid #1a1a1a" }}
      >
        <div className="flex items-center gap-2 px-3 py-2 mb-6">
          <Logo size={16} />
          <span className="text-[14px] font-semibold" style={{ color: "#e5e5e5" }}>MCPeek</span>
        </div>

        <nav className="flex flex-col gap-0.5 flex-1">{links}</nav>

        {/* Local demo status */}
        <div
          className="flex items-center gap-2.5 px-3 py-2.5 mt-auto rounded"
          style={{ borderTop: "1px solid #1a1a1a" }}
        >
          <div className="w-7 h-7 rounded-full flex items-center justify-center text-[10px] font-bold" style={{ background: "rgba(34,197,94,0.12)", color: "#22c55e" }}>
            <Terminal className="h-3.5 w-3.5" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-[12px] font-medium truncate" style={{ color: "#e5e5e5" }}>Local demo</div>
            <div className="text-[10px] truncate" style={{ color: "#525252" }}>No account required</div>
          </div>
        </div>
      </aside>
    </>
  );
}
