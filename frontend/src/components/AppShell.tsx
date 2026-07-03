"use client";

import { usePathname } from "next/navigation";
import Sidebar from "./Sidebar";
import CookieBanner from "./CookieBanner";

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isLanding = pathname === "/";
  const isStandalone = pathname === "/demo";

  if (isLanding || isStandalone) {
    return <>{children}</>;
  }

  return (
    <>
      <Sidebar />
      <main className="md:ml-56 min-h-screen" style={{ background: "#0a0a0a" }}>{children}</main>
      <CookieBanner />
    </>
  );
}
