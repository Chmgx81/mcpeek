import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { ThemeProvider } from "@/lib/theme";
import AppShell from "@/components/AppShell";

const inter = Inter({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-inter",
});

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL ?? "http://localhost:3000"),
  title: "MCPeek — Runtime-Aware Security Scanner for MCP Servers & AI Agents",
  description: "Detect hidden threats in MCP servers, AI agent skills, and toolchains. Runtime-aware scanning catches what static analyzers miss. No account required.",
  keywords: ["MCP", "MCP server", "AI agent", "security scanner", "prompt injection", "supply chain", "toolchain security", "SKILL.md", "agent skills"],
  icons: { icon: "/favicon.svg" },
  openGraph: {
    title: "MCPeek — Runtime-Aware Security Scanner",
    description: "Detect hidden threats in MCP servers, AI agent skills, and toolchains.",
    type: "website",
    siteName: "MCPeek",
    images: [{ url: "/og.svg", width: 1200, height: 630, alt: "MCPeek Security Scanner" }],
  },
  twitter: {
    card: "summary_large_image",
    title: "MCPeek — Runtime-Aware Security Scanner",
    description: "Detect hidden threats in MCP servers, AI agent skills, and toolchains.",
    images: ["/og.svg"],
  },
  robots: { index: true, follow: true },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={inter.variable} data-theme="dark" suppressHydrationWarning>
      <body className="antialiased">
        <ThemeProvider>
          <AppShell>{children}</AppShell>
        </ThemeProvider>
      </body>
    </html>
  );
}
