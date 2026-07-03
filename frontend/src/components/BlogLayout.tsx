"use client";

import { useState, useEffect, useRef } from "react";
import { ArrowLeft } from "lucide-react";
import Link from "next/link";

interface TocItem {
  id: string;
  label: string;
}

export default function BlogLayout({
  title,
  date,
  children,
}: {
  title: string;
  date: string;
  children: React.ReactNode;
}) {
  const [activeId, setActiveId] = useState("");
  const headingsRef = useRef<Map<string, Element>>(new Map());

  useEffect(() => {
    const headings = document.querySelectorAll("article h2, article h3");
    const map = new Map<string, Element>();
    headings.forEach((h) => {
      if (h.id) map.set(h.id, h);
    });
    headingsRef.current = map;

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setActiveId(entry.target.id);
          }
        });
      },
      { rootMargin: "-80px 0px -60% 0px", threshold: 0 }
    );

    headings.forEach((h) => observer.observe(h));
    return () => observer.disconnect();
  }, []);

  const toc: TocItem[] = [
    { id: "why", label: "Why MCPeek" },
    { id: "how-it-works", label: "How it works" },
    { id: "detection", label: "What we detect" },
    { id: "getting-started", label: "Getting started" },
    { id: "whats-next", label: "What's next" },
  ];

  return (
    <div className="min-h-screen" style={{ background: "#0a0a0a" }}>
      <div className="mx-auto max-w-5xl px-5 py-6 md:px-8">
        <Link
          href="/"
          className="inline-flex items-center gap-1 text-[12px] mb-8 transition-colors"
          style={{ color: "#525252" }}
        >
          <ArrowLeft className="h-3 w-3" /> Back to home
        </Link>

        <div className="flex gap-12 relative">
          {/* Sticky TOC */}
          <aside className="hidden lg:block w-48 shrink-0">
            <div className="sticky top-24">
              <p className="text-[10px] font-medium uppercase tracking-widest mb-3" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>
                On this page
              </p>
              <nav className="space-y-1">
                {toc.map((item) => (
                  <a
                    key={item.id}
                    href={`#${item.id}`}
                    className="block text-[12px] py-1 transition-colors"
                    style={{
                      color: activeId === item.id ? "#22c55e" : "#525252",
                      fontWeight: activeId === item.id ? 500 : 400,
                    }}
                  >
                    {item.label}
                  </a>
                ))}
              </nav>
            </div>
          </aside>

          {/* Article content */}
          <article className="flex-1 min-w-0 max-w-2xl">
            <header className="mb-10">
              <p className="text-[11px] font-medium uppercase tracking-widest mb-2" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>
                Blog
              </p>
              <h1 className="text-3xl md:text-4xl font-bold mb-3" style={{ color: "#fafafa", letterSpacing: "-0.03em", lineHeight: 1.15 }}>
                {title}
              </h1>
              <p className="text-[13px]" style={{ color: "#525252" }}>{date}</p>
            </header>

            <div className="prose-dark space-y-6">
              {children}
            </div>
          </article>
        </div>
      </div>
    </div>
  );
}
