"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { ArrowLeft, History } from "lucide-react";
import ScanHistoryTable from "@/components/ScanHistoryTable";
import { fetchScans, deleteScan } from "@/lib/api";
import type { ScanResponse } from "@/lib/types";

export default function HistoryPage() {
  const [scans, setScans] = useState<ScanResponse[]>([]);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    fetchScans(page, 20)
      .then((r) => { setScans(r.scans); setPages(r.pages ?? 1); setLoading(false); })
      .catch(() => setLoading(false));
  }, [page]);

  useEffect(() => { load(); }, [load]);

  const handleDelete = async (id: string) => {
    if (!confirm("Delete this scan? This cannot be undone.")) return;
    setDeletingId(id);
    try {
      await deleteScan(id);
      setScans((prev) => prev.filter((s) => s.scan_id !== id));
    } catch {
      // ignore
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="px-5 py-6 md:px-8">
      <div className="mx-auto max-w-3xl space-y-5">
        <div>
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-1 text-[11px] mb-3 transition-colors"
            style={{ color: "#525252" }}
          >
            <ArrowLeft className="h-3 w-3" /> Dashboard
          </Link>
          <div className="flex items-center gap-1.5">
            <History className="h-3.5 w-3.5" style={{ color: "#22c55e" }} />
            <h1 className="text-lg font-bold" style={{ color: "#fafafa" }}>Scan History</h1>
          </div>
        </div>

        <ScanHistoryTable scans={scans} loading={loading} onDelete={handleDelete} deletingId={deletingId} />

        {pages > 1 && (
          <div className="flex items-center justify-center gap-3">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="px-3 py-1 text-[11px] font-medium transition-colors disabled:opacity-30"
              style={{ border: "1px solid #262626", color: "#737373", borderRadius: "4px" }}
            >
              Previous
            </button>
            <span className="text-[11px] tabular-nums" style={{ color: "#525252" }}>
              Page {page} of {pages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(pages, p + 1))}
              disabled={page >= pages}
              className="px-3 py-1 text-[11px] font-medium transition-colors disabled:opacity-30"
              style={{ border: "1px solid #262626", color: "#737373", borderRadius: "4px" }}
            >
              Next
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
