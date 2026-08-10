"use client";

import { useCallback, useRef, useEffect } from "react";
import { useRouter } from "next/navigation";
import { fetchScan } from "@/lib/api";

export function usePollScan() {
  const router = useRouter();
  const abortRef = useRef<AbortController | null>(null);

  const poll = useCallback(
    async (scanId: string, opts?: { maxAttempts?: number; intervalMs?: number; redirectTo?: string }) => {
      const { maxAttempts = 150, intervalMs = 2000, redirectTo } = opts ?? {};
      abortRef.current?.abort();
      const controller = new AbortController();
      abortRef.current = controller;

      for (let i = 0; i < maxAttempts; i++) {
        if (controller.signal.aborted) return;
        await new Promise((r) => setTimeout(r, intervalMs));
        if (controller.signal.aborted) return;
        try {
          const r = await fetchScan(scanId);
          if (r.status === "completed" || r.status === "failed") {
            router.push(redirectTo ?? `/scan/${scanId}`);
            return r;
          }
        } catch {
          // retry on next iteration
        }
      }
      return null;
    },
    [router]
  );

  useEffect(() => {
    return () => abortRef.current?.abort();
  }, []);

  return { poll, abort: () => abortRef.current?.abort() };
}
