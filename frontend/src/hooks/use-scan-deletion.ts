"use client";

import { useState, useCallback } from "react";
import { deleteScan } from "@/lib/api";

export function useScanDeletion(onDeleted?: (id: string) => void) {
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const handleDelete = useCallback(async () => {
    const id = confirmDeleteId;
    setConfirmDeleteId(null);
    if (!id) return;
    setDeletingId(id);
    try {
      await deleteScan(id);
      onDeleted?.(id);
    } catch {
      // silent — could add toast here
    } finally {
      setDeletingId(null);
    }
  }, [confirmDeleteId, onDeleted]);

  return { deletingId, confirmDeleteId, setConfirmDeleteId, handleDelete };
}
