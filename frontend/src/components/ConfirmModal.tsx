"use client";

import { AlertTriangle, X } from "lucide-react";

interface ConfirmModalProps {
  open: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function ConfirmModal({
  open,
  title,
  message,
  confirmLabel = "Delete",
  danger = true,
  onConfirm,
  onCancel,
}: ConfirmModalProps) {
  if (!open) return null;

  return (
    <>
      <div
        className="fixed inset-0 z-[70]"
        style={{ background: "rgba(0,0,0,0.6)" }}
        onClick={onCancel}
      />
      <div
        className="fixed z-[71] top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[340px] p-5"
        style={{
          background: "#111111",
          border: "1px solid #1a1a1a",
          borderRadius: "8px",
          boxShadow: "0 16px 64px rgba(0,0,0,0.5)",
        }}
      >
        <div className="flex items-start gap-3 mb-4">
          <div
            className="shrink-0 w-8 h-8 rounded flex items-center justify-center"
            style={{
              background: danger ? "rgba(239,68,68,0.1)" : "rgba(34,197,94,0.1)",
            }}
          >
            <AlertTriangle className="h-4 w-4" style={{ color: danger ? "#ef4444" : "#22c55e" }} />
          </div>
          <div className="flex-1 min-w-0">
            <h3 className="text-[14px] font-semibold" style={{ color: "#e5e5e5" }}>
              {title}
            </h3>
            <p className="text-[12px] mt-1" style={{ color: "#737373", lineHeight: 1.5 }}>
              {message}
            </p>
          </div>
          <button onClick={onCancel} className="shrink-0" style={{ color: "#525252" }}>
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex items-center justify-end gap-2">
          <button
            onClick={onCancel}
            className="px-3 py-1.5 text-[12px] font-medium transition-colors"
            style={{ border: "1px solid #262626", color: "#737373", borderRadius: "4px" }}
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="px-3 py-1.5 text-[12px] font-medium transition-all hover:brightness-110"
            style={{
              background: danger ? "#ef4444" : "#22c55e",
              color: "#fff",
              borderRadius: "4px",
            }}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </>
  );
}
