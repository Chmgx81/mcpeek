"use client";

import { useState, useCallback, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { Search, Loader2, Scan, FileText, ChevronDown } from "lucide-react";
import { submitScan, fetchScan } from "@/lib/api";
import type { TargetType } from "@/lib/types";

const TYPES: { value: TargetType; label: string; placeholder: string }[] = [
  { value: "mcp_server", label: "MCP Server", placeholder: "GitHub URL or local path" },
  { value: "agent_skill", label: "Agent Skill", placeholder: "GitHub URL" },
  { value: "npm_package", label: "npm Package", placeholder: "package-name" },
  { value: "pypi_package", label: "PyPI Package", placeholder: "package-name" },
];

const SCAN_STAGES = [
  "Fetching target...",
  "Analyzing structure...",
  "Scanning for secrets...",
  "Checking shell commands...",
  "Detecting injection vectors...",
  "Scoring trust signals...",
  "Simulating attacks...",
  "Generating report...",
];

export default function ScanForm() {
  const router = useRouter();
  const [targetType, setTargetType] = useState<TargetType>("mcp_server");
  const [target, setTarget] = useState("");
  const [configText, setConfigText] = useState("");
  const [inputMode, setInputMode] = useState<"url" | "text">("url");
  const [deep, setDeep] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scanStage, setScanStage] = useState(0);
  const stageRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const currentType = TYPES.find((t) => t.value === targetType)!;

  useEffect(() => {
    if (scanning) {
      setScanStage(0);
      stageRef.current = setInterval(() => {
        setScanStage((prev) => (prev < SCAN_STAGES.length - 1 ? prev + 1 : prev));
      }, 1800);
    }
    return () => { if (stageRef.current) clearInterval(stageRef.current); };
  }, [scanning]);

  const poll = useCallback(
    async (scanId: string) => {
      for (let i = 0; i < 300; i++) {
        await new Promise((r) => setTimeout(r, 2000));
        try {
          const r = await fetchScan(scanId);
          if (r.status === "completed" || r.status === "failed") {
            setScanning(false);
            router.push(`/scan/${scanId}`);
            return;
          }
        } catch {}
      }
      setScanning(false);
      setError("Scan timed out");
    },
    [router]
  );

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    let scanTarget = target.trim();
    let options: Record<string, unknown> = { deep };
    if (inputMode === "text" && configText.trim()) {
      scanTarget = "__inline_config__";
      options.inline_content = configText.trim();
    }
    if (!scanTarget) return;
    setScanning(true);
    try {
      const result = await submitScan({ target_type: targetType, target: scanTarget, options });
      if (result.status === "completed" || result.status === "failed") {
        router.push(`/scan/${result.scan_id}`);
        return;
      }
      poll(result.scan_id);
    } catch (err) {
      setScanning(false);
      setError(err instanceof Error ? err.message : "Scan failed");
    }
  };

  const hasInput =
    (inputMode === "url" && target.trim()) ||
    (inputMode === "text" && configText.trim());

  return (
    <form onSubmit={handleSubmit} className="p-4" style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}>
      <h2 className="text-[13px] font-semibold mb-3" style={{ color: "#e5e5e5" }}>New Scan</h2>

      {/* Mode tabs */}
      <div className="flex gap-1 p-0.5 mb-3 rounded" style={{ background: "#0a0a0a", border: "1px solid #1a1a1a" }}>
        {([
          { key: "url" as const, icon: Search, label: "URL / Package" },
          { key: "text" as const, icon: FileText, label: "Paste Config" },
        ]).map((tab) => (
          <button
            key={tab.key}
            type="button"
            onClick={() => setInputMode(tab.key)}
            disabled={scanning}
            className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] font-medium transition-colors"
            style={{
              background: inputMode === tab.key ? "#1a1a1a" : "transparent",
              color: inputMode === tab.key ? "#e5e5e5" : "#525252",
              borderRadius: "3px",
            }}
          >
            <tab.icon className="h-3 w-3" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* URL mode */}
      {inputMode === "url" && (
        <div className="flex flex-col gap-2 sm:flex-row">
          <div className="relative sm:w-40 shrink-0">
            <select
              value={targetType}
              onChange={(e) => setTargetType(e.target.value as TargetType)}
              disabled={scanning}
              className="w-full appearance-none px-2.5 py-2 pr-7 text-[12px] disabled:opacity-50"
              style={{ background: "#0a0a0a", border: "1px solid #262626", color: "#a3a3a3", borderRadius: "4px" }}
            >
              {TYPES.map((t) => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </select>
            <ChevronDown className="pointer-events-none absolute right-2 top-1/2 h-3 w-3 -translate-y-1/2" style={{ color: "#525252" }} />
          </div>
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2" style={{ color: "#525252" }} />
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={currentType.placeholder}
              disabled={scanning}
              className="w-full py-2 pl-8 pr-2.5 text-[12px] disabled:opacity-50 placeholder:text-[#404040]"
              style={{ background: "#0a0a0a", border: "1px solid #262626", color: "#e5e5e5", borderRadius: "4px" }}
            />
          </div>
        </div>
      )}

      {/* Text mode */}
      {inputMode === "text" && (
        <textarea
          value={configText}
          onChange={(e) => setConfigText(e.target.value)}
          placeholder="Paste your MCP server config, package.json, or SKILL.md content..."
          disabled={scanning}
          rows={6}
          className="w-full p-2.5 font-mono text-[11px] disabled:opacity-50 resize-none placeholder:text-[#404040]"
          style={{ background: "#0a0a0a", border: "1px solid #262626", color: "#e5e5e5", borderRadius: "4px" }}
        />
      )}

      {/* Bottom row */}
      <div className="mt-3 flex items-center justify-between">
        <label className="flex items-center gap-1.5 cursor-pointer text-[12px]" style={{ color: "#525252" }}>
          <input
            type="checkbox"
            checked={deep}
            onChange={(e) => setDeep(e.target.checked)}
            disabled={scanning}
            className="h-3 w-3 rounded-sm"
            style={{ accentColor: "#22c55e" }}
          />
          Deep scan
        </label>
        <button
          type="submit"
          disabled={scanning || !hasInput}
          className="inline-flex items-center gap-1.5 px-4 py-1.5 text-[12px] font-medium transition-all disabled:cursor-not-allowed disabled:opacity-30 hover:brightness-110"
          style={{ background: "#22c55e", color: "#000000", borderRadius: "4px" }}
        >
          {scanning ? <><Loader2 className="h-3 w-3 animate-spin" /> Scanning...</> : <><Scan className="h-3 w-3" /> Scan</>}
        </button>
      </div>

      {/* Scan progress */}
      {scanning && (
        <div className="mt-3 p-2.5 rounded" style={{ background: "#0a0a0a", border: "1px solid #1a1a1a" }}>
          <div className="flex items-center gap-2 mb-1.5">
            <div className="h-1.5 flex-1 rounded-full overflow-hidden" style={{ background: "#1a1a1a" }}>
              <div
                className="h-full rounded-full transition-all duration-700 ease-out"
                style={{ background: "#22c55e", width: `${((scanStage + 1) / SCAN_STAGES.length) * 100}%` }}
              />
            </div>
            <span className="text-[9px] tabular-nums" style={{ color: "#525252" }}>{scanStage + 1}/{SCAN_STAGES.length}</span>
          </div>
          <p className="text-[11px] font-mono" style={{ color: "#22c55e" }}>{SCAN_STAGES[scanStage]}</p>
        </div>
      )}

      {error && (
        <div className="mt-2 px-2.5 py-1.5 text-[12px] rounded" style={{ background: "rgba(239,68,68,0.08)", color: "#ef4444", borderRadius: "4px" }}>
          {error}
        </div>
      )}
    </form>
  );
}
