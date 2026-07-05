"use client";

import { useEffect, useState } from "react";
import { use } from "react";
import {
  ArrowLeft, Clock, FileText, Link2, Package, Loader2, AlertTriangle,
  Shield, Globe, Lock, Swords, ChevronDown, ChevronUp, FileJson, FileCode, Share2, Check, RefreshCw, AlertOctagon, Trash2,
} from "lucide-react";
import Link from "next/link";
import RiskScore from "@/components/RiskScore";
import FindingCard from "@/components/FindingCard";
import SeverityBadge from "@/components/SeverityBadge";
import ConfirmModal from "@/components/ConfirmModal";
import { fetchScan, fetchFullReport, rescanScan, fetchContentChanges, deleteScan, type ContentChange } from "@/lib/api";
import type { ScanResponse, FullReport, AttackScenario } from "@/lib/types";

const TYPE_LABELS: Record<string, string> = {
  mcp_server: "MCP Server",
  agent_skill: "Agent Skill",
  npm_package: "npm Package",
  pypi_package: "PyPI Package",
};

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function AttackCard({ scenario }: { scenario: AttackScenario }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}>
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center justify-between gap-2.5 p-3 text-left transition-colors"
        style={{ background: open ? "#141414" : "transparent" }}
      >
        <div className="flex items-center gap-2 min-w-0">
          <Swords className="h-3.5 w-3.5 shrink-0" style={{ color: "#ef4444" }} />
          <span className="truncate text-[13px] font-medium" style={{ color: "#e5e5e5" }}>{scenario.finding}</span>
          <SeverityBadge severity={scenario.severity} />
        </div>
        {open ? <ChevronUp className="h-3.5 w-3.5 shrink-0" style={{ color: "#525252" }} /> : <ChevronDown className="h-3.5 w-3.5 shrink-0" style={{ color: "#525252" }} />}
      </button>
      {open && (
        <div className="p-3" style={{ borderTop: "1px solid #1a1a1a" }}>
          <p className="text-[13px]" style={{ color: "#a3a3a3", lineHeight: 1.5 }}>{scenario.attack_vector}</p>
        </div>
      )}
    </div>
  );
}

export default function ScanResultsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [scan, setScan] = useState<ScanResponse | null>(null);
  const [report, setReport] = useState<FullReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [showExec, setShowExec] = useState(false);
  const [copied, setCopied] = useState(false);
  const [rescanning, setRescanning] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [contentChanges, setContentChanges] = useState<ContentChange[] | null>(null);

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    Promise.all([
      fetchScan(id).catch((e) => { console.error("fetchScan failed:", e); throw e; }),
      fetchFullReport(id).catch(() => null),
    ]).then(([s, r]) => {
      if (!cancelled) { setScan(s); setReport(r); setLoading(false); }
    }).catch((e) => {
      console.error("Scan load error:", e);
      if (!cancelled) { setError(e instanceof Error ? e.message : "Failed to load scan results"); setLoading(false); }
    }).finally(() => clearTimeout(timeout));

    return () => { cancelled = true; controller.abort(); clearTimeout(timeout); };
  }, [id]);

  // Load content changes if this is a re-scan
  useEffect(() => {
    if (scan?.rescan_of) {
      fetchContentChanges(id).then((r) => {
        if (r.has_changes) setContentChanges(r.changes);
      }).catch(() => {});
    }
  }, [id, scan?.rescan_of]);

  const handleRescan = async () => {
    setRescanning(true);
    try {
      const result = await rescanScan(id);
      // Poll until complete
      for (let i = 0; i < 60; i++) {
        await new Promise((r) => setTimeout(r, 2000));
        const updated = await fetchScan(result.scan_id);
        if (updated.status === "completed" || updated.status === "failed") {
          window.location.href = `/scan/${result.scan_id}`;
          return;
        }
      }
      setRescanning(false);
    } catch {
      setRescanning(false);
    }
  };

  const handleDelete = async () => {
    setConfirmDelete(false);
    setDeleting(true);
    try {
      await deleteScan(id);
      window.location.href = "/history";
    } catch {
      setDeleting(false);
    }
  };

  if (loading) return (
    <div className="flex items-center justify-center py-32" style={{ background: "#0a0a0a" }}>
      <div className="flex flex-col items-center gap-3">
        <div className="relative">
          <Loader2 className="h-8 w-8 animate-spin" style={{ color: "#22c55e" }} />
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="h-2 w-2 rounded-full" style={{ background: "#22c55e" }} />
          </div>
        </div>
        <div className="text-center">
          <p className="text-[13px] font-medium" style={{ color: "#e5e5e5" }}>Loading results</p>
          <p className="text-[11px] mt-0.5" style={{ color: "#525252" }}>Analyzing findings...</p>
        </div>
      </div>
    </div>
  );

  if (error || !scan) return (
    <div className="flex min-h-screen items-center justify-center" style={{ background: "#0a0a0a" }}>
      <div className="flex flex-col items-center gap-2 text-center">
        <AlertTriangle className="h-6 w-6" style={{ color: "#ef4444" }} />
        <p className="text-[13px]" style={{ color: "#e5e5e5" }}>{error || "Scan not found"}</p>
        <Link href="/dashboard" className="text-[12px] font-medium" style={{ color: "#22c55e" }}>Back to dashboard</Link>
      </div>
    </div>
  );

  const findings = [...scan.findings].sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5));
  const total = findings.length;
  const critical = scan.summary.critical;
  const high = scan.summary.high;

  const runtimeRisks = scan.findings.filter((f) =>
    ["execution", "code_execution", "exfiltration", "manifest", "tool_poisoning"].includes(f.category)
  ).length;
  const trustRisks = scan.findings.filter((f) =>
    ["supply_chain", "permissions", "social_engineering", "scope_creep", "intent_subversion", "context_oversharing"].includes(f.category)
  ).length;

  const trustScore = report?.json?.scores?.trust_score?.value ?? Math.max(0, 100 - trustRisks * 12 - runtimeRisks * 8);

  const recommendations = report?.json?.recommendations?.length ? report.json.recommendations : (() => {
    const r: string[] = [];
    if (critical > 0) r.push("Address all critical findings before deploying.");
    if (high > 0) r.push("Review high-severity findings and apply fixes.");
    if (runtimeRisks > 0) r.push("Audit external URLs and install scripts.");
    if (trustRisks > 0) r.push("Verify dependency sources and pin versions.");
    if (scan.findings.some((f) => f.category === "hardcoded_secret")) r.push("Rotate exposed credentials.");
    if (total === 0) r.push("No issues detected. Continue periodic scans.");
    return r;
  })();

  const scenarios = report?.json?.attack_simulation?.scenarios ?? [];

  return (
    <div className="min-h-screen" style={{ background: "#0a0a0a" }}>
      {/* Header */}
      <div style={{ borderBottom: "1px solid #1a1a1a", background: "#0f0f0f" }}>
        <div className="mx-auto max-w-3xl px-5 py-4 md:px-8">
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-1 text-[11px] mb-3 transition-colors"
            style={{ color: "#525252" }}
          >
            <ArrowLeft className="h-3 w-3" /> Dashboard
          </Link>

          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h1 className="text-[15px] font-bold truncate" style={{ color: "#e5e5e5" }}>
                  {scan.target}
                </h1>
                <span className="shrink-0 text-[9px] uppercase tracking-wider" style={{ color: "#525252" }}>
                  {TYPE_LABELS[scan.target_type]}
                </span>
              </div>
              <div className="mt-1 flex items-center gap-1.5">
                <span
                  className="inline-flex px-1.5 py-0.5 text-[8px] font-semibold uppercase"
                  style={{
                    background: scan.status === "completed" ? "rgba(34,197,94,0.1)" : "rgba(239,68,68,0.1)",
                    color: scan.status === "completed" ? "#22c55e" : "#ef4444",
                    borderRadius: "2px",
                  }}
                >
                  {scan.status}
                </span>
                <span className="text-[11px]" style={{ color: "#525252" }}>
                  {new Date(scan.created_at).toLocaleString()}
                </span>
              </div>
            </div>
            <div className="flex items-center gap-3 shrink-0">
              <div className="flex items-center gap-6">
                <div className="flex flex-col items-center gap-0.5">
                  <span className="text-[8px] uppercase tracking-widest" style={{ color: "#525252" }}>Security</span>
                  <RiskScore score={scan.overall_risk} size="lg" />
                </div>
                <div className="flex flex-col items-center gap-0.5">
                  <span className="text-[8px] uppercase tracking-widest" style={{ color: "#525252" }}>Trust</span>
                  <RiskScore score={trustScore} size="lg" isTrust />
                </div>
              </div>
              {scan.status === "completed" && (
                <button
                  onClick={handleRescan}
                  disabled={rescanning}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-medium transition-all disabled:opacity-50"
                  style={{
                    border: "1px solid #262626",
                    color: rescanning ? "#22c55e" : "#737373",
                    borderRadius: "3px",
                  }}
                >
                  {rescanning ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
                  {rescanning ? "Re-scanning..." : "Re-scan"}
                </button>
              )}
              <button
                onClick={() => setConfirmDelete(true)}
                disabled={deleting}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-medium transition-all disabled:opacity-50"
                style={{
                  border: "1px solid rgba(239,68,68,0.3)",
                  color: deleting ? "#ef4444" : "#737373",
                  borderRadius: "3px",
                }}
              >
                {deleting ? <Loader2 className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3 w-3" />}
                {deleting ? "Deleting..." : "Delete"}
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="mx-auto max-w-3xl space-y-5 px-5 py-5 md:px-8">
        {/* Summary cards */}
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <SummaryCard icon={<Shield className="h-3.5 w-3.5" />} value={total} label="Findings" color="#e5e5e5" />
          <SummaryCard icon={<AlertTriangle className="h-3.5 w-3.5" />} value={critical} label="Critical" color="#ef4444" pulse={critical > 0} />
          <SummaryCard icon={<Globe className="h-3.5 w-3.5" />} value={runtimeRisks} label="Runtime Risks" color="#f97316" />
          <SummaryCard icon={<Lock className="h-3.5 w-3.5" />} value={trustRisks} label="Trust Risks" color="#22c55e" />
        </div>

        {/* Metadata */}
        <div className="p-3 flex flex-wrap gap-x-5 gap-y-1 text-[11px]" style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px", color: "#525252" }}>
          <span className="flex items-center gap-1"><Clock className="h-3 w-3" /> {scan.metadata.scan_duration_ms}ms</span>
          <span className="flex items-center gap-1"><FileText className="h-3 w-3" /> {scan.metadata.files_analyzed} files</span>
          <span className="flex items-center gap-1"><Link2 className="h-3 w-3" /> {scan.metadata.urls_checked} URLs</span>
          <span className="flex items-center gap-1"><Package className="h-3 w-3" /> {scan.metadata.deps_analyzed} deps</span>
        </div>

        {/* Content change alert */}
        {(scan.content_changed || contentChanges) && (
          <div className="p-3 flex items-start gap-2.5" style={{ background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.2)", borderRadius: "6px" }}>
            <AlertOctagon className="h-4 w-4 shrink-0 mt-0.5" style={{ color: "#ef4444" }} />
            <div>
              <p className="text-[12px] font-semibold" style={{ color: "#ef4444" }}>Bait-and-switch detected</p>
              <p className="text-[11px] mt-0.5" style={{ color: "#a3a3a3" }}>
                External URL content has changed since the previous scan. This is a strong indicator of a supply-chain attack.
              </p>
              {contentChanges && contentChanges.length > 0 && (
                <ul className="mt-1.5 space-y-0.5">
                  {contentChanges.map((c, i) => (
                    <li key={i} className="text-[10px] font-mono" style={{ color: "#737373" }}>
                      {c.status}: {c.url}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}

        {/* Attack Simulation */}
        {scenarios.length > 0 && (
          <section>
            <p className="text-[10px] font-medium uppercase tracking-widest mb-2 flex items-center gap-1.5" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>
              <Swords className="h-3 w-3" /> Attack Simulation
            </p>
            <div className="space-y-1.5">
              {scenarios.map((s, i) => <AttackCard key={i} scenario={s} />)}
            </div>
          </section>
        )}

        {/* AI Attack Scenarios */}
        {scan.ai_attack_scenarios && scan.ai_attack_scenarios.length > 0 && (
          <section>
            <p className="text-[10px] font-medium uppercase tracking-widest mb-2 flex items-center gap-1.5" style={{ color: "#a855f7", letterSpacing: "0.1em" }}>
              <Swords className="h-3 w-3" /> AI-Generated Attack Scenarios
            </p>
            <div className="space-y-1.5">
              {scan.ai_attack_scenarios.map((scenario, i) => (
                <div key={i} style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}>
                  <div className="p-3">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-[13px] font-medium" style={{ color: "#e5e5e5" }}>{scenario.title}</span>
                      <SeverityBadge severity={scenario.severity} />
                    </div>
                    <div className="space-y-2 text-[12px]" style={{ color: "#a3a3a3" }}>
                      <div>
                        <span className="text-[10px] uppercase tracking-wider" style={{ color: "#525252" }}>Vector</span>
                        <p style={{ lineHeight: 1.5 }}>{scenario.vector}</p>
                      </div>
                      <div>
                        <span className="text-[10px] uppercase tracking-wider" style={{ color: "#525252" }}>Impact</span>
                        <p style={{ lineHeight: 1.5 }}>{scenario.impact}</p>
                      </div>
                      {scenario.steps && scenario.steps.length > 0 && (
                        <div>
                          <span className="text-[10px] uppercase tracking-wider" style={{ color: "#525252" }}>Exploitation Steps</span>
                          <ol className="mt-1 space-y-1">
                            {scenario.steps.map((step, j) => (
                              <li key={j} className="flex items-start gap-1.5">
                                <span className="text-[10px] font-mono mt-0.5" style={{ color: "#525252" }}>{j + 1}.</span>
                                <span style={{ lineHeight: 1.5 }}>{step}</span>
                              </li>
                            ))}
                          </ol>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* AI Threat Intelligence */}
        {scan.ai_threat_intel && scan.ai_threat_intel.length > 0 && (
          <section>
            <p className="text-[10px] font-medium uppercase tracking-widest mb-2 flex items-center gap-1.5" style={{ color: "#f97316", letterSpacing: "0.1em" }}>
              <AlertTriangle className="h-3 w-3" /> Threat Intelligence
            </p>
            <div className="space-y-1.5">
              {scan.ai_threat_intel.map((intel, i) => (
                <div key={i} className="p-3" style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}>
                  <p className="text-[12px] font-medium mb-2" style={{ color: "#e5e5e5" }}>{intel.category}</p>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px]">
                    {intel.cves && intel.cves.length > 0 && (
                      <div>
                        <span className="text-[9px] uppercase tracking-wider" style={{ color: "#525252" }}>CVEs</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {intel.cves.map((cve, j) => (
                            <span key={j} className="px-1.5 py-0.5 font-mono" style={{ background: "rgba(239,68,68,0.1)", color: "#ef4444", borderRadius: "2px" }}>{cve}</span>
                          ))}
                        </div>
                      </div>
                    )}
                    {intel.mitre_techniques && intel.mitre_techniques.length > 0 && (
                      <div>
                        <span className="text-[9px] uppercase tracking-wider" style={{ color: "#525252" }}>MITRE ATT&CK</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {intel.mitre_techniques.map((t, j) => (
                            <span key={j} className="px-1.5 py-0.5" style={{ background: "rgba(249,115,22,0.1)", color: "#f97316", borderRadius: "2px" }}>{t}</span>
                          ))}
                        </div>
                      </div>
                    )}
                    {intel.campaigns && intel.campaigns.length > 0 && (
                      <div>
                        <span className="text-[9px] uppercase tracking-wider" style={{ color: "#525252" }}>Campaigns</span>
                        <div className="mt-1 space-y-0.5">
                          {intel.campaigns.map((c, j) => (
                            <p key={j} className="text-[10px]" style={{ color: "#a3a3a3" }}>{c}</p>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Findings */}
        <section>
          <p className="text-[10px] font-medium uppercase tracking-widest mb-2" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>
            Findings ({findings.length})
          </p>
          {findings.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12" style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}>
              <Shield className="mb-2 h-6 w-6" style={{ color: "#22c55e" }} />
              <p className="text-[13px] font-medium" style={{ color: "#e5e5e5" }}>No issues found</p>
              <p className="text-[11px] mt-0.5" style={{ color: "#525252" }}>This scan passed all security checks.</p>
            </div>
          ) : (
            <div className="space-y-1.5">
              {findings.map((f) => <FindingCard key={f.id} finding={f} />)}
            </div>
          )}
        </section>

        {/* Recommendations */}
        <section className="p-4" style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}>
          <p className="text-[10px] font-medium uppercase tracking-widest mb-2" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>Recommendations</p>
          <ul className="space-y-1.5">
            {recommendations.map((rec, i) => (
              <li key={i} className="flex items-start gap-1.5 text-[12px]" style={{ color: "#a3a3a3" }}>
                <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full" style={{ background: "#22c55e" }} />
                {rec}
              </li>
            ))}
          </ul>
        </section>

        {/* Executive Summary */}
        {report?.executive_summary && (
          <section className="p-4" style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}>
            <button onClick={() => setShowExec(!showExec)} className="flex w-full items-center justify-between text-left">
              <p className="text-[10px] font-medium uppercase tracking-widest" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>Executive Summary</p>
              {showExec ? <ChevronUp className="h-3.5 w-3.5" style={{ color: "#525252" }} /> : <ChevronDown className="h-3.5 w-3.5" style={{ color: "#525252" }} />}
            </button>
            {showExec && (
              <p className="mt-2 text-[12px] whitespace-pre-wrap" style={{ color: "#a3a3a3", lineHeight: 1.5 }}>
                {report.executive_summary}
              </p>
            )}
          </section>
        )}

        {/* AI Risk Narrative */}
        {scan.ai_narrative && scan.ai_narrative.summary && (
          <section className="p-4" style={{ background: "#111111", border: "1px solid #a855f730", borderRadius: "6px" }}>
            <p className="text-[10px] font-medium uppercase tracking-widest mb-2 flex items-center gap-1.5" style={{ color: "#a855f7", letterSpacing: "0.1em" }}>
              AI Risk Analysis
            </p>
            <p className="text-[13px] mb-2" style={{ color: "#e5e5e5", lineHeight: 1.6 }}>
              {scan.ai_narrative.summary}
            </p>
            <div className="flex items-center gap-3 text-[11px]">
              <span className="px-2 py-0.5 uppercase font-medium" style={{
                background: scan.ai_narrative.verdict === "reject" ? "rgba(239,68,68,0.15)" : scan.ai_narrative.verdict === "approve" ? "rgba(34,197,94,0.15)" : "rgba(234,179,8,0.15)",
                color: scan.ai_narrative.verdict === "reject" ? "#ef4444" : scan.ai_narrative.verdict === "approve" ? "#22c55e" : "#eab308",
                borderRadius: "2px",
              }}>
                {scan.ai_narrative.verdict}
              </span>
              <span style={{ color: "#525252" }}>Confidence: {scan.ai_narrative.confidence}</span>
            </div>
          </section>
        )}

        {/* AI Remediation */}
        {scan.ai_remediation && scan.ai_remediation.length > 0 && (
          <section>
            <p className="text-[10px] font-medium uppercase tracking-widest mb-2 flex items-center gap-1.5" style={{ color: "#22c55e", letterSpacing: "0.1em" }}>
              AI-Powered Remediation
            </p>
            <div className="space-y-1.5">
              {scan.ai_remediation.map((rem, i) => (
                <div key={i} className="p-3" style={{ background: "#111111", border: "1px solid #1a1a1a", borderRadius: "6px" }}>
                  <p className="text-[12px] font-medium mb-1.5" style={{ color: "#e5e5e5" }}>{rem.finding_title}</p>
                  <div className="p-2 mb-1.5 font-mono text-[11px]" style={{ background: "#0a0a0a", border: "1px solid #262626", borderRadius: "4px", color: "#22c55e" }}>
                    {rem.fix}
                  </div>
                  <p className="text-[11px]" style={{ color: "#a3a3a3", lineHeight: 1.5 }}>{rem.explanation}</p>
                  {rem.tradeoffs && rem.tradeoffs !== "None" && (
                    <p className="text-[10px] mt-1" style={{ color: "#525252" }}>Trade-offs: {rem.tradeoffs}</p>
                  )}
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Export */}
        {scan.status === "completed" && (
          <div className="flex flex-wrap gap-1.5">
            <button
              onClick={async () => {
                await navigator.clipboard.writeText(window.location.href);
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
              }}
              className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium transition-colors"
              style={{ border: "1px solid #262626", color: copied ? "#22c55e" : "#737373", borderRadius: "3px" }}
            >
              {copied ? <Check className="h-3 w-3" /> : <Share2 className="h-3 w-3" />} {copied ? "Copied!" : "Share"}
            </button>
            {[
              { fmt: "json", icon: FileJson, label: "JSON" },
              { fmt: "markdown", icon: FileCode, label: "Markdown" },
              { fmt: "text", icon: FileText, label: "Text" },
            ].map(({ fmt, icon: Icon, label }) => (
              <a
                key={fmt}
                href={`/api/v1/report/${id}/export?format=${fmt}`}
                className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium transition-colors"
                style={{ border: "1px solid #262626", color: "#737373", borderRadius: "3px" }}
              >
                <Icon className="h-3 w-3" /> {label}
              </a>
            ))}
          </div>
        )}
      </div>

      <ConfirmModal
        open={confirmDelete}
        title="Delete scan"
        message="This scan and all its findings will be permanently deleted. This cannot be undone."
        confirmLabel="Delete"
        onConfirm={handleDelete}
        onCancel={() => setConfirmDelete(false)}
      />
    </div>
  );
}

function SummaryCard({ icon, value, label, color, pulse }: {
  icon: React.ReactNode; value: number; label: string; color: string; pulse?: boolean;
}) {
  return (
    <div
      className="p-3 text-center"
      style={{
        background: "#111111",
        border: pulse ? "1px solid rgba(239,68,68,0.3)" : "1px solid #1a1a1a",
        borderRadius: "6px",
      }}
    >
      <div className="mb-1.5 flex justify-center opacity-60" style={{ color }}>{icon}</div>
      <p className="text-lg font-bold tabular-nums" style={{ color }}>{value}</p>
      <p className="text-[10px] mt-0.5" style={{ color: "#525252" }}>{label}</p>
    </div>
  );
}
