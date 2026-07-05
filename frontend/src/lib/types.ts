export type TargetType = "mcp_server" | "agent_skill" | "npm_package" | "pypi_package";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type RiskLevel = "critical" | "high" | "medium" | "low" | "safe";

export type ScanStatus = "pending" | "running" | "completed" | "failed";

export interface ScanRequest {
  target_type: TargetType;
  target: string;
  options?: {
    deep?: boolean;
    timeout?: number;
    inline_content?: string;
    ai_api_key?: string;
    ai_model?: string;
  };
  rescan_of?: string;
}

export interface Finding {
  id: string;
  category: string;
  severity: Severity;
  title: string;
  description: string;
  evidence: string;
  remediation: string;
  cwe: string | null;
  owasp: string | null;
  references: string[];
}

export interface ScanMeta {
  scan_duration_ms: number;
  files_analyzed: number;
  urls_checked: number;
  deps_analyzed: number;
}

export interface ScanResponse {
  scan_id: string;
  status: ScanStatus;
  target: string;
  target_type: TargetType;
  overall_risk: number;
  risk_level: RiskLevel;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  findings: Finding[];
  metadata: ScanMeta;
  created_at: string;
  content_changed?: boolean;
  rescan_of?: string;
  ai_attack_scenarios?: AIAttackScenario[];
  ai_remediation?: AIRemediation[];
  ai_narrative?: AINarrative;
  ai_threat_intel?: AIThreatIntel[];
}

export interface AIAttackScenario {
  title: string;
  vector: string;
  impact: string;
  steps: string[];
  severity: Severity;
  related_finding: string;
}

export interface AIRemediation {
  finding_title: string;
  fix: string;
  explanation: string;
  tradeoffs: string;
}

export interface AINarrative {
  summary: string;
  verdict: string;
  confidence: string;
}

export interface AIThreatIntel {
  category: string;
  cves: string[];
  campaigns: string[];
  mitre_techniques: string[];
}

export interface PaginatedScans {
  scans: ScanResponse[];
  total: number;
  page: number;
  limit: number;
  pages?: number;
}

export interface StatsResponse {
  total_scans: number;
  risk_distribution: Record<RiskLevel, number>;
  recent_scans: ScanResponse[];
}

// --- Report types ---

export interface AttackScenario {
  category: string;
  severity: Severity;
  finding: string;
  attack_vector: string;
}

export interface FullReport {
  json: {
    report: Record<string, string>;
    scan_overview: Record<string, unknown>;
    scores: {
      risk_score: { value: number; label: string; scale: string };
      trust_score: { value: number; label: string; scale: string };
    };
    findings_summary: {
      total: number;
      by_severity: Record<string, number>;
    };
    findings: Record<string, Finding[]>;
    recommendations: string[];
    attack_simulation: {
      description: string;
      scenarios: AttackScenario[];
    };
  };
  security_summary: string;
  executive_summary: string;
}
