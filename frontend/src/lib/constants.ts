export const TYPE_LABELS: Record<string, string> = {
  mcp_server: "MCP Server",
  agent_skill: "Agent Skill",
  npm_package: "npm Package",
  pypi_package: "PyPI Package",
};

export const SEVERITY_COLORS: Record<string, { bg: string; text: string }> = {
  critical: { bg: "rgba(239,68,68,0.1)", text: "#ef4444" },
  high: { bg: "rgba(249,115,22,0.1)", text: "#f97316" },
  medium: { bg: "rgba(234,179,8,0.1)", text: "#eab308" },
  low: { bg: "rgba(34,197,94,0.1)", text: "#22c55e" },
  info: { bg: "rgba(115,115,115,0.1)", text: "#737373" },
  safe: { bg: "rgba(34,197,94,0.1)", text: "#22c55e" },
};

export const RISK_COLORS: Record<string, { bg: string; text: string }> = {
  critical: { bg: "rgba(239,68,68,0.1)", text: "#ef4444" },
  high: { bg: "rgba(249,115,22,0.1)", text: "#f97316" },
  medium: { bg: "rgba(234,179,8,0.1)", text: "#eab308" },
  low: { bg: "rgba(34,197,94,0.1)", text: "#22c55e" },
  safe: { bg: "rgba(34,197,94,0.1)", text: "#22c55e" },
};

export const STATUS_COLORS: Record<string, { bg: string; text: string }> = {
  completed: { bg: "rgba(34,197,94,0.1)", text: "#22c55e" },
  failed: { bg: "rgba(239,68,68,0.1)", text: "#ef4444" },
  pending: { bg: "rgba(234,179,8,0.1)", text: "#eab308" },
  running: { bg: "rgba(59,130,246,0.1)", text: "#3b82f6" },
};

export const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
