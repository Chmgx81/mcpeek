import type {
  ScanRequest,
  ScanResponse,
  PaginatedScans,
  StatsResponse,
  FullReport,
} from "./types";

const BASE = "/api/v1";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${body || res.statusText}`);
  }
  return res.json();
}

export function submitScan(data: ScanRequest): Promise<ScanResponse> {
  return request<ScanResponse>("/scan", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export function fetchScan(id: string): Promise<ScanResponse> {
  return request<ScanResponse>(`/scan/${id}`);
}

export function fetchScans(
  page = 1,
  limit = 20
): Promise<PaginatedScans> {
  return request<PaginatedScans>(`/scans?page=${page}&limit=${limit}`);
}

export function fetchStats(): Promise<StatsResponse> {
  return request<StatsResponse>("/stats");
}

export function fetchHealth(): Promise<{ status: string }> {
  return request<{ status: string }>("/health");
}

export function fetchFullReport(id: string): Promise<FullReport> {
  return request<FullReport>(`/report/${id}/full`);
}

export function fetchReport(
  id: string,
  format: "json" | "text" | "markdown"
): Promise<{ format: string; content: string | object }> {
  return request(`/report/${id}/export?format=${format}`);
}
