import type {
  ScanRequest,
  ScanResponse,
  PaginatedScans,
  StatsResponse,
  FullReport,
} from "./types";

const BASE = `${process.env.NEXT_PUBLIC_API_URL ?? ""}/api/v1`;

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

export function rescanScan(id: string): Promise<{ scan_id: string; status: string; rescan_of: string }> {
  return request(`/scan/${id}/rescan`, { method: "POST" });
}

export interface ContentChange {
  url: string;
  old_hash: string | null;
  new_hash: string | null;
  status: "changed" | "added" | "removed";
}

export interface ContentChangesResponse {
  scan_id: string;
  rescan_of: string;
  changes: ContentChange[];
  total_changes: number;
  has_changes: boolean;
}

export function fetchContentChanges(id: string): Promise<ContentChangesResponse> {
  return request(`/scan/${id}/changes`);
}
