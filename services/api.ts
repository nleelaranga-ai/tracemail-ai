// The ONLY file that talks to the network. Every component/hook goes through here.
// Per Definition of Done: zero direct calls to third-party services from frontend —
// all telemetry flows through the backend gateway microservice.
import type {
  AttackGraph,
  AuthResponse,
  CreateInvestigationResponse,
  GeoJSON,
  Investigation,
  TimelineStep,
  SocOverview,
  DepartmentMetric,
  InboxEmailItem,
  EvidenceRecordItem,
  ExplainabilityResponse,
  GraphNodeDetail,
  AttachmentScanResponse
} from "@/types";
import {
  MOCK_INVESTIGATIONS,
  getMockGeo,
  getMockGraph,
  getMockTimeline
} from "./mockData";

function sanitizeApiBase(raw?: string): string {
  if (!raw) return "";
  let url = String(raw).trim().replace(/^["']|["']$/g, "").replace(/\/+$/, "");
  if (!url) return "";
  if (!url.startsWith("http://") && !url.startsWith("https://") && !url.startsWith("/")) {
    url = `https://${url}`;
  }
  return url;
}

const rawBase = typeof process !== "undefined" ? process.env?.NEXT_PUBLIC_API_URL : undefined;
export const BASE_URL =
  rawBase !== undefined ? sanitizeApiBase(rawBase) : "https://tracemail-ai-production.up.railway.app";

export const USE_MOCKS = process.env.NEXT_PUBLIC_USE_MOCKS === "true";

export const apiUrl = (path: string) => {
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  if (!BASE_URL) return cleanPath;
  return `${BASE_URL}${cleanPath}`;
};

function authHeaders(): HeadersInit {
  if (typeof window === "undefined") return {};
  const token = window.localStorage.getItem("tm_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const url = apiUrl(path);
  const res = await fetch(url, {
    ...init,
    headers: { "Content-Type": "application/json", ...authHeaders(), ...(init?.headers || {}) }
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API ${path} failed (${res.status}): ${body}`);
  }
  return res.json() as Promise<T>;
}

function delay<T>(value: T, ms = 500): Promise<T> {
  return new Promise((resolve) => setTimeout(() => resolve(value), ms));
}

export const api = {
  async login(email: string, password: string): Promise<AuthResponse> {
    if (USE_MOCKS) {
      if (!email || password.length < 6) {
        throw new Error("Enter a valid email and a password of at least 6 characters.");
      }
      return delay({ token: "mock-jwt-token", user: { id: "u1", email, name: email.split("@")[0] } });
    }
    try {
      return await request<AuthResponse>("/api/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
    } catch (err) {
      console.error("Backend login failed:", err);
      throw err;
    }
  },

  async register(email: string, password: string): Promise<AuthResponse> {
    if (USE_MOCKS) {
      if (!email || password.length < 6) {
        throw new Error("Enter a valid email and a password of at least 6 characters.");
      }
      return delay({ token: "mock-jwt-token", user: { id: "u1", email, name: email.split("@")[0] } });
    }
    try {
      return await request<AuthResponse>("/api/auth/register", { method: "POST", body: JSON.stringify({ email, password }) });
    } catch (err) {
      console.error("Backend registration failed:", err);
      throw err;
    }
  },

  async listInvestigations(): Promise<Investigation[]> {
    if (USE_MOCKS) return delay(MOCK_INVESTIGATIONS, 300);
    try {
      return await request<Investigation[]>("/api/investigations");
    } catch (err) {
      console.error("Backend investigation history failed:", err);
      throw err;
    }
  },

  async createInvestigation(file: File): Promise<CreateInvestigationResponse> {
    if (USE_MOCKS) {
      const isInternshala = file.name.toLowerCase().includes("internshala");
      const mockId = isInternshala ? "inv-1039" : MOCK_INVESTIGATIONS[0].id;
      return delay({ investigationId: mockId, status: "complete" }, 1200);
    }
    const form = new FormData();
    form.append("file", file);
    try {
      const res = await fetch(apiUrl("/api/investigations"), {
        method: "POST",
        headers: { ...authHeaders() },
        body: form
      });
      if (!res.ok) {
        const errText = await res.text().catch(() => "");
        throw new Error(`Upload failed (${res.status}): ${errText || res.statusText}`);
      }
      return await res.json();
    } catch (err) {
      console.error("Backend upload failed:", err);
      throw err;
    }
  },

  async getInvestigation(id: string): Promise<Investigation> {
    if (USE_MOCKS) {
      const found = MOCK_INVESTIGATIONS.find((i) => i.id === id) || MOCK_INVESTIGATIONS[0];
      return delay(found, 400);
    }
    try {
      return await request<Investigation>(`/api/investigations/${id}`);
    } catch (err) {
      console.error(`Backend getInvestigation(${id}) failed:`, err);
      throw err;
    }
  },

  async getMap(id: string): Promise<GeoJSON> {
    if (USE_MOCKS) {
      const inv = MOCK_INVESTIGATIONS.find((i) => i.id === id);
      return delay(getMockGeo(id, inv), 300);
    }
    try {
      return await request<GeoJSON>(`/api/geo/map/${id}`);
    } catch (err) {
      console.error(`Backend map request failed for ${id}:`, err);
      throw err;
    }
  },

  async getInvestigationMap(id: string): Promise<any> {
    try {
      return await request<any>(`/maps/investigation/${id}`);
    } catch (err) {
      console.error(`Backend OSM investigation map request failed for ${id}:`, err);
      return null;
    }
  },

  async getIpLocation(ip: string): Promise<any> {
    return await request<any>(`/maps/location/${encodeURIComponent(ip)}`);
  },

  async geocode(q: string): Promise<any> {
    return await request<any>(`/maps/geocode?q=${encodeURIComponent(q)}`);
  },

  async reverseGeocode(lat: number, lon: number): Promise<any> {
    return await request<any>(`/maps/reverse?lat=${lat}&lon=${lon}`);
  },

  async getRoute(coords: string): Promise<any> {
    return await request<any>(`/maps/route?coords=${encodeURIComponent(coords)}`);
  },

  async getPlaces(lat: number, lon: number, radius = 5000): Promise<any> {
    return await request<any>(`/maps/places?lat=${lat}&lon=${lon}&radius=${radius}`);
  },

  async getTimeline(id: string): Promise<TimelineStep[]> {
    if (USE_MOCKS) {
      const inv = MOCK_INVESTIGATIONS.find((i) => i.id === id);
      return delay(getMockTimeline(id, inv), 300);
    }
    try {
      return await request<TimelineStep[]>(`/api/geo/timeline/${id}`);
    } catch (err) {
      console.error(`Backend timeline request failed for ${id}:`, err);
      throw err;
    }
  },

  async getGraph(id: string): Promise<AttackGraph> {
    if (USE_MOCKS) {
      const inv = MOCK_INVESTIGATIONS.find((i) => i.id === id);
      return delay(getMockGraph(id, inv), 300);
    }
    try {
      return await request<AttackGraph>(`/api/geo/graph/${id}`);
    } catch (err) {
      console.error(`Backend graph request failed for ${id}:`, err);
      throw err;
    }
  },

  async downloadReport(id: string, format: "pdf" | "html" | "json" = "pdf"): Promise<Blob> {
    if (USE_MOCKS) {
      if (format === "html") {
        const html = `<!DOCTYPE html><html><head><title>TraceMail AI Report ${id}</title><style>body{background:#0b1120;color:#e2e8f0;font-family:sans-serif;padding:24px;}</style></head><body><h1>TraceMail AI — Forensic Report</h1><p>Case: ${id}</p><p>Status: Complete</p></body></html>`;
        return delay(new Blob([html], { type: "text/html" }), 400);
      }
      if (format === "json") {
        const json = JSON.stringify({ report_metadata: { investigation_id: id, platform: "TraceMail AI", version: "1.0.0" } }, null, 2);
        return delay(new Blob([json], { type: "application/json" }), 400);
      }
      const text = `TraceMail AI — Forensic Report\nInvestigation: ${id}\nGenerated: ${new Date().toISOString()}\n\n(Mock report — real PDF produced by Reports Engine)`;
      return delay(new Blob([text], { type: "application/pdf" }), 600);
    }
    const endpoint = format === "html" ? `/api/report/html/${id}` : format === "json" ? `/api/report/json/${id}` : `/api/report/pdf/${id}`;
    try {
      const res = await fetch(apiUrl(endpoint), { headers: { ...authHeaders() } });
      if (!res.ok) throw new Error(`Report download failed (${res.status})`);
      return await res.blob();
    } catch (err) {
      console.error(`Backend report request failed for ${id}:`, err);
      throw err;
    }
  },

  // --- Master Plan v2 Client API Methods ---

  async getSocOverview(): Promise<SocOverview> {
    return await request<SocOverview>("/api/soc/overview");
  },

  async getOrgHeatmap(): Promise<DepartmentMetric[]> {
    return await request<DepartmentMetric[]>("/api/org/heatmap");
  },

  async getInboxResults(email?: string): Promise<InboxEmailItem[]> {
    const q = email ? `?email=${encodeURIComponent(email)}` : "";
    return await request<InboxEmailItem[]>(`/api/inbox/results${q}`);
  },

  async scanInbox(email?: string): Promise<any> {
    const q = email ? `?email=${encodeURIComponent(email)}` : "";
    return await request<any>(`/api/inbox/scan${q}`, { method: "POST" });
  },

  async getGoogleLoginUrl(): Promise<{ authUrl: string; configured?: boolean; provider?: string }> {
    return await request<{ authUrl: string; configured?: boolean; provider?: string }>("/api/auth/google/login");
  },

  async connectGoogleInbox(email: string): Promise<any> {
    return await request<any>(`/api/auth/google/callback?email=${encodeURIComponent(email)}`);
  },

  async connectGoogleInboxWithCode(code: string): Promise<any> {
    return await request<any>(`/api/auth/google/callback?code=${encodeURIComponent(code)}`);
  },

  async getGoogleInboxStatus(email?: string): Promise<{ connected: boolean; email: string; mode: string; client_configured: boolean; last_scanned_at: string | null }> {
    const q = email ? `?email=${encodeURIComponent(email)}` : "";
    return await request<any>(`/api/auth/google/status${q}`);
  },

  async disconnectGoogleInbox(email?: string): Promise<any> {
    const q = email ? `?email=${encodeURIComponent(email)}` : "";
    return await request<any>(`/api/auth/google/disconnect${q}`, { method: "POST" });
  },

  async listEvidence(): Promise<EvidenceRecordItem[]> {
    return await request<EvidenceRecordItem[]>("/api/evidence");
  },

  async getEvidence(investigationId: string): Promise<EvidenceRecordItem> {
    return await request<EvidenceRecordItem>(`/api/evidence/${investigationId}`);
  },

  async verifyEvidence(investigationId: string, simulatedCorrupt = false): Promise<any> {
    const q = simulatedCorrupt ? "?simulated_corrupt=true" : "";
    return await request<any>(`/api/evidence/${investigationId}/verify${q}`, { method: "POST" });
  },

  async getExplainability(investigationId: string): Promise<ExplainabilityResponse> {
    return await request<ExplainabilityResponse>(`/api/ai/explainability/${investigationId}`);
  },

  async getNodeDetail(nodeId: string): Promise<GraphNodeDetail> {
    return await request<GraphNodeDetail>(`/api/graph/node/${encodeURIComponent(nodeId)}`);
  },

  async scanAttachment(filename: string, sha256?: string): Promise<AttachmentScanResponse> {
    return await request<AttachmentScanResponse>("/api/threat/attachment", {
      method: "POST",
      body: JSON.stringify({ filename, sha256 })
    });
  },

  async listCampaigns(): Promise<any[]> {
    return await request<any[]>("/api/campaigns");
  },

  async getCampaignDetail(id: string): Promise<any> {
    return await request<any>(`/api/campaigns/${id}`);
  },

  async getCompositeThreatIntel(payload: { ip?: string; domain?: string; urls?: string[]; rawHeaders?: string; attachments?: any[] }): Promise<any> {
    return await request<any>("/api/threat/composite-intel", {
      method: "POST",
      body: JSON.stringify(payload)
    });
  },

  isMockMode: USE_MOCKS
};
