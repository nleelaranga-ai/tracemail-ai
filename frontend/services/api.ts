// The ONLY file that talks to the network. Every component/hook goes through here.
// Per Definition of Done (Section 9.1): zero direct calls to AI/Threat-Intel/Maps/Reports —
// backend only, and everything must work against mock data before the backend is live.
import type {
  AttackGraph,
  AuthResponse,
  CreateInvestigationResponse,
  GeoJSON,
  Investigation,
  TimelineStep
} from "@/types";
import {
  MOCK_INVESTIGATIONS,
  getMockGeo,
  getMockGraph,
  getMockTimeline
} from "./mockData";

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "";
const USE_MOCKS = BASE_URL.length === 0;

function authHeaders(): HeadersInit {
  if (typeof window === "undefined") return {};
  const token = window.localStorage.getItem("tm_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
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
    return request<AuthResponse>("/api/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
  },

  async register(email: string, password: string): Promise<AuthResponse> {
    if (USE_MOCKS) {
      if (!email || password.length < 6) {
        throw new Error("Enter a valid email and a password of at least 6 characters.");
      }
      return delay({ token: "mock-jwt-token", user: { id: "u1", email, name: email.split("@")[0] } });
    }
    return request<AuthResponse>("/api/auth/register", { method: "POST", body: JSON.stringify({ email, password }) });
  },

  async listInvestigations(): Promise<Investigation[]> {
    if (USE_MOCKS) return delay(MOCK_INVESTIGATIONS, 300);
    return request<Investigation[]>("/api/investigations");
  },

  async createInvestigation(file: File): Promise<CreateInvestigationResponse> {
    if (USE_MOCKS) {
      return delay({ investigationId: MOCK_INVESTIGATIONS[0].id, status: "complete" }, 1200);
    }
    const form = new FormData();
    form.append("file", file);
    const res = await fetch(`${BASE_URL}/api/investigations`, {
      method: "POST",
      headers: { ...authHeaders() },
      body: form
    });
    if (!res.ok) throw new Error(`Upload failed (${res.status})`);
    return res.json();
  },

  async getInvestigation(id: string): Promise<Investigation> {
    if (USE_MOCKS) {
      const found = MOCK_INVESTIGATIONS.find((i) => i.id === id) || MOCK_INVESTIGATIONS[0];
      return delay(found, 400);
    }
    return request<Investigation>(`/api/investigations/${id}`);
  },

  async getMap(id: string): Promise<GeoJSON> {
    if (USE_MOCKS) {
      const inv = MOCK_INVESTIGATIONS.find((i) => i.id === id);
      return delay(getMockGeo(id, inv), 300);
    }
    return request<GeoJSON>(`/api/geo/map/${id}`);
  },

  async getTimeline(id: string): Promise<TimelineStep[]> {
    if (USE_MOCKS) {
      const inv = MOCK_INVESTIGATIONS.find((i) => i.id === id);
      return delay(getMockTimeline(id, inv), 300);
    }
    return request<TimelineStep[]>(`/api/geo/timeline/${id}`);
  },

  async getGraph(id: string): Promise<AttackGraph> {
    if (USE_MOCKS) {
      const inv = MOCK_INVESTIGATIONS.find((i) => i.id === id);
      return delay(getMockGraph(id, inv), 300);
    }
    return request<AttackGraph>(`/api/geo/graph/${id}`);
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
    const res = await fetch(`${BASE_URL}${endpoint}`, { headers: { ...authHeaders() } });
    if (!res.ok) throw new Error(`Report download failed (${res.status})`);
    return res.blob();
  },

  isMockMode: USE_MOCKS
};
