// Mirrors the backend response schemas frozen in Section 6 of the master plan.
// Field names here must never drift from what Backend actually returns.

export interface User {
  id: string;
  email: string;
  name?: string;
}

export interface AuthResponse {
  token: string;
  user: User;
}

export type InvestigationStatus = "queued" | "processing" | "complete" | "failed";

export interface CreateInvestigationResponse {
  investigationId: string;
  status: InvestigationStatus;
}

export type Verdict = "phishing" | "suspicious" | "safe";

export interface Entity {
  type: "url" | "ip" | "domain";
  value: string;
}

export interface AiResult {
  phishingScore: number; // 0-100
  verdict: Verdict;
  explanation: string;
  entities: Entity[];
}

export interface ThreatResult {
  type: "ip" | "url";
  value: string;
  reputation: "clean" | "suspicious" | "malicious";
  geo?: { country?: string; city?: string; lat?: number; lon?: number };
  malicious: boolean;
}

export interface Investigation {
  id: string;
  status: InvestigationStatus;
  sender: string;
  subject: string;
  receivedAt: string;
  aiResult: AiResult | null;
  threatResults: ThreatResult[];
  mapUrl: string | null;
  timelineUrl: string | null;
  graphUrl: string | null;
  reportUrl: string | null;
}

export interface GeoFeature {
  type: "Feature";
  geometry:
    | { type: "Point"; coordinates: [number, number] }
    | { type: "LineString"; coordinates: [number, number][] };
  properties: Record<string, unknown>;
}

export interface GeoJSON {
  type: "FeatureCollection";
  features: GeoFeature[];
}

export interface TimelineStep {
  step: number;
  server: string;
  ip: string;
  timestamp: string;
  malicious?: boolean;
}

export interface GraphNode {
  id: string;
  label: string;
  type: "sender" | "relay" | "recipient";
  malicious?: boolean;
}

export interface GraphEdge {
  from: string;
  to: string;
}

export interface AttackGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}
