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

export interface VirusTotalSummary {
  positives?: number;
  total_engines?: number;
  reputation?: number;
  scan_date?: string;
  permalink?: string;
}

export interface AbuseIPDBSummary {
  abuse_confidence_score?: number;
  total_reports?: number;
  is_whitelisted?: boolean;
  last_reported_at?: string;
}

export interface WHOISSummary {
  domain?: string;
  registrar?: string;
  creation_date?: string;
  domain_age_days?: number | null;
  registrant_country?: string;
}

export interface DNSSummary {
  spf?: string;
  dkim?: string;
  dmarc?: string;
  mx_records?: string[];
}

export interface URLScanSummary {
  malicious?: boolean;
  score?: number;
  verdicts?: {
    overall?: {
      malicious?: boolean;
      score?: number;
      categories?: string[];
    };
  };
}

export interface GeoIPSummary {
  ip?: string;
  country?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  isp?: string;
  asn?: string;
}

export interface ThreatIntelBundle {
  virustotal?: VirusTotalSummary;
  abuseipdb?: AbuseIPDBSummary;
  whois?: WHOISSummary;
  dns?: DNSSummary;
  urlscan?: URLScanSummary;
  geoip?: GeoIPSummary;
}

export interface AIAnalysisSummary {
  prediction: "phishing" | "suspicious" | "safe";
  confidence: number;
  summary: string;
  reasons: string[];
}

export interface DynamicTimelineStep {
  step: number;
  name: string;
  detail: string;
  status: "completed" | "in_progress" | "pending" | "failed";
  timestamp?: string;
}

export interface IOCChipItem {
  type: "url" | "ip" | "domain" | "hash" | "attachment";
  value: string;
  malicious: boolean;
  category?: string;
}

export interface Investigation {
  id: string;
  status: InvestigationStatus;
  sender: string;
  recipient?: string;
  subject: string;
  receivedAt: string;
  aiResult: AiResult | null;
  verdict?: Verdict;
  phishingScore?: number;
  threatResults: ThreatResult[];
  mapUrl: string | null;
  timelineUrl: string | null;
  graphUrl: string | null;
  reportUrl: string | null;

  // Dynamic Unified Intelligence Properties
  threat_score?: number;
  threatScore?: number;
  risk_level?: "Low" | "Medium" | "High" | "Critical";
  riskLevel?: "Low" | "Medium" | "High" | "Critical";
  origin_ip?: string;
  origin_city?: string;
  origin_country?: string;
  ip?: string;
  city?: string;
  country?: string;
  latitude?: number;
  longitude?: number;
  threat_intel?: ThreatIntelBundle;
  threatIntel?: ThreatIntelBundle;
  ai_analysis?: AIAnalysisSummary;
  aiAnalysis?: AIAnalysisSummary;
  timeline?: DynamicTimelineStep[];
  iocs?: IOCChipItem[];
  entities?: Entity[] | { urls?: string[]; ips?: string[]; domains?: string[] };
  auth_results?: { spf?: string; dkim?: string; dmarc?: string };
  action_items?: string[];
  evidence_hash?: string;
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
