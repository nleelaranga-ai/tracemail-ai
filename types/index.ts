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
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  is_malicious?: boolean;
  reputation?: number;
  scan_date?: string;
  permalink?: string;
  mode?: string;
  provider_status?: string;
  fallback_used?: boolean;
}

export interface AbuseIPDBSummary {
  abuse_confidence_score?: number;
  abuse_score?: number;
  confidence_score?: number;
  total_reports?: number;
  is_whitelisted?: boolean;
  is_malicious?: boolean;
  last_reported_at?: string;
  mode?: string;
  provider_status?: string;
  fallback_used?: boolean;
}

export interface WHOISSummary {
  domain?: string;
  name?: string;
  registrar?: string;
  creation_date?: string;
  domain_age_days?: number | null;
  age_days?: number | null;
  registrant_country?: string;
  mode?: string;
  provider_status?: string;
  fallback_used?: boolean;
}

export interface DNSSummary {
  spf?: string;
  dkim?: string;
  dmarc?: string;
  mx_records?: string[];
  mode?: string;
  provider_status?: string;
  fallback_used?: boolean;
}

export interface URLScanSummary {
  malicious?: boolean;
  is_malicious?: boolean;
  score?: number;
  verdict?: string;
  page_title?: string;
  screenshot_url?: string;
  mode?: string;
  provider_status?: string;
  fallback_used?: boolean;
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
  mode?: string;
  provider_status?: string;
  fallback_used?: boolean;
}

export interface GoogleSafeBrowsingSummary {
  is_malicious?: boolean;
  threat_types?: string[];
  matches_count?: number;
  provider?: string;
  mode?: string;
  provider_status?: string;
  fallback_used?: boolean;
}

export interface ThreatIntelBundle {
  virustotal?: VirusTotalSummary;
  abuseipdb?: AbuseIPDBSummary;
  whois?: WHOISSummary;
  dns?: DNSSummary;
  urlscan?: URLScanSummary;
  google_safe_browsing?: GoogleSafeBrowsingSummary;
  geoip?: GeoIPSummary;
  mode?: "live" | "fallback";
  fallback_used?: boolean;
  provider_statuses?: Record<string, string>;
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
  event?: string;
  time?: string;
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
  explanation?: string;
  ai_summary?: string;
  timeline?: DynamicTimelineStep[];
  iocs?: IOCChipItem[];
  entities?: Entity[] | { urls?: string[]; ips?: string[]; domains?: string[] };
  auth_results?: { spf?: string; dkim?: string; dmarc?: string };
  action_items?: string[];
  evidence_hash?: string;
  attack_graph?: {
    nodes: Array<{ id: string; label: string; type: "sender" | "smtp" | "domain" | "ip" | "url" | "attachment"; risk?: string; details?: Record<string, any> }>;
    edges: Array<{ source: string; target: string; label?: string }>;
  };
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


// --- Master Plan v2 Types (SIH 26106) ---

export interface SocAlertItem {
  id: string;
  subject: string;
  sender: string;
  verdict: string;
  score: number;
  riskLevel: string;
  timestamp: string;
}

export interface SocOverview {
  totalScanned: number;
  phishingDetected: number;
  safeEmails: number;
  suspiciousEmails: number;
  criticalThreats: number;
  riskDistribution: {
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
  };
  topCountries: { country: string; count: number }[];
  topBrands: { brand: string; count: number }[];
  topDomains: { domain: string; count: number }[];
  recentAlerts: SocAlertItem[];
}

export interface DepartmentMetric {
  department: string;
  threatCount: number;
  phishingCount: number;
  safeCount: number;
  riskLevel: "Critical" | "High" | "Medium" | "Low";
  vulnerabilityScore: number;
  topAttackType: string;
  lastAttack: string;
  primaryTarget: string;
}

export interface InboxEmailItem {
  id: string;
  messageId: string;
  sender: string;
  subject: string;
  snippet?: string;
  risk: "Safe" | "Suspicious" | "Critical";
  threatScore: number;
  verdict: string;
  scannedAt: string;
}

export interface CustodyLogEvent {
  step: number;
  action: string;
  timestamp: string;
  actor: string;
  hash: string;
  verified: boolean;
}

export interface EvidenceRecordItem {
  id: string;
  investigationId: string;
  sha256: string;
  originalHash: string;
  investigator: string;
  status: "Verified" | "Tampered" | "Exported";
  subject?: string;
  sender?: string;
  createdAt: string;
  verifiedAt: string;
  custodyLog: CustodyLogEvent[];
}

export interface ExplainabilityReason {
  label: string;
  weight: number;
  category: string;
  description: string;
}

export interface ExplainabilityResponse {
  investigationId: string;
  score: number;
  confidence: number;
  verdict: string;
  summary: string;
  reasons: ExplainabilityReason[];
}

export interface GraphNodeDetail {
  nodeId: string;
  type: string;
  label: string;
  reputation: "clean" | "suspicious" | "malicious";
  abuseScore: number;
  verdict: string;
  country: string;
  city: string;
  asn: string;
  whois: {
    registrar: string;
    creationDate: string;
    registrantCountry: string;
  };
  timeline: { step: number; action: string; time: string }[];
}

export interface AttachmentScanResponse {
  filename: string;
  sha256: string;
  fileType: string;
  malicious: boolean;
  verdict: string;
  engine: string;
  positives: number;
  totalEngines: number;
}
