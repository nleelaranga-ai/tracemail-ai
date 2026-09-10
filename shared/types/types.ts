/**
 * TraceMail AI — TypeScript Contract Definitions
 * Shared types for Frontend Team mirroring Backend & Threat Intelligence API responses.
 * Based on Section 6 Master API Contracts.
 */

export type RiskLevel = 'SAFE' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL';
export type AuthVerdict = 'pass' | 'fail' | 'none' | 'softfail';
export type InvestigationStatus = 'queued' | 'processing' | 'completed' | 'failed';
export type ThreatCategory = 'phishing' | 'malware' | 'spoofing' | 'bec' | 'suspicious' | 'clean';

export interface IPThreatResponse {
  ip: string;
  country: string;
  city: string;
  lat: number;
  lon: number;
  isp: string;
  asn: string;
  abuseScore: number; // 0-100 from AbuseIPDB
  malicious: boolean;
}

export interface URLThreatRequest {
  url: string;
}

export interface URLThreatResponse {
  url: string;
  malicious: boolean;
  category: string;
  scanDate: string;
  vtPositives: number;
  vtTotal: number;
}

export interface AuthCheckRequest {
  rawHeaders: string;
}

export interface AuthCheckResponse {
  spf: AuthVerdict;
  dkim: AuthVerdict;
  dmarc: AuthVerdict;
  domainAge: string; // e.g. "14 days"
  registrar: string; // e.g. "NameCheap Inc."
}

export interface UnifiedThreatReport {
  risk_level: RiskLevel;
  risk_score: number; // 0-100
  malicious_url: boolean;
  domain_age_days: number;
  ip_reputation: number; // 0-100
  country: string;
  spf: string;
  dkim: string;
  dmarc: string;
}

export interface AIEntities {
  urls: string[];
  ips: string[];
  domains: string[];
  senderClaim?: string;
  senderActual?: string;
}

export interface AIPhishingResponse {
  phishingScore: number; // 0-100
  verdict: 'phishing' | 'suspicious' | 'safe';
  explanation: string;
  entities: AIEntities;
}

export interface GeoPointFeature {
  type: 'Feature';
  geometry: {
    type: 'Point';
    coordinates: [number, number]; // [lon, lat]
  };
  properties: {
    hop: number;
    ip: string;
    city: string;
    malicious: boolean;
  };
}

export interface GeoLineFeature {
  type: 'Feature';
  geometry: {
    type: 'LineString';
    coordinates: [number, number][]; // [[lon, lat], ...]
  };
  properties: {
    from: string;
    to: string;
  };
}

export interface GeoJSONMapResponse {
  type: 'FeatureCollection';
  features: (GeoPointFeature | GeoLineFeature)[];
}

export interface TimelineEvent {
  step: number;
  server: string;
  ip: string;
  timestamp: string;
  malicious: boolean;
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'sender' | 'relay' | 'recipient';
  malicious?: boolean;
}

export interface GraphEdge {
  from: string;
  to: string;
}

export interface AttackGraphResponse {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface InvestigationDetailResponse {
  id: string;
  status: InvestigationStatus;
  sender: string;
  subject: string;
  receivedAt: string;
  aiResult?: AIPhishingResponse;
  threatResults: (IPThreatResponse | URLThreatResponse)[];
  mapUrl?: string;
  timelineUrl?: string;
  graphUrl?: string;
  reportUrl?: string;
}

export interface InvestigationTimelineStep {
  time: string;
  event: string;
}

export interface IOCItem {
  type: 'url' | 'ip' | 'domain' | 'hash' | 'attachment';
  value: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface VirusTotalSummary {
  malicious_vendors: number;
  total_vendors: number;
  scan_date: string;
  positives: number;
}

export interface AbuseIPDBSummary {
  confidence_score: number;
  isp: string;
  total_reports: number;
  is_malicious: boolean;
}

export interface WHOISSummary {
  registrar: string;
  created_date: string;
  expiry_date: string;
  domain_age: string;
  domain_age_days: number;
}

export interface DNSSummary {
  spf: string;
  dkim: string;
  dmarc: string;
}

export interface URLScanSummary {
  verdict: string;
  score: number;
  page_title: string;
  screenshot_url?: string | null;
  technologies: string[];
}

export interface AIAnalysisSummary {
  prediction: string;
  confidence: number;
  summary: string;
  reasons: string[];
}

export interface UnifiedInvestigationResponse {
  scan_id: string;
  sender: string;
  domain: string;
  ip: string;
  country: string;
  city: string;
  latitude: number;
  longitude: number;
  threat_score: number;
  risk_level: 'Low' | 'Medium' | 'High' | 'Critical';
  ai_summary: string;
  timeline: InvestigationTimelineStep[];
  virus_total: VirusTotalSummary;
  abuse_ipdb: AbuseIPDBSummary;
  whois: WHOISSummary;
  dns: DNSSummary;
  urlscan: URLScanSummary;
  ai_analysis: AIAnalysisSummary;
  ioc: IOCItem[];

  // Aliases for compatibility
  id?: string;
  investigationId?: string;
  status?: string;
  recipient?: string;
  subject?: string;
  receivedAt?: string;
  phishingScore?: number;
  verdict?: string;
  explanation?: string;
  aiResult?: any;
  threatResults?: any[];
  mapUrl?: string;
  timelineUrl?: string;
  graphUrl?: string;
  reportUrl?: string;
  geojson_map?: any;
  attack_graph?: any;
}

