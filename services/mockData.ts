// Mock data matching the exact contracts in Section 6 of the master plan.
import type {
  AttackGraph,
  GeoJSON,
  Investigation,
  TimelineStep
} from "@/types";

export const MOCK_INVESTIGATIONS: Investigation[] = [
  {
    id: "inv-1042",
    status: "complete",
    sender: "security@paypa1-verification.com",
    recipient: "analyst@target.org",
    subject: "URGENT: Verify your account credentials immediately",
    receivedAt: "2026-09-06T09:58:12Z",
    threat_score: 92,
    threatScore: 92,
    risk_level: "Critical",
    riskLevel: "Critical",
    origin_city: "Frankfurt",
    origin_country: "Germany",
    origin_ip: "185.220.101.4",
    latitude: 50.1109,
    longitude: 8.6821,
    aiResult: {
      phishingScore: 92,
      verdict: "phishing",
      explanation:
        "Sender domain was registered 14 days ago and impersonates a known bank login page. The email uses urgency language and a mismatched reply-to address, both strong phishing indicators.",
      entities: [
        { type: "url", value: "http://secure-bank-verify.co/login" },
        { type: "ip", value: "185.220.101.4" },
        { type: "domain", value: "paypa1-verification.com" }
      ]
    },
    threatResults: [
      {
        type: "ip",
        value: "185.220.101.4",
        reputation: "malicious",
        geo: { country: "Germany", city: "Frankfurt", lat: 50.11, lon: 8.68 },
        malicious: true
      },
      {
        type: "url",
        value: "http://secure-bank-verify.co/login",
        reputation: "malicious",
        malicious: true
      }
    ],
    threat_intel: {
      virustotal: {
        positives: 5,
        total_engines: 88,
        reputation: -42,
        scan_date: "2026-09-06T09:58:12Z"
      },
      abuseipdb: {
        abuse_confidence_score: 100,
        total_reports: 142,
        is_whitelisted: false
      },
      whois: {
        domain: "paypa1-verification.com",
        registrar: "NameCheap, Inc.",
        creation_date: "2026-08-23T11:00:00Z",
        domain_age_days: 14,
        registrant_country: "IS"
      },
      dns: {
        spf: "fail",
        dkim: "fail",
        dmarc: "fail",
        mx_records: ["mail.sketchy-relay.net"]
      },
      urlscan: {
        malicious: true,
        score: 92
      },
      geoip: {
        ip: "185.220.101.4",
        country: "Germany",
        city: "Frankfurt",
        latitude: 50.1109,
        longitude: 8.6821,
        isp: "Host Europe GmbH",
        asn: "AS8560"
      }
    },
    ai_analysis: {
      prediction: "phishing",
      confidence: 0.98,
      summary: "High-confidence credential harvesting attack detected using newly registered domain homoglyphs.",
      reasons: [
        "Cryptographic Authentication Failed: Both SPF and DKIM signatures failed validation.",
        "Brand Impersonation: Homoglyph character substitution (paypa1 instead of paypal).",
        "Credential Harvesting URL: Embedded login hyperlink resolves to unindexed hostile IP.",
        "Recent Domain Registration: Registered only 14 days ago via privacy proxy."
      ]
    },
    timeline: [
      { step: 1, name: "Email Uploaded", detail: "RFC 822 message payload received and SHA-256 fingerprint computed.", status: "completed" },
      { step: 2, name: "Headers Parsed", detail: "Discovered origin relay at 185.220.101.4; flagged forged Return-Path.", status: "completed" },
      { step: 3, name: "WHOIS Lookup Completed", detail: "ICANN RDAP reported domain age 14 days (High-risk newly registered domain).", status: "completed" },
      { step: 4, name: "Threat Intelligence Completed", detail: "VirusTotal 5/88 detections, AbuseIPDB 100% confidence, SPF/DKIM fail.", status: "completed" },
      { step: 5, name: "AI Classification", detail: "Neural classifier flagged urgency trigger and credential harvesting intent (98% confidence).", status: "completed" },
      { step: 6, name: "Threat Score Generated", detail: "Weighted algorithm produced critical threat score 92/100 (Verdict: PHISHING).", status: "completed" }
    ],
    iocs: [
      { type: "url", value: "http://secure-bank-verify.co/login", malicious: true },
      { type: "ip", value: "185.220.101.4", malicious: true },
      { type: "domain", value: "paypa1-verification.com", malicious: true },
      { type: "hash", value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", malicious: true }
    ],
    mapUrl: "/api/geo/map/inv-1042",
    timelineUrl: "/api/geo/timeline/inv-1042",
    graphUrl: "/api/geo/graph/inv-1042",
    reportUrl: "/api/report/pdf/inv-1042"
  },
  {
    id: "inv-1039",
    status: "complete",
    sender: "newsletter@fig-updates.com",
    recipient: "analyst@target.org",
    subject: "Your weekly design and product digest",
    receivedAt: "2026-09-04T07:12:03Z",
    threat_score: 8,
    threatScore: 8,
    risk_level: "Low",
    riskLevel: "Low",
    origin_city: "Mountain View",
    origin_country: "United States",
    origin_ip: "142.250.80.27",
    latitude: 37.422,
    longitude: -122.084,
    aiResult: {
      phishingScore: 8,
      verdict: "safe",
      explanation:
        "Consistent sending history, valid SPF/DKIM/DMARC, no suspicious links or urgency language detected.",
      entities: [{ type: "domain", value: "fig-updates.com" }]
    },
    threatResults: [
      {
        type: "ip",
        value: "142.250.80.27",
        reputation: "clean",
        geo: { country: "USA", city: "Mountain View", lat: 37.4, lon: -122.08 },
        malicious: false
      }
    ],
    threat_intel: {
      virustotal: { positives: 0, total_engines: 88, reputation: 100, scan_date: "2026-09-04T07:12:03Z" },
      abuseipdb: { abuse_confidence_score: 0, total_reports: 0, is_whitelisted: true },
      whois: { domain: "fig-updates.com", registrar: "MarkMonitor Inc.", domain_age_days: 1820 },
      dns: { spf: "pass", dkim: "pass", dmarc: "pass" },
      urlscan: { malicious: false, score: 0 },
      geoip: { ip: "142.250.80.27", country: "United States", city: "Mountain View", latitude: 37.422, longitude: -122.084, isp: "Google LLC", asn: "AS15169" }
    },
    ai_analysis: {
      prediction: "safe",
      confidence: 0.99,
      summary: "Legitimate enterprise communication with valid DKIM authentication.",
      reasons: [
        "Cryptographic Integrity: DKIM and SPF records match sending infrastructure.",
        "Established Domain History: Domain has been continuously registered for over 5 years."
      ]
    },
    timeline: [
      { step: 1, name: "Email Uploaded", detail: "Payload parsed and validated cleanly.", status: "completed" },
      { step: 2, name: "Headers Parsed", detail: "Return-Path matches authenticated domain.", status: "completed" },
      { step: 3, name: "WHOIS Lookup Completed", detail: "Enterprise registrar verified; age > 5 years.", status: "completed" },
      { step: 4, name: "Threat Intelligence Completed", detail: "Zero engines flagged; AbuseIPDB score 0%.", status: "completed" },
      { step: 5, name: "AI Classification", detail: "Low-risk newsletter profile matched.", status: "completed" },
      { step: 6, name: "Threat Score Generated", detail: "Score evaluated as 8/100 (Verdict: SAFE).", status: "completed" }
    ],
    iocs: [
      { type: "domain", value: "fig-updates.com", malicious: false }
    ],
    mapUrl: "/api/geo/map/inv-1039",
    timelineUrl: "/api/geo/timeline/inv-1039",
    graphUrl: "/api/geo/graph/inv-1039",
    reportUrl: "/api/report/pdf/inv-1039"
  },
  {
    id: "inv-1031",
    status: "complete",
    sender: "billing@paypa1-support.com",
    recipient: "analyst@target.org",
    subject: "Unusual activity detected on your account",
    receivedAt: "2026-09-01T14:22:47Z",
    threat_score: 61,
    threatScore: 61,
    risk_level: "Medium",
    riskLevel: "Medium",
    origin_city: "Amsterdam",
    origin_country: "Netherlands",
    origin_ip: "45.155.205.12",
    latitude: 52.3676,
    longitude: 4.9041,
    aiResult: {
      phishingScore: 61,
      verdict: "suspicious",
      explanation:
        "Domain uses a look-alike character substitution and SPF is missing, but no malicious payload URLs were found in the body.",
      entities: [
        { type: "domain", value: "paypa1-support.com" },
        { type: "ip", value: "45.155.205.12" }
      ]
    },
    threatResults: [
      {
        type: "ip",
        value: "45.155.205.12",
        reputation: "suspicious",
        geo: { country: "Netherlands", city: "Amsterdam", lat: 52.37, lon: 4.9 },
        malicious: false
      }
    ],
    threat_intel: {
      virustotal: { positives: 2, total_engines: 88, reputation: -10, scan_date: "2026-09-01T14:22:47Z" },
      abuseipdb: { abuse_confidence_score: 45, total_reports: 19, is_whitelisted: false },
      whois: { domain: "paypa1-support.com", registrar: "Tucows Domains Inc.", domain_age_days: 45 },
      dns: { spf: "fail", dkim: "none", dmarc: "none" },
      urlscan: { malicious: false, score: 45 },
      geoip: { ip: "45.155.205.12", country: "Netherlands", city: "Amsterdam", latitude: 52.3676, longitude: 4.9041, isp: "Serverius Holding B.V.", asn: "AS50673" }
    },
    ai_analysis: {
      prediction: "suspicious",
      confidence: 0.82,
      summary: "Look-alike brand domain detected with missing cryptographic authentication.",
      reasons: [
        "Unauthenticated Relay: SPF validation returned fail.",
        "Typosquatting Domain: Character substitution detected."
      ]
    },
    timeline: [
      { step: 1, name: "Email Uploaded", detail: "Payload validated.", status: "completed" },
      { step: 2, name: "Headers Parsed", detail: "Relay traced to Netherlands host.", status: "completed" },
      { step: 3, name: "WHOIS Lookup Completed", detail: "Domain age 45 days.", status: "completed" },
      { step: 4, name: "Threat Intelligence Completed", detail: "2 engines flagged; Abuse confidence 45%.", status: "completed" },
      { step: 5, name: "AI Classification", detail: "Flagged as suspicious lookalike.", status: "completed" },
      { step: 6, name: "Threat Score Generated", detail: "Score evaluated as 61/100 (Verdict: SUSPICIOUS).", status: "completed" }
    ],
    iocs: [
      { type: "domain", value: "paypa1-support.com", malicious: true },
      { type: "ip", value: "45.155.205.12", malicious: false }
    ],
    mapUrl: "/api/geo/map/inv-1031",
    timelineUrl: "/api/geo/timeline/inv-1031",
    graphUrl: "/api/geo/graph/inv-1031",
    reportUrl: "/api/report/pdf/inv-1031"
  }
];

export const MOCK_GEOJSON: Record<string, GeoJSON> = {
  "inv-1042": {
    type: "FeatureCollection",
    features: [
      {
        type: "Feature",
        geometry: { type: "Point", coordinates: [8.6821, 50.1109] },
        properties: { hop: 1, ip: "185.220.101.4", city: "Frankfurt", malicious: true }
      },
      {
        type: "Feature",
        geometry: { type: "Point", coordinates: [77.5946, 12.9716] },
        properties: { hop: 2, ip: "142.250.1.27", city: "Bengaluru", malicious: false }
      },
      {
        type: "Feature",
        geometry: { type: "LineString", coordinates: [[8.6821, 50.1109], [77.5946, 12.9716]] },
        properties: { from: "Frankfurt", to: "Bengaluru" }
      }
    ]
  }
};

export const MOCK_TIMELINE: Record<string, TimelineStep[]> = {
  "inv-1042": [
    { step: 1, server: "mail.sketchy-relay.net", ip: "185.220.101.4", timestamp: "2026-09-06T09:58:12Z", malicious: true },
    { step: 2, server: "mx.gmail.com", ip: "142.250.1.27", timestamp: "2026-09-06T09:58:15Z", malicious: false }
  ]
};

export const MOCK_GRAPH: Record<string, AttackGraph> = {
  "inv-1042": {
    nodes: [
      { id: "sender", label: "security@paypa1-verification.com", type: "sender" },
      { id: "hop1", label: "185.220.101.4 (Frankfurt)", type: "relay", malicious: true },
      { id: "victim", label: "analyst@target.org", type: "recipient" }
    ],
    edges: [
      { from: "sender", to: "hop1" },
      { from: "hop1", to: "victim" }
    ]
  }
};

function fallbackGeo(inv: Investigation): GeoJSON {
  const points = inv.threatResults.filter((t) => t.geo?.lat && t.geo?.lon);
  if (points.length === 0 && (inv.latitude || inv.longitude)) {
    return {
      type: "FeatureCollection",
      features: [
        {
          type: "Feature",
          geometry: { type: "Point", coordinates: [inv.longitude || 78.9629, inv.latitude || 20.5937] },
          properties: {
            hop: 1,
            ip: inv.origin_ip || inv.ip || "Origin Host",
            city: inv.origin_city || inv.city || "Origin Node",
            malicious: inv.threat_score ? inv.threat_score >= 65 : false
          }
        }
      ]
    };
  }
  return {
    type: "FeatureCollection",
    features: points.map((t, i) => ({
      type: "Feature",
      geometry: { type: "Point", coordinates: [t.geo!.lon!, t.geo!.lat!] },
      properties: { hop: i + 1, ip: t.value, city: t.geo?.city, malicious: t.malicious }
    }))
  };
}

function fallbackTimeline(inv: Investigation): TimelineStep[] {
  return inv.threatResults
    .filter((t) => t.type === "ip")
    .map((t, i) => ({
      step: i + 1,
      server: t.geo?.city ? `relay-${t.geo.city.toLowerCase()}` : "unknown-relay",
      ip: t.value,
      timestamp: inv.receivedAt,
      malicious: t.malicious
    }));
}

function fallbackGraph(inv: Investigation): AttackGraph {
  const relays = inv.threatResults.filter((t) => t.type === "ip");
  return {
    nodes: [
      { id: "sender", label: inv.sender, type: "sender" },
      ...relays.map((r, i) => ({
        id: `hop${i + 1}`,
        label: `${r.value}${r.geo?.city ? ` (${r.geo.city})` : ""}`,
        type: "relay" as const,
        malicious: r.malicious
      })),
      { id: "recipient", label: inv.recipient || "analyst@target.org", type: "recipient" as const }
    ],
    edges: [
      { from: "sender", to: relays.length ? "hop1" : "recipient" },
      ...relays.slice(0, -1).map((_, i) => ({ from: `hop${i + 1}`, to: `hop${i + 2}` })),
      ...(relays.length ? [{ from: `hop${relays.length}`, to: "recipient" }] : [])
    ]
  };
}

export function getMockGeo(id: string, inv?: Investigation): GeoJSON {
  return MOCK_GEOJSON[id] ?? (inv ? fallbackGeo(inv) : { type: "FeatureCollection", features: [] });
}
export function getMockTimeline(id: string, inv?: Investigation): TimelineStep[] {
  return MOCK_TIMELINE[id] ?? (inv ? fallbackTimeline(inv) : []);
}
export function getMockGraph(id: string, inv?: Investigation): AttackGraph {
  return MOCK_GRAPH[id] ?? (inv ? fallbackGraph(inv) : { nodes: [], edges: [] });
}
