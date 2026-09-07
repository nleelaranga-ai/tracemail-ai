// Mock data matching the exact contracts in Section 6 of the master plan.
// Used automatically whenever NEXT_PUBLIC_API_URL is unset, so Person 1 can build
// and demo every screen before Backend (Person 2) is ready.
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
    sender: "unknown@sketchy-relay.net",
    subject: "URGENT: Verify your account within 24 hours",
    receivedAt: "2026-09-06T09:58:12Z",
    aiResult: {
      phishingScore: 92,
      verdict: "phishing",
      explanation:
        "Sender domain was registered 14 days ago and impersonates a known bank login page. The email uses urgency language and a mismatched reply-to address, both strong phishing indicators.",
      entities: [
        { type: "url", value: "http://secure-bank-verify.co/login" },
        { type: "ip", value: "185.220.101.4" },
        { type: "domain", value: "sketchy-relay.net" }
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
      },
      {
        type: "ip",
        value: "142.250.1.27",
        reputation: "clean",
        geo: { country: "India", city: "Bengaluru", lat: 12.97, lon: 77.59 },
        malicious: false
      }
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
    subject: "Your weekly product digest",
    receivedAt: "2026-09-04T07:12:03Z",
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
    mapUrl: "/api/geo/map/inv-1039",
    timelineUrl: "/api/geo/timeline/inv-1039",
    graphUrl: "/api/geo/graph/inv-1039",
    reportUrl: "/api/report/pdf/inv-1039"
  },
  {
    id: "inv-1031",
    status: "complete",
    sender: "billing@paypa1-support.com",
    subject: "Unusual activity detected on your account",
    receivedAt: "2026-09-01T14:22:47Z",
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
        geometry: { type: "Point", coordinates: [8.68, 50.11] },
        properties: { hop: 1, ip: "185.220.101.4", city: "Frankfurt", malicious: true }
      },
      {
        type: "Feature",
        geometry: { type: "Point", coordinates: [77.59, 12.97] },
        properties: { hop: 2, ip: "142.250.1.27", city: "Bengaluru", malicious: false }
      },
      {
        type: "Feature",
        geometry: { type: "LineString", coordinates: [[8.68, 50.11], [77.59, 12.97]] },
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
      { id: "sender", label: "unknown@sketchy-relay.net", type: "sender" },
      { id: "hop1", label: "185.220.101.4 (Frankfurt)", type: "relay", malicious: true },
      { id: "victim", label: "you@yourcompany.com", type: "recipient" }
    ],
    edges: [
      { from: "sender", to: "hop1" },
      { from: "hop1", to: "victim" }
    ]
  }
};

function fallbackGeo(inv: Investigation): GeoJSON {
  const points = inv.threatResults.filter((t) => t.geo?.lat && t.geo?.lon);
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
      { id: "recipient", label: "you@yourcompany.com", type: "recipient" as const }
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
