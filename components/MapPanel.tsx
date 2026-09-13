"use client";
import React from "react";
import dynamic from "next/dynamic";
import { useInvestigationMasterMap, useGeoMap } from "@/hooks/useInvestigation";
import { Loader2, MapPin } from "lucide-react";

const ThreatMap = dynamic(() => import("./maps/ThreatMap").then((m) => m.ThreatMap), {
  ssr: false,
  loading: () => (
    <div className="flex h-[480px] items-center justify-center text-ink-muted">
      <Loader2 className="h-6 w-6 animate-spin text-trace" />
      <span className="ml-2 font-mono text-xs">Initializing Google Maps Platform telemetry...</span>
    </div>
  )
});

interface Props {
  investigationId: string;
  originLat?: number;
  originLon?: number;
  originCity?: string;
  originCountry?: string;
  threatScore?: number;
  riskLevel?: string;
  originIp?: string;
}

export function MapPanel({
  investigationId,
  originLat,
  originLon,
  originCity = "Frankfurt",
  originCountry = "Germany",
  threatScore = 89,
  riskLevel = "Critical",
  originIp = "185.220.101.4"
}: Props) {
  const { data: masterMap, isLoading: masterLoading } = useInvestigationMasterMap(investigationId);
  const { data: geojsonFallback, isLoading: geoLoading } = useGeoMap(investigationId);

  const isLoading = masterLoading && geoLoading;

  if (isLoading) {
    return (
      <div className="flex h-[480px] items-center justify-center gap-2 text-ink-muted bg-bg-surface rounded-xl border border-bg-border">
        <Loader2 className="h-5 w-5 animate-spin text-trace" />
        <span className="font-mono text-xs">Loading Google Maps Platform attack telemetry…</span>
      </div>
    );
  }

  // Construct markers, routes, and heatmap from masterMap if available
  const markers = masterMap?.markers || [
    {
      id: "origin-attacker",
      label: `Attacker Origin: ${originIp}`,
      type: "attacker",
      color: "#ef4444",
      latitude: originLat || 50.1109,
      longitude: originLon || 8.6821,
      ip: originIp,
      city: originCity,
      country: originCountry,
      threat_score: threatScore,
      role: "Hostile Attack Origin"
    },
    {
      id: "target-inbox",
      label: "Target Organization",
      type: "victim",
      color: "#3b82f6",
      latitude: 16.5062,
      longitude: 80.6480,
      ip: "203.0.113.50",
      city: "Vijayawada",
      country: "India",
      threat_score: 0,
      role: "Protected Target (Victim)"
    }
  ];

  const routes = masterMap?.routes || [
    {
      id: `route-${investigationId}`,
      name: `Attack Traversal: ${originCity} -> Vijayawada`,
      polyline: [
        [originLat || 50.1109, originLon || 8.6821],
        [12.9716, 77.5946],
        [16.5062, 80.6480]
      ],
      distance_km: masterMap?.summary?.attack_distance_km || 6842.5,
      is_hostile: threatScore >= 50,
      color: threatScore >= 50 ? "#ef4444" : "#f97316"
    }
  ];

  const heatmap = masterMap?.heatmap || [
    { lat: originLat || 50.1109, lng: originLon || 8.6821, weight: threatScore },
    { lat: 12.9716, lng: 77.5946, weight: 45.0 },
    { lat: 16.5062, lng: 80.6480, weight: 15.0 }
  ];

  const nearbyPlaces = masterMap?.nearby_places || [];

  return (
    <ThreatMap
      key={investigationId}
      markers={markers}
      routes={routes}
      heatmap={heatmap}
      nearbyPlaces={nearbyPlaces}
      originCity={masterMap?.origin_city || originCity}
      originCountry={masterMap?.origin_country || originCountry}
      originIp={masterMap?.origin_ip || originIp}
      threatScore={masterMap?.threat_score || threatScore}
      riskLevel={masterMap?.risk_level || riskLevel}
      distanceKm={masterMap?.summary?.attack_distance_km || 6842.5}
      height={480}
    />
  );
}
