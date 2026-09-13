"use client";
import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  MapPin,
  Route as RouteIcon,
  Flame,
  Building,
  ShieldAlert,
  Compass,
  KeyRound,
  ExternalLink,
  Layers,
  Sparkles,
  Info
} from "lucide-react";

export interface MapMarkerData {
  id: string;
  label: string;
  type: "attacker" | "victim" | "relay" | "safe" | string;
  color: string;
  latitude: number;
  longitude: number;
  ip?: string;
  city?: string;
  country?: string;
  threat_score?: number;
  role?: string;
  isp?: string;
  rdns?: string;
  dkim_status?: string;
}

export interface MapRouteData {
  id: string;
  name: string;
  polyline: [number, number][]; // [lat, lon]
  distance_km?: number;
  is_hostile?: boolean;
  color?: string;
  hops?: string[];
}

export interface HeatmapPointData {
  lat: number;
  lng: number;
  weight: number;
}

export interface NearbyPlaceData {
  name: string;
  amenity: string;
  latitude: number;
  longitude: number;
  distance_meters?: number;
}

export interface ThreatMapProps {
  markers?: MapMarkerData[];
  routes?: MapRouteData[];
  heatmap?: HeatmapPointData[];
  nearbyPlaces?: NearbyPlaceData[];
  originCity?: string;
  originCountry?: string;
  originIp?: string;
  threatScore?: number;
  riskLevel?: string;
  distanceKm?: number;
  height?: number | string;
}

// Retro / Cyber Dark Theme Styles for Google Maps
const DARK_MAP_STYLES: any[] = [
  { elementType: "geometry", stylers: [{ color: "#0a0f1d" }] },
  { elementType: "labels.text.stroke", stylers: [{ color: "#0a0f1d" }] },
  { elementType: "labels.text.fill", stylers: [{ color: "#748cab" }] },
  {
    featureType: "administrative.locality",
    elementType: "labels.text.fill",
    stylers: [{ color: "#93c5fd" }]
  },
  {
    featureType: "poi",
    elementType: "labels.text.fill",
    stylers: [{ color: "#64748b" }]
  },
  {
    featureType: "poi.park",
    elementType: "geometry",
    stylers: [{ color: "#111c3a" }]
  },
  {
    featureType: "road",
    elementType: "geometry",
    stylers: [{ color: "#1e293b" }]
  },
  {
    featureType: "road",
    elementType: "geometry.stroke",
    stylers: [{ color: "#0f172a" }]
  },
  {
    featureType: "road",
    elementType: "labels.text.fill",
    stylers: [{ color: "#64748b" }]
  },
  {
    featureType: "road.highway",
    elementType: "geometry",
    stylers: [{ color: "#334155" }]
  },
  {
    featureType: "road.highway",
    elementType: "geometry.stroke",
    stylers: [{ color: "#1e293b" }]
  },
  {
    featureType: "transit",
    elementType: "geometry",
    stylers: [{ color: "#1e293b" }]
  },
  {
    featureType: "water",
    elementType: "geometry",
    stylers: [{ color: "#050814" }]
  },
  {
    featureType: "water",
    elementType: "labels.text.fill",
    stylers: [{ color: "#334155" }]
  }
];

function createSvgPin(color: string): string {
  const svg = `
    <svg xmlns="http://www.w3.org/2000/svg" width="34" height="44" viewBox="0 0 34 44">
      <defs>
        <filter id="shadow" x="-30%" y="-30%" width="160%" height="160%">
          <feDropShadow dx="0" dy="3" stdDeviation="3" flood-color="#000000" flood-opacity="0.8"/>
        </filter>
      </defs>
      <path d="M17 2 C8.71 2 2 8.71 2 17 C2 27.5 17 42 17 42 C17 42 32 27.5 32 17 C32 8.71 25.29 2 17 2 Z"
            fill="${color}" stroke="#ffffff" stroke-width="2" filter="url(#shadow)"/>
      <circle cx="17" cy="17" r="7" fill="#0f172a"/>
      <circle cx="17" cy="17" r="4.5" fill="${color}"/>
    </svg>
  `;
  return `data:image/svg+xml;charset=UTF-8,${encodeURIComponent(svg)}`;
}

export function ThreatMap({
  markers = [],
  routes = [],
  heatmap = [],
  nearbyPlaces = [],
  originCity = "Frankfurt",
  originCountry = "Germany",
  originIp = "185.220.101.4",
  threatScore = 89,
  riskLevel = "Critical",
  distanceKm = 6842.5,
  height = 480
}: ThreatMapProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<any>(null);
  const markersRef = useRef<any[]>([]);
  const polylinesRef = useRef<any[]>([]);
  const circlesRef = useRef<any[]>([]);
  const placesMarkersRef = useRef<any[]>([]);
  const activeInfoWindowRef = useRef<any>(null);

  // Script & API key state
  const envApiKey = (process.env.NEXT_PUBLIC_GOOGLE_MAPS_API_KEY || "").trim();
  const [apiKey, setApiKey] = useState(envApiKey);
  const [isScriptLoaded, setIsScriptLoaded] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  // Layer Visibility Controls
  const [showMarkers, setShowMarkers] = useState(true);
  const [showRoutes, setShowRoutes] = useState(true);
  const [showHeatmap, setShowHeatmap] = useState(true);
  const [showPlaces, setShowPlaces] = useState(false);

  const primaryMarker = markers.find((m) => m.type === "attacker") || markers[0];
  const centerLat = primaryMarker ? primaryMarker.latitude : 50.1109;
  const centerLon = primaryMarker ? primaryMarker.longitude : 8.6821;
  const isCritical = threatScore >= 70;

  // 1. Dynamic Script Loader
  useEffect(() => {
    if (typeof window === "undefined") return;

    // If window.google.maps is already available
    if ((window as any).google?.maps) {
      setIsScriptLoaded(true);
      return;
    }

    const scriptId = "google-maps-platform-script";
    const existingScript = document.getElementById(scriptId) as HTMLScriptElement | null;

    if (existingScript) {
      existingScript.addEventListener("load", () => setIsScriptLoaded(true));
      existingScript.addEventListener("error", () => setLoadError("Failed to load Google Maps script"));
      return;
    }

    const script = document.createElement("script");
    script.id = scriptId;
    script.src = `https://maps.googleapis.com/maps/api/js?key=${apiKey}&libraries=places,geometry`;
    script.async = true;
    script.defer = true;
    script.onload = () => setIsScriptLoaded(true);
    script.onerror = () => setLoadError("Failed to load Google Maps JavaScript API");

    document.head.appendChild(script);
  }, [apiKey]);

  // 2. Initialize Map Instance
  useEffect(() => {
    if (!isScriptLoaded || !containerRef.current) return;
    const google = (window as any).google;
    if (!google?.maps) return;

    if (!mapRef.current) {
      mapRef.current = new google.maps.Map(containerRef.current, {
        center: { lat: centerLat, lng: centerLon },
        zoom: 3,
        mapTypeId: "roadmap",
        disableDefaultUI: false,
        zoomControl: true,
        mapTypeControl: false,
        streetViewControl: false,
        fullscreenControl: true,
        styles: DARK_MAP_STYLES
      });
    }
  }, [isScriptLoaded, centerLat, centerLon]);

  // 3. Render Markers & InfoWindows
  useEffect(() => {
    if (!mapRef.current) return;
    const google = (window as any).google;
    if (!google?.maps) return;

    // Clear old markers
    markersRef.current.forEach((m) => m.setMap(null));
    markersRef.current = [];

    if (!showMarkers) return;

    const bounds = new google.maps.LatLngBounds();

    markers.forEach((m) => {
      const isAttacker = m.type === "attacker";
      const isVictim = m.type === "victim";
      const isRelay = m.type === "relay";
      const pinColor = m.color || (isAttacker ? "#ef4444" : isVictim ? "#3b82f6" : isRelay ? "#f97316" : "#22c55e");

      const icon = {
        url: createSvgPin(pinColor),
        scaledSize: new google.maps.Size(34, 44),
        anchor: new google.maps.Point(17, 42)
      };

      const marker = new google.maps.Marker({
        position: { lat: m.latitude, lng: m.longitude },
        map: mapRef.current,
        title: m.label,
        icon
      });

      // Rich Cyber InfoWindow
      const contentString = `
        <div style="background-color: #0b132b; color: #f8fafc; padding: 12px; border-radius: 8px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; min-width: 240px; border: 1px solid #1e293b;">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 6px;">
            <span style="font-size: 10px; font-weight: 700; text-transform: uppercase; padding: 2px 6px; border-radius: 4px; background-color: ${pinColor}25; color: ${pinColor}; border: 1px solid ${pinColor}50;">
              ${m.role || m.type}
            </span>
            ${m.threat_score !== undefined ? `<span style="font-size: 11px; font-weight: 700; color: ${pinColor};">Threat: ${m.threat_score}/100</span>` : ""}
          </div>
          <div style="font-size: 13px; font-weight: 700; color: #ffffff; margin-bottom: 4px;">
            ${m.label}
          </div>
          <div style="font-size: 11px; color: #94a3b8; margin-bottom: 8px;">
            ${m.city || "Unknown City"}, ${m.country || "Global"} ${m.ip ? `(${m.ip})` : ""}
          </div>
          ${m.isp ? `<div style="font-size: 10px; color: #cbd5e1; margin-bottom: 2px;">ISP: <span style="color: #38bdf8;">${m.isp}</span></div>` : ""}
          ${m.dkim_status ? `<div style="font-size: 10px; color: #cbd5e1;">DKIM: <span style="color: ${m.dkim_status === "pass" ? "#22c55e" : "#ef4444"}; font-weight: 600;">${m.dkim_status.toUpperCase()}</span></div>` : ""}
        </div>
      `;

      const infoWindow = new google.maps.InfoWindow({
        content: contentString
      });

      marker.addListener("click", () => {
        if (activeInfoWindowRef.current) {
          activeInfoWindowRef.current.close();
        }
        infoWindow.open(mapRef.current, marker);
        activeInfoWindowRef.current = infoWindow;
      });

      bounds.extend(marker.getPosition()!);
      markersRef.current.push(marker);
    });

    // Fit bounds if more than 1 marker
    if (markers.length > 1) {
      mapRef.current.fitBounds(bounds, { top: 40, bottom: 40, left: 40, right: 40 });
    }
  }, [markers, showMarkers, isScriptLoaded]);

  // 4. Render Polylines
  useEffect(() => {
    if (!mapRef.current) return;
    const google = (window as any).google;
    if (!google?.maps) return;

    polylinesRef.current.forEach((p) => p.setMap(null));
    polylinesRef.current = [];

    if (!showRoutes) return;

    routes.forEach((r) => {
      const path = r.polyline.map(([lat, lon]) => ({ lat, lng: lon }));
      const polyline = new google.maps.Polyline({
        path,
        geodesic: true,
        strokeColor: r.color || (r.is_hostile ? "#ef4444" : "#f97316"),
        strokeOpacity: 0.85,
        strokeWeight: 3.5,
        map: mapRef.current
      });
      polylinesRef.current.push(polyline);
    });
  }, [routes, showRoutes, isScriptLoaded]);

  // 5. Render Heatmap Density Circles
  useEffect(() => {
    if (!mapRef.current) return;
    const google = (window as any).google;
    if (!google?.maps) return;

    circlesRef.current.forEach((c) => c.setMap(null));
    circlesRef.current = [];

    if (!showHeatmap) return;

    heatmap.forEach((hp) => {
      const circle = new google.maps.Circle({
        strokeColor: "#ef4444",
        strokeOpacity: 0.5,
        strokeWeight: 1.5,
        fillColor: "#ef4444",
        fillOpacity: Math.min(0.35, Math.max(0.1, hp.weight / 250)),
        map: mapRef.current,
        center: { lat: hp.lat, lng: hp.lng },
        radius: Math.max(60000, hp.weight * 6000)
      });
      circlesRef.current.push(circle);
    });
  }, [heatmap, showHeatmap, isScriptLoaded]);

  // 6. Render Nearby Infrastructure Places
  useEffect(() => {
    if (!mapRef.current) return;
    const google = (window as any).google;
    if (!google?.maps) return;

    placesMarkersRef.current.forEach((p) => p.setMap(null));
    placesMarkersRef.current = [];

    if (!showPlaces) return;

    nearbyPlaces.forEach((p) => {
      const pinColor = "#eab308";
      const icon = {
        url: createSvgPin(pinColor),
        scaledSize: new google.maps.Size(26, 34),
        anchor: new google.maps.Point(13, 32)
      };

      const marker = new google.maps.Marker({
        position: { lat: p.latitude, lng: p.longitude },
        map: mapRef.current,
        title: p.name,
        icon
      });

      const infoContent = `
        <div style="background-color: #0b132b; color: #f8fafc; padding: 10px; border-radius: 6px; font-family: sans-serif; font-size: 11px; border: 1px solid #334155;">
          <span style="background-color: #eab30825; color: #fde047; font-size: 9px; font-weight: 700; text-transform: uppercase; padding: 2px 5px; border-radius: 3px;">
            ${p.amenity}
          </span>
          <div style="font-weight: 600; color: #ffffff; margin-top: 4px;">${p.name}</div>
          ${p.distance_meters ? `<div style="color: #94a3b8; font-size: 10px; margin-top: 2px;">Proximity: ${p.distance_meters.toFixed(0)}m from origin</div>` : ""}
        </div>
      `;

      const infoWindow = new google.maps.InfoWindow({ content: infoContent });
      marker.addListener("click", () => {
        if (activeInfoWindowRef.current) activeInfoWindowRef.current.close();
        infoWindow.open(mapRef.current, marker);
        activeInfoWindowRef.current = infoWindow;
      });

      placesMarkersRef.current.push(marker);
    });
  }, [nearbyPlaces, showPlaces, isScriptLoaded]);

  // Recenter / Fit All Handler
  const handleRecenter = useCallback(() => {
    if (!mapRef.current) return;
    const google = (window as any).google;
    if (!google?.maps) return;

    if (markers.length > 0) {
      const bounds = new google.maps.LatLngBounds();
      markers.forEach((m) => bounds.extend({ lat: m.latitude, lng: m.longitude }));
      mapRef.current.fitBounds(bounds, { top: 40, bottom: 40, left: 40, right: 40 });
    } else {
      mapRef.current.setCenter({ lat: centerLat, lng: centerLon });
      mapRef.current.setZoom(4);
    }
  }, [markers, centerLat, centerLon]);

  return (
    <div className="relative overflow-hidden rounded-xl border border-bg-border bg-bg-surface shadow-2xl">
      {/* Top HUD: Telemetry & Provenance Badge */}
      <div className="border-b border-bg-border bg-bg-raised/80 px-4 py-3 backdrop-blur-md flex flex-wrap items-center justify-between gap-3 z-10 relative">
        <div className="flex items-center gap-3">
          <div
            className={`flex h-8 w-8 items-center justify-center rounded-lg ${
              isCritical
                ? "bg-red-500/20 text-red-400 border border-red-500/30"
                : "bg-trace/20 text-trace border border-trace/30"
            }`}
          >
            <ShieldAlert className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider text-ink font-mono">
                Geospatial Threat Matrix
              </span>
              <span className="inline-flex items-center gap-1 rounded-full bg-blue-500/10 px-2 py-0.5 text-[10px] font-semibold text-blue-400 border border-blue-500/20">
                <span className="h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />
                Google Maps Platform
              </span>
            </div>
            <p className="text-[11px] text-ink-muted">
              Origin:{" "}
              <span className="text-ink font-medium">
                {originCity}, {originCountry}
              </span>{" "}
              ({originIp}) · Dist: <span className="font-mono text-trace">{distanceKm} km</span>
            </p>
          </div>
        </div>

        {/* Layer Controls & Recenter */}
        <div className="flex items-center gap-1.5 bg-bg/80 p-1 rounded-lg border border-bg-border">
          <button
            onClick={() => setShowMarkers(!showMarkers)}
            className={`flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-medium transition ${
              showMarkers
                ? "bg-trace text-bg-surface font-semibold shadow-sm"
                : "text-ink-muted hover:text-ink"
            }`}
            title="Toggle Threat & Target Markers"
          >
            <MapPin className="h-3 w-3" /> Markers
          </button>

          <button
            onClick={() => setShowRoutes(!showRoutes)}
            className={`flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-medium transition ${
              showRoutes
                ? "bg-cyan-500 text-bg-surface font-semibold shadow-sm"
                : "text-ink-muted hover:text-ink"
            }`}
            title="Toggle Attack Traversal Route (Google Directions)"
          >
            <RouteIcon className="h-3 w-3" /> Routes
          </button>

          <button
            onClick={() => setShowHeatmap(!showHeatmap)}
            className={`flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-medium transition ${
              showHeatmap
                ? "bg-red-500 text-white font-semibold shadow-sm"
                : "text-ink-muted hover:text-ink"
            }`}
            title="Toggle Threat Density Heatmap"
          >
            <Flame className="h-3 w-3" /> Heatmap
          </button>

          <button
            onClick={() => setShowPlaces(!showPlaces)}
            className={`flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-medium transition ${
              showPlaces
                ? "bg-amber-500 text-bg-surface font-semibold shadow-sm"
                : "text-ink-muted hover:text-ink"
            }`}
            title="Toggle Critical Infrastructure (Google Places)"
          >
            <Building className="h-3 w-3" /> Places
          </button>

          <button
            onClick={handleRecenter}
            className="flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium text-ink-muted hover:text-ink transition border-l border-bg-border ml-1 pl-2"
            title="Recenter and fit all cyber telemetry"
          >
            <Compass className="h-3.5 w-3.5 text-trace" /> Fit
          </button>
        </div>
      </div>

      {/* Map Surface or API Key Configuration Notice */}
      <div className="relative">
        <div
          ref={containerRef}
          style={{ height, width: "100%" }}
          className="bg-[#0a0f1d] flex items-center justify-center"
        >
          {!isScriptLoaded && !loadError && (
            <div className="flex flex-col items-center justify-center gap-2 text-ink-muted p-6 text-center">
              <div className="h-7 w-7 rounded-full border-2 border-blue-500 border-t-transparent animate-spin" />
              <p className="font-mono text-xs text-ink">Connecting to Google Maps Platform API...</p>
              <p className="text-[11px] text-ink-faint">Loading Geocoding, Directions & Places libraries</p>
            </div>
          )}

          {loadError && (
            <div className="flex flex-col items-center justify-center gap-3 p-6 text-center max-w-md">
              <div className="h-10 w-10 rounded-full bg-amber-500/20 text-amber-400 flex items-center justify-center border border-amber-500/30">
                <KeyRound className="h-5 w-5" />
              </div>
              <p className="text-sm font-semibold text-ink">Google Maps API Key Required</p>
              <p className="text-xs text-ink-muted">
                Configure your key in <code className="bg-bg-raised px-1.5 py-0.5 rounded text-trace">.env.local</code> as{" "}
                <code className="bg-bg-raised px-1.5 py-0.5 rounded text-amber-300">NEXT_PUBLIC_GOOGLE_MAPS_API_KEY</code>.
              </p>
              <div className="flex items-center gap-2 w-full mt-2">
                <input
                  type="password"
                  placeholder="Paste AIzaSy... key for live preview"
                  className="flex-1 bg-bg px-3 py-1.5 rounded text-xs border border-bg-border text-ink font-mono focus:border-trace focus:outline-none"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                />
                <button
                  onClick={() => {
                    setLoadError(null);
                    setIsScriptLoaded(false);
                  }}
                  className="px-3 py-1.5 rounded bg-trace text-bg-surface font-medium text-xs hover:opacity-90 transition"
                >
                  Load
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Footer Legend Bar */}
      <div className="border-t border-bg-border bg-bg/90 px-4 py-2 flex flex-wrap items-center justify-between gap-4 text-[11px] text-ink-muted">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5 font-medium">
            <span className="h-2.5 w-2.5 rounded-full bg-red-500" /> Attacker IP
          </span>
          <span className="flex items-center gap-1.5 font-medium">
            <span className="h-2.5 w-2.5 rounded-full bg-orange-500" /> Relay Server
          </span>
          <span className="flex items-center gap-1.5 font-medium">
            <span className="h-2.5 w-2.5 rounded-full bg-blue-500" /> Target Organization
          </span>
          <span className="flex items-center gap-1.5 font-medium">
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-500" /> Verified Hop
          </span>
          <span className="flex items-center gap-1.5 font-medium">
            <span className="h-2.5 w-2.5 rounded-full bg-amber-500" /> Critical Infrastructure
          </span>
        </div>
        <div className="font-mono text-[10px] text-ink-faint flex items-center gap-2">
          <span>Project: peak-responder-483612-p8</span>
          <span>·</span>
          <span>Google Maps JS · Geocoding · Directions · Places</span>
        </div>
      </div>
    </div>
  );
}
