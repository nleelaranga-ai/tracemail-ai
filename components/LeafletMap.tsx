"use client";
import { useEffect, useRef } from "react";
import { MapContainer, TileLayer, CircleMarker, Polyline, Popup } from "react-leaflet";
import type { Map as LeafletMapInstance } from "leaflet";
import "leaflet/dist/leaflet.css";
import type { GeoJSON as TraceGeoJSON } from "@/types";

interface Props {
  geojson: TraceGeoJSON;
  originLat?: number;
  originLon?: number;
  originCity?: string;
  originCountry?: string;
  threatScore?: number;
  riskLevel?: string;
  originIp?: string;
}

export function LeafletMap({
  geojson,
  originLat,
  originLon,
  originCity = "Frankfurt",
  originCountry = "Germany",
  threatScore = 89,
  riskLevel = "Critical",
  originIp = "185.220.101.4"
}: Props) {
  const mapRef = useRef<LeafletMapInstance | null>(null);

  useEffect(() => {
    return () => {
      mapRef.current?.remove();
      mapRef.current = null;
    };
  }, []);

  const points = geojson?.features ? geojson.features.filter((f) => f.geometry.type === "Point") : [];
  const lines = geojson?.features ? geojson.features.filter((f) => f.geometry.type === "LineString") : [];

  // Determine center: prefer explicit origin coordinates, then first point in GeoJSON, default to Frankfurt [50.1109, 8.6821]
  const centerLat = originLat !== undefined && originLat !== 0 ? originLat : (points[0]?.geometry.type === "Point" ? points[0].geometry.coordinates[1] : 50.1109);
  const centerLon = originLon !== undefined && originLon !== 0 ? originLon : (points[0]?.geometry.type === "Point" ? points[0].geometry.coordinates[0] : 8.6821);

  return (
    <div className="relative">
      <div className="absolute right-3 top-3 z-[1000] rounded-lg border border-bg-border bg-bg-surface/90 px-3 py-1.5 backdrop-blur-md shadow-md">
        <p className="text-[11px] font-semibold text-ink flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full bg-red-500 animate-ping" />
          Origin: {originCity}, {originCountry}
        </p>
        <p className="font-mono text-[10px] text-ink-muted">
          Coords: {centerLat.toFixed(2)}°, {centerLon.toFixed(2)}°
        </p>
      </div>

      <MapContainer
        ref={mapRef}
        center={[centerLat, centerLon]}
        zoom={4}
        style={{ height: 440, width: "100%" }}
        scrollWheelZoom={false}
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />

        {/* Origin Circle Marker */}
        <CircleMarker
          center={[centerLat, centerLon]}
          radius={12}
          pathOptions={{
            color: "#ef4444",
            fillColor: "#ef4444",
            fillOpacity: 0.8,
            weight: 3
          }}
        >
          <Popup>
            <div className="p-1 font-mono text-xs">
              <div className="font-bold text-red-500 uppercase">🎯 Attack Origin</div>
              <div>Location: {originCity}, {originCountry}</div>
              <div>IP: {originIp}</div>
              <div>Threat Score: {threatScore} / 100 ({riskLevel})</div>
            </div>
          </Popup>
        </CircleMarker>

        {lines.map((f, i) =>
          f.geometry.type === "LineString" ? (
            <Polyline
              key={i}
              positions={f.geometry.coordinates.map(([lon, lat]) => [lat, lon])}
              pathOptions={{ color: "#00D9C0", weight: 2.5, dashArray: "5 8" }}
            />
          ) : null
        )}

        {points.map((f, i) => {
          if (f.geometry.type !== "Point") return null;
          const [lon, lat] = f.geometry.coordinates;
          const malicious = Boolean(f.properties.malicious);
          return (
            <CircleMarker
              key={i}
              center={[lat, lon]}
              radius={8}
              pathOptions={{
                color: malicious ? "#F4415C" : "#22C55E",
                fillColor: malicious ? "#F4415C" : "#22C55E",
                fillOpacity: 0.75
              }}
            >
              <Popup>
                <span className="font-mono text-xs">
                  Hop {String(f.properties.hop ?? "")} · {String(f.properties.ip ?? "")}
                  <br />
                  {String(f.properties.city ?? "")}
                  {malicious ? " · Flagged Malicious" : " · Verified Clean"}
                </span>
              </Popup>
            </CircleMarker>
          );
        })}
      </MapContainer>
    </div>
  );
}
