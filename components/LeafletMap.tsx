"use client";
import { useEffect, useRef } from "react";
import { MapContainer, TileLayer, CircleMarker, Polyline, Popup } from "react-leaflet";
import type { Map as LeafletMapInstance } from "leaflet";
import "leaflet/dist/leaflet.css";
import type { GeoJSON as TraceGeoJSON } from "@/types";

export function LeafletMap({ geojson }: { geojson: TraceGeoJSON }) {
  const mapRef = useRef<LeafletMapInstance | null>(null);

  useEffect(() => {
    return () => {
      mapRef.current?.remove();
      mapRef.current = null;
    };
  }, []);

  const points = geojson.features.filter((f) => f.geometry.type === "Point");
  const lines = geojson.features.filter((f) => f.geometry.type === "LineString");
  const first = points[0]?.geometry.type === "Point" ? points[0].geometry.coordinates : [0, 20];

  return (
    <MapContainer
      ref={mapRef}
      center={[first[1], first[0]]}
      zoom={3}
      style={{ height: 420, width: "100%" }}
      scrollWheelZoom={false}
    >
      <TileLayer
        attribution='&copy; OpenStreetMap contributors'
        url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
      />
      {lines.map((f, i) =>
        f.geometry.type === "LineString" ? (
          <Polyline
            key={i}
            positions={f.geometry.coordinates.map(([lon, lat]) => [lat, lon])}
            pathOptions={{ color: "#00D9C0", weight: 2, dashArray: "4 6" }}
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
            radius={7}
            pathOptions={{
              color: malicious ? "#F4415C" : "#22C55E",
              fillColor: malicious ? "#F4415C" : "#22C55E",
              fillOpacity: 0.7
            }}
          >
            <Popup>
              <span className="font-mono text-xs">
                Hop {String(f.properties.hop ?? "")} · {String(f.properties.ip ?? "")}
                <br />
                {String(f.properties.city ?? "")}
                {malicious ? " · malicious" : ""}
              </span>
            </Popup>
          </CircleMarker>
        );
      })}
    </MapContainer>
  );
}