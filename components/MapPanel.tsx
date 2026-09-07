"use client";
import dynamic from "next/dynamic";
import { useGeoMap } from "@/hooks/useInvestigation";
import { Loader2, MapPin } from "lucide-react";

const LeafletMap = dynamic(() => import("./LeafletMap").then((m) => m.LeafletMap), {
  ssr: false,
  loading: () => (
    <div className="flex h-[420px] items-center justify-center text-ink-muted">
      <Loader2 className="h-5 w-5 animate-spin" />
    </div>
  )
});

export function MapPanel({ investigationId }: { investigationId: string }) {
  const { data, isLoading, isError } = useGeoMap(investigationId);

  if (isLoading) {
    return (
      <div className="flex h-[420px] items-center justify-center gap-2 text-ink-muted">
        <Loader2 className="h-4 w-4 animate-spin" /> Loading hop path…
      </div>
    );
  }
  if (isError || !data) {
    return (
      <div className="flex h-[420px] flex-col items-center justify-center gap-2 text-ink-muted">
        <MapPin className="h-6 w-6" />
        <p className="text-sm">No geolocation data available for this case yet.</p>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded border border-bg-border">
      <LeafletMap key={investigationId} geojson={data} />
    </div>
  );
}