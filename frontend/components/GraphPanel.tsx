"use client";
import dynamic from "next/dynamic";
import { useGeoGraph } from "@/hooks/useInvestigation";
import { Loader2, Share2 } from "lucide-react";

const FlowGraph = dynamic(() => import("./FlowGraph").then((m) => m.FlowGraph), {
  ssr: false,
  loading: () => (
    <div className="flex h-[420px] items-center justify-center text-ink-muted">
      <Loader2 className="h-5 w-5 animate-spin" />
    </div>
  )
});

export function GraphPanel({ investigationId }: { investigationId: string }) {
  const { data, isLoading, isError } = useGeoGraph(investigationId);

  if (isLoading) {
    return (
      <div className="flex h-[420px] items-center justify-center gap-2 text-ink-muted">
        <Loader2 className="h-4 w-4 animate-spin" /> Building attack graph…
      </div>
    );
  }
  if (isError || !data || data.nodes.length === 0) {
    return (
      <div className="flex h-[420px] flex-col items-center justify-center gap-2 text-ink-muted">
        <Share2 className="h-6 w-6" />
        <p className="text-sm">No attack graph available for this case yet.</p>
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded border border-bg-border bg-bg-raised">
      <FlowGraph graph={data} />
    </div>
  );
}
