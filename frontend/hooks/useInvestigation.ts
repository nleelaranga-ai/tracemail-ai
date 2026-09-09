"use client";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/services/api";

export function useInvestigations() {
  return useQuery({ queryKey: ["investigations"], queryFn: api.listInvestigations });
}

export function useInvestigation(id: string) {
  return useQuery({
    queryKey: ["investigation", id],
    queryFn: () => api.getInvestigation(id),
    enabled: !!id
  });
}

export function useGeoMap(id: string) {
  return useQuery({ queryKey: ["geo-map", id], queryFn: () => api.getMap(id), enabled: !!id });
}

export function useGeoTimeline(id: string) {
  return useQuery({ queryKey: ["geo-timeline", id], queryFn: () => api.getTimeline(id), enabled: !!id });
}

export function useGeoGraph(id: string) {
  return useQuery({ queryKey: ["geo-graph", id], queryFn: () => api.getGraph(id), enabled: !!id });
}
