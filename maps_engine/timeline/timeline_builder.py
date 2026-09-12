from datetime import datetime, timezone
from typing import List, Dict, Any


def build_timeline(hops: List[Dict[str, Any]], default_ip: str = "Origin Host") -> List[Dict[str, Any]]:
    """
    Build a chronological timeline from enriched email hops.

    Expected hop format:
    {
        "server": "mail.example.com",
        "ip": "185.220.101.4",
        "timestamp": "2026-09-06T09:58:12Z",
        "malicious": True
    }

    :param hops: List of hop dictionaries.
    :param default_ip: Fallback IP string if hop has none.
    :return: Chronologically sorted list of timeline steps.
    """
    def _parse_time(hop: Dict[str, Any]) -> datetime:
        raw_ts = hop.get("timestamp")
        if not raw_ts:
            return datetime.min.replace(tzinfo=timezone.utc)
        try:
            return datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)

    # Sort hops chronologically by timestamp
    sorted_hops = sorted(hops, key=_parse_time)

    timeline: List[Dict[str, Any]] = []

    for index, hop in enumerate(sorted_hops, start=1):
        ts = hop.get("timestamp")
        if not ts:
            ts = datetime.now(timezone.utc).isoformat()

        server = hop.get("server") or f"mail-relay-{index}.network"
        ip = hop.get("ip") or default_ip

        timeline.append({
            "step": index,
            "server": server,
            "ip": ip,
            "timestamp": ts,
            "malicious": bool(hop.get("malicious", False))
        })

    return timeline
