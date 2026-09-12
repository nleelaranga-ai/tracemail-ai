from datetime import datetime


def build_timeline(hops):
    """
    Build a chronological timeline from enriched email hops.

    Expected hop format:
    {
        "server": "mail.example.com",
        "ip": "185.220.101.4",
        "timestamp": "2026-09-06T09:58:12Z",
        "malicious": True
    }
    """

    # Sort hops by timestamp
    sorted_hops = sorted(
        hops,
        key=lambda hop: datetime.fromisoformat(
            hop["timestamp"].replace("Z", "+00:00")
        )
    )

    timeline = []

    for index, hop in enumerate(sorted_hops, start=1):
        timeline.append({
            "step": index,
            "server": hop.get("server"),
            "ip": hop.get("ip"),
            "timestamp": hop.get("timestamp"),
            "malicious": hop.get("malicious", False)
        })

    return timeline