from typing import List, Dict, Any, Optional


def build_attack_graph(
    hops: List[Dict[str, Any]],
    sender: Optional[str] = None,
    recipient: Optional[str] = None,
    is_phishing: bool = False
) -> Dict[str, Any]:
    """
    Build nodes and edges representing the email attack path and infrastructure topology.

    Each hop becomes a relay node. The graph links:
    sender -> hop1 -> hop2 -> ... -> recipient

    :param hops: List of hop dictionaries.
    :param sender: Source email address or origin host.
    :param recipient: Destination email address or victim mailbox.
    :param is_phishing: Flag indicating whether origin sender is flagged as malicious.
    :return: Dict containing 'nodes' and 'edges' lists.
    """
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    # Sender node
    nodes.append({
        "id": "sender",
        "label": sender or "unknown",
        "type": "sender",
        "malicious": bool(is_phishing)
    })

    previous_node = "sender"

    # Relay nodes
    for index, hop in enumerate(hops, start=1):
        node_id = f"hop{index}"
        city = hop.get("city")
        ip = hop.get("ip")

        if city and ip:
            label = f"{ip} ({city})"
        elif ip:
            label = str(ip)
        else:
            label = f"relay-{index}"

        nodes.append({
            "id": node_id,
            "label": label,
            "type": "relay",
            "malicious": bool(hop.get("malicious", False))
        })

        edges.append({
            "from": previous_node,
            "to": node_id
        })

        previous_node = node_id

    # Recipient node
    nodes.append({
        "id": "victim",
        "label": recipient or "unknown",
        "type": "recipient",
        "malicious": False
    })

    edges.append({
        "from": previous_node,
        "to": "victim"
    })

    return {
        "nodes": nodes,
        "edges": edges
    }
