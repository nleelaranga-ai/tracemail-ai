def build_attack_graph(hops, sender=None, recipient=None):
    """
    Build nodes and edges representing the email attack path.

    Each hop becomes a relay node.
    """

    nodes = []
    edges = []

    # Sender node
    nodes.append({
        "id": "sender",
        "label": sender or "unknown",
        "type": "sender"
    })

    previous_node = "sender"

    # Relay nodes
    for index, hop in enumerate(hops, start=1):
        node_id = f"hop{index}"

        city = hop.get("city")
        ip = hop.get("ip")

        if city:
            label = f"{ip} ({city})"
        else:
            label = ip

        nodes.append({
            "id": node_id,
            "label": label,
            "type": "relay",
            "malicious": hop.get("malicious", False)
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
        "type": "recipient"
    })

    edges.append({
        "from": previous_node,
        "to": "victim"
    })

    return {
        "nodes": nodes,
        "edges": edges
    }