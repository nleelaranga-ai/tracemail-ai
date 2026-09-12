def build_geojson(hops):
    """
    Convert enriched email hops into GeoJSON.

    Each hop becomes a Point.
    All valid hop locations are connected using a LineString.
    """

    features = []

    # Create Point features
    for index, hop in enumerate(hops, start=1):

        # Skip hops without location information
        if hop.get("lat") is None or hop.get("lon") is None:
            continue

        feature = {
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [
                    hop["lon"],
                    hop["lat"]
                ]
            },
            "properties": {
                "hop": index,
                "ip": hop.get("ip"),
                "city": hop.get("city"),
                "malicious": hop.get("malicious", False)
            }
        }

        features.append(feature)

    # Collect valid coordinates for the path
    coordinates = [
        [hop["lon"], hop["lat"]]
        for hop in hops
        if hop.get("lat") is not None and hop.get("lon") is not None
    ]

    # Create path between hops
    if len(coordinates) >= 2:

        line_feature = {
            "type": "Feature",
            "geometry": {
                "type": "LineString",
                "coordinates": coordinates
            },
            "properties": {
                "type": "email_path"
            }
        }

        features.append(line_feature)

    return {
        "type": "FeatureCollection",
        "features": features
    }