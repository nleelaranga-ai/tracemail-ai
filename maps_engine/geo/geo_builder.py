from typing import List, Dict, Any, Optional


def build_geojson(
    hops: List[Dict[str, Any]],
    origin_city: str = "Origin Node",
    origin_lat: float = 0.0,
    origin_lon: float = 0.0
) -> Dict[str, Any]:
    """
    Convert enriched email hops into GeoJSON FeatureCollection.

    Each hop becomes a Point feature.
    All valid sequential hop locations are connected using a LineString.

    :param hops: List of hop dicts with lat/lon or latitude/longitude, ip, city, malicious.
    :param origin_city: Fallback city name if hop city is empty.
    :param origin_lat: Fallback latitude if hop has no coordinates.
    :param origin_lon: Fallback longitude if hop has no coordinates.
    :return: GeoJSON FeatureCollection dict.
    """
    features: List[Dict[str, Any]] = []
    coordinates: List[List[float]] = []

    for index, hop in enumerate(hops, start=1):
        raw_lat = hop.get("lat") if hop.get("lat") is not None else hop.get("latitude")
        raw_lon = hop.get("lon") if hop.get("lon") is not None else hop.get("longitude")

        # Use origin coordinates if hop coordinate is unset and fallback is provided
        if (raw_lat is None or raw_lon is None or (raw_lat == 0.0 and raw_lon == 0.0)) and (origin_lat != 0.0 or origin_lon != 0.0):
            raw_lat = origin_lat
            raw_lon = origin_lon

        # Skip hops without location information
        if raw_lat is None or raw_lon is None:
            continue

        try:
            lat = float(raw_lat)
            lon = float(raw_lon)
        except (ValueError, TypeError):
            continue

        feature = {
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [lon, lat]
            },
            "properties": {
                "hop": index,
                "ip": hop.get("ip"),
                "city": hop.get("city") or origin_city,
                "malicious": hop.get("malicious", False)
            }
        }
        features.append(feature)
        coordinates.append([lon, lat])

    # Create path connecting sequential hops if 2 or more
    if len(coordinates) >= 2:
        start_city = hops[0].get("city") or origin_city or "Origin"
        end_city = hops[-1].get("city") or "Destination Gateway"
        line_feature = {
            "type": "Feature",
            "geometry": {
                "type": "LineString",
                "coordinates": coordinates
            },
            "properties": {
                "type": "email_path",
                "from": start_city,
                "to": end_city
            }
        }
        features.append(line_feature)

    return {
        "type": "FeatureCollection",
        "features": features
    }
