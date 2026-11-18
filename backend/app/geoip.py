"""Offline GeoIP resolution, world city catalog, and World Map arc aggregation."""
from __future__ import annotations

import ipaddress
import json
import math
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any

DEFAULT_HOME: dict[str, Any] = {
    "lat": 13.7563,
    "lon": 100.5018,
    "city": "Bangkok",
    "country": "Thailand",
    "continent": "Asia",
}

BUILTIN_WORLD_CITIES: list[dict[str, Any]] = [
    {"ct": "Asia", "cn": "Thailand", "n": "Bangkok", "lt": 13.7563, "ln": 100.5018},
    {"ct": "Asia", "cn": "Thailand", "n": "Chiang Mai", "lt": 18.7883, "ln": 98.9853},
    {"ct": "Asia", "cn": "Thailand", "n": "Phuket", "lt": 7.8804, "ln": 98.3923},
    {"ct": "Asia", "cn": "Singapore", "n": "Singapore", "lt": 1.3521, "ln": 103.8198},
    {"ct": "Asia", "cn": "Japan", "n": "Tokyo", "lt": 35.6762, "ln": 139.6503},
    {"ct": "Asia", "cn": "Japan", "n": "Osaka", "lt": 34.6937, "ln": 135.5023},
    {"ct": "Asia", "cn": "South Korea", "n": "Seoul", "lt": 37.5665, "ln": 126.9780},
    {"ct": "Asia", "cn": "China", "n": "Beijing", "lt": 39.9042, "ln": 116.4074},
    {"ct": "Asia", "cn": "China", "n": "Shanghai", "lt": 31.2304, "ln": 121.4737},
    {"ct": "Asia", "cn": "China", "n": "Shenzhen", "lt": 22.5431, "ln": 114.0579},
    {"ct": "Asia", "cn": "Hong Kong", "n": "Hong Kong", "lt": 22.3193, "ln": 114.1694},
    {"ct": "Asia", "cn": "Taiwan", "n": "Taipei", "lt": 25.0330, "ln": 121.5654},
    {"ct": "Asia", "cn": "India", "n": "Mumbai", "lt": 19.0760, "ln": 72.8777},
    {"ct": "Asia", "cn": "India", "n": "Bengaluru", "lt": 12.9716, "ln": 77.5946},
    {"ct": "Asia", "cn": "India", "n": "New Delhi", "lt": 28.6139, "ln": 77.2090},
    {"ct": "Asia", "cn": "Indonesia", "n": "Jakarta", "lt": -6.2088, "ln": 106.8456},
    {"ct": "Asia", "cn": "Malaysia", "n": "Kuala Lumpur", "lt": 3.1390, "ln": 101.6869},
    {"ct": "Asia", "cn": "Vietnam", "n": "Hanoi", "lt": 21.0285, "ln": 105.8542},
    {"ct": "Asia", "cn": "Vietnam", "n": "Ho Chi Minh City", "lt": 10.8231, "ln": 106.6297},
    {"ct": "Asia", "cn": "Philippines", "n": "Manila", "lt": 14.5995, "ln": 120.9842},
    {"ct": "Asia", "cn": "United Arab Emirates", "n": "Dubai", "lt": 25.2048, "ln": 55.2708},
    {"ct": "Asia", "cn": "Israel", "n": "Tel Aviv", "lt": 32.0853, "ln": 34.7818},
    {"ct": "Asia", "cn": "Turkey", "n": "Istanbul", "lt": 41.0082, "ln": 28.9784},
    {"ct": "Europe", "cn": "United Kingdom", "n": "London", "lt": 51.5074, "ln": -0.1278},
    {"ct": "Europe", "cn": "United Kingdom", "n": "Manchester", "lt": 53.4808, "ln": -2.2426},
    {"ct": "Europe", "cn": "Germany", "n": "Frankfurt", "lt": 50.1109, "ln": 8.6821},
    {"ct": "Europe", "cn": "Germany", "n": "Berlin", "lt": 52.5200, "ln": 13.4050},
    {"ct": "Europe", "cn": "Germany", "n": "Munich", "lt": 48.1351, "ln": 11.5820},
    {"ct": "Europe", "cn": "Netherlands", "n": "Amsterdam", "lt": 52.3676, "ln": 4.9041},
    {"ct": "Europe", "cn": "France", "n": "Paris", "lt": 48.8566, "ln": 2.3522},
    {"ct": "Europe", "cn": "Ireland", "n": "Dublin", "lt": 53.3498, "ln": -6.2603},
    {"ct": "Europe", "cn": "Switzerland", "n": "Zurich", "lt": 47.3769, "ln": 8.5417},
    {"ct": "Europe", "cn": "Sweden", "n": "Stockholm", "lt": 59.3293, "ln": 18.0686},
    {"ct": "Europe", "cn": "Finland", "n": "Helsinki", "lt": 60.1699, "ln": 24.9384},
    {"ct": "Europe", "cn": "Poland", "n": "Warsaw", "lt": 52.2297, "ln": 21.0122},
    {"ct": "Europe", "cn": "Spain", "n": "Madrid", "lt": 40.4168, "ln": -3.7038},
    {"ct": "Europe", "cn": "Italy", "n": "Milan", "lt": 45.4642, "ln": 9.1900},
    {"ct": "Europe", "cn": "Romania", "n": "Bucharest", "lt": 44.4268, "ln": 26.1025},
    {"ct": "Europe", "cn": "Russia", "n": "Moscow", "lt": 55.7558, "ln": 37.6173},
    {"ct": "Europe", "cn": "Ukraine", "n": "Kyiv", "lt": 50.4501, "ln": 30.5234},
    {"ct": "North America", "cn": "United States", "n": "Ashburn", "lt": 39.0438, "ln": -77.4874},
    {"ct": "North America", "cn": "United States", "n": "New York", "lt": 40.7128, "ln": -74.0060},
    {"ct": "North America", "cn": "United States", "n": "San Francisco", "lt": 37.7749, "ln": -122.4194},
    {"ct": "North America", "cn": "United States", "n": "Mountain View", "lt": 37.3861, "ln": -122.0839},
    {"ct": "North America", "cn": "United States", "n": "Los Angeles", "lt": 34.0522, "ln": -118.2437},
    {"ct": "North America", "cn": "United States", "n": "Seattle", "lt": 47.6062, "ln": -122.3321},
    {"ct": "North America", "cn": "United States", "n": "Chicago", "lt": 41.8781, "ln": -87.6298},
    {"ct": "North America", "cn": "United States", "n": "Dallas", "lt": 32.7767, "ln": -96.7970},
    {"ct": "North America", "cn": "United States", "n": "Miami", "lt": 25.7617, "ln": -80.1918},
    {"ct": "North America", "cn": "Canada", "n": "Toronto", "lt": 43.6532, "ln": -79.3832},
    {"ct": "North America", "cn": "Canada", "n": "Montreal", "lt": 45.5017, "ln": -73.5673},
    {"ct": "North America", "cn": "Canada", "n": "Vancouver", "lt": 49.2827, "ln": -123.1207},
    {"ct": "North America", "cn": "Mexico", "n": "Mexico City", "lt": 19.4326, "ln": -99.1332},
    {"ct": "South America", "cn": "Brazil", "n": "Sao Paulo", "lt": -23.5505, "ln": -46.6333},
    {"ct": "South America", "cn": "Argentina", "n": "Buenos Aires", "lt": -34.6037, "ln": -58.3816},
    {"ct": "South America", "cn": "Chile", "n": "Santiago", "lt": -33.4489, "ln": -70.6693},
    {"ct": "South America", "cn": "Colombia", "n": "Bogota", "lt": 4.7110, "ln": -74.0721},
    {"ct": "Africa", "cn": "South Africa", "n": "Johannesburg", "lt": -26.2041, "ln": 28.0473},
    {"ct": "Africa", "cn": "South Africa", "n": "Cape Town", "lt": -33.9249, "ln": 18.4241},
    {"ct": "Africa", "cn": "Kenya", "n": "Nairobi", "lt": -1.2921, "ln": 36.8219},
    {"ct": "Africa", "cn": "Egypt", "n": "Cairo", "lt": 30.0444, "ln": 31.2357},
    {"ct": "Africa", "cn": "Nigeria", "n": "Lagos", "lt": 6.5244, "ln": 3.3792},
    {"ct": "Oceania", "cn": "Australia", "n": "Sydney", "lt": -33.8688, "ln": 151.2093},
    {"ct": "Oceania", "cn": "Australia", "n": "Melbourne", "lt": -37.8136, "ln": 144.9631},
    {"ct": "Oceania", "cn": "New Zealand", "n": "Auckland", "lt": -36.8485, "ln": 174.7633},
]

_EXACT_IP_GEO: dict[str, tuple[str, str, float, float, str]] = {
    "8.8.8.8": ("United States", "Mountain View", 37.3861, -122.0839, "North America"),
    "8.8.4.4": ("United States", "Mountain View", 37.3861, -122.0839, "North America"),
    "1.1.1.1": ("Australia", "Sydney", -33.8688, 151.2093, "Oceania"),
    "1.0.0.1": ("Australia", "Sydney", -33.8688, 151.2093, "Oceania"),
    "9.9.9.9": ("Switzerland", "Zurich", 47.3769, 8.5417, "Europe"),
    "149.112.112.112": ("Switzerland", "Zurich", 47.3769, 8.5417, "Europe"),
    "208.67.222.222": ("United States", "San Francisco", 37.7749, -122.4194, "North America"),
    "208.67.220.220": ("United States", "San Francisco", 37.7749, -122.4194, "North America"),
}

_PREFIX_GEO: list[tuple[ipaddress.IPv4Network, tuple[str, str, float, float, str]]] = [
    (ipaddress.ip_network("198.51.100.0/24"), ("Netherlands", "Amsterdam", 52.3676, 4.9041, "Europe")),
    (ipaddress.ip_network("203.0.113.0/24"), ("Japan", "Tokyo", 35.6762, 139.6503, "Asia")),
    (ipaddress.ip_network("192.0.2.0/24"), ("United States", "Ashburn", 39.0438, -77.4874, "North America")),
    (ipaddress.ip_network("13.64.0.0/11"), ("United States", "Ashburn", 39.0438, -77.4874, "North America")),
    (ipaddress.ip_network("18.128.0.0/9"), ("United States", "Ashburn", 39.0438, -77.4874, "North America")),
    (ipaddress.ip_network("20.0.0.0/8"), ("United States", "Seattle", 47.6062, -122.3321, "North America")),
    (ipaddress.ip_network("34.64.0.0/10"), ("United States", "Mountain View", 37.3861, -122.0839, "North America")),
    (ipaddress.ip_network("35.184.0.0/13"), ("United States", "Council Bluffs", 41.2619, -95.8608, "North America")),
    (ipaddress.ip_network("45.0.0.0/8"), ("Singapore", "Singapore", 1.3521, 103.8198, "Asia")),
    (ipaddress.ip_network("46.0.0.0/8"), ("Germany", "Frankfurt", 50.1109, 8.6821, "Europe")),
    (ipaddress.ip_network("52.0.0.0/8"), ("United States", "Ashburn", 39.0438, -77.4874, "North America")),
    (ipaddress.ip_network("54.0.0.0/8"), ("United States", "Ashburn", 39.0438, -77.4874, "North America")),
    (ipaddress.ip_network("77.0.0.0/8"), ("Germany", "Frankfurt", 50.1109, 8.6821, "Europe")),
    (ipaddress.ip_network("78.0.0.0/8"), ("United Kingdom", "London", 51.5074, -0.1278, "Europe")),
    (ipaddress.ip_network("79.0.0.0/8"), ("France", "Paris", 48.8566, 2.3522, "Europe")),
    (ipaddress.ip_network("80.0.0.0/8"), ("Netherlands", "Amsterdam", 52.3676, 4.9041, "Europe")),
    (ipaddress.ip_network("85.0.0.0/8"), ("Germany", "Berlin", 52.5200, 13.4050, "Europe")),
    (ipaddress.ip_network("91.0.0.0/8"), ("Russia", "Moscow", 55.7558, 37.6173, "Europe")),
    (ipaddress.ip_network("95.0.0.0/8"), ("Poland", "Warsaw", 52.2297, 21.0122, "Europe")),
    (ipaddress.ip_network("103.0.0.0/8"), ("Singapore", "Singapore", 1.3521, 103.8198, "Asia")),
    (ipaddress.ip_network("104.16.0.0/12"), ("United States", "San Francisco", 37.7749, -122.4194, "North America")),
    (ipaddress.ip_network("110.0.0.0/8"), ("China", "Beijing", 39.9042, 116.4074, "Asia")),
    (ipaddress.ip_network("114.0.0.0/8"), ("China", "Shanghai", 31.2304, 121.4737, "Asia")),
    (ipaddress.ip_network("119.0.0.0/8"), ("Hong Kong", "Hong Kong", 22.3193, 114.1694, "Asia")),
    (ipaddress.ip_network("121.0.0.0/8"), ("South Korea", "Seoul", 37.5665, 126.9780, "Asia")),
    (ipaddress.ip_network("125.0.0.0/8"), ("Japan", "Tokyo", 35.6762, 139.6503, "Asia")),
    (ipaddress.ip_network("139.0.0.0/8"), ("Netherlands", "Amsterdam", 52.3676, 4.9041, "Europe")),
    (ipaddress.ip_network("140.82.0.0/16"), ("United States", "San Francisco", 37.7749, -122.4194, "North America")),
    (ipaddress.ip_network("151.101.0.0/16"), ("United States", "San Francisco", 37.7749, -122.4194, "North America")),
    (ipaddress.ip_network("162.158.0.0/15"), ("United States", "San Francisco", 37.7749, -122.4194, "North America")),
    (ipaddress.ip_network("172.64.0.0/13"), ("United States", "San Francisco", 37.7749, -122.4194, "North America")),
    (ipaddress.ip_network("177.0.0.0/8"), ("Brazil", "Sao Paulo", -23.5505, -46.6333, "South America")),
    (ipaddress.ip_network("185.0.0.0/8"), ("Netherlands", "Amsterdam", 52.3676, 4.9041, "Europe")),
    (ipaddress.ip_network("188.0.0.0/8"), ("Germany", "Frankfurt", 50.1109, 8.6821, "Europe")),
    (ipaddress.ip_network("193.0.0.0/8"), ("United Kingdom", "London", 51.5074, -0.1278, "Europe")),
    (ipaddress.ip_network("196.0.0.0/8"), ("South Africa", "Johannesburg", -26.2041, 28.0473, "Africa")),
    (ipaddress.ip_network("200.0.0.0/8"), ("Brazil", "Sao Paulo", -23.5505, -46.6333, "South America")),
    (ipaddress.ip_network("202.0.0.0/7"), ("Thailand", "Bangkok", 13.7563, 100.5018, "Asia")),
    (ipaddress.ip_network("210.0.0.0/8"), ("Japan", "Tokyo", 35.6762, 139.6503, "Asia")),
    (ipaddress.ip_network("216.0.0.0/8"), ("United States", "New York", 40.7128, -74.0060, "North America")),
]


def load_geo_data(custom_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Return built-in city catalog merged with optional world_cities.json."""
    rows = list(BUILTIN_WORLD_CITIES)
    candidates: list[Path] = []
    if custom_path:
        candidates.append(Path(custom_path))
    candidates.append(Path(__file__).resolve().parents[1] / "assets" / "world_cities.json")
    for path in candidates:
        try:
            if path.is_file():
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, list):
                    rows = loaded
                    break
        except (OSError, json.JSONDecodeError):
            continue
    return rows


@lru_cache(maxsize=1)
def _geo_index() -> tuple[
    tuple[str, ...],
    dict[str, tuple[str, ...]],
    dict[str, tuple[str, ...]],
    dict[tuple[str, str], tuple[float, float]],
]:
    countries_by_continent: dict[str, set[str]] = defaultdict(set)
    cities_by_country: dict[str, set[str]] = defaultdict(set)
    locations: dict[tuple[str, str], tuple[float, float]] = {}

    for item in load_geo_data():
        try:
            continent = str(item["ct"])
            country = str(item["cn"])
            city = str(item["n"])
            loc = (float(item["lt"]), float(item["ln"]))
        except (KeyError, TypeError, ValueError):
            continue
        countries_by_continent[continent].add(country)
        cities_by_country[country].add(city)
        locations.setdefault((city, country), loc)

    countries = {ct: tuple(sorted(vals)) for ct, vals in countries_by_continent.items()}
    cities = {cn: tuple(sorted(vals)) for cn, vals in cities_by_country.items()}
    return tuple(sorted(countries)), countries, cities, locations


def get_continents() -> list[str]:
    return list(_geo_index()[0])


def get_countries(continent: str) -> list[str]:
    return list(_geo_index()[1].get(continent, ()))


def get_cities(country: str) -> list[str]:
    return list(_geo_index()[2].get(country, ()))


def get_location_details(city_name: str, country_name: str) -> tuple[float, float]:
    return _geo_index()[3].get((city_name, country_name), (0.0, 0.0))


class GeoIP:
    """Thread-safe GeoIP resolver using MaxMindDB -> geolite2 -> offline regional fallback."""

    _reader: Any = None
    _reader_kind: str = "none"
    _reader_path: str | None = None

    @classmethod
    def _ensure_reader(cls, geoip_db_path: str | Path | None = None) -> tuple[Any, str]:
        requested = str(geoip_db_path) if geoip_db_path else None
        if cls._reader is not None and (requested is None or requested == cls._reader_path):
            return cls._reader, cls._reader_kind

        if requested:
            p = Path(requested).expanduser()
            if p.is_file():
                try:
                    import maxminddb  # type: ignore[import-not-found]

                    cls._reader = maxminddb.open_database(str(p))
                    cls._reader_kind = "maxminddb"
                    cls._reader_path = requested
                    cls._lookup_cached.cache_clear()
                    return cls._reader, cls._reader_kind
                except Exception:
                    pass

        for default_mmdb in (
            Path(__file__).resolve().parents[1] / "assets" / "GeoLite2-City.mmdb",
            Path("/usr/share/GeoIP/GeoLite2-City.mmdb"),
            Path("/opt/homebrew/share/GeoIP/GeoLite2-City.mmdb"),
        ):
            if default_mmdb.is_file():
                try:
                    import maxminddb  # type: ignore[import-not-found]

                    cls._reader = maxminddb.open_database(str(default_mmdb))
                    cls._reader_kind = "maxminddb"
                    cls._reader_path = str(default_mmdb)
                    return cls._reader, cls._reader_kind
                except Exception:
                    pass

        try:
            from geolite2 import geolite2  # type: ignore[import-not-found]

            cls._reader = geolite2.reader()
            cls._reader_kind = "geolite2"
            cls._reader_path = None
            return cls._reader, cls._reader_kind
        except Exception:
            return None, "offline_catalog"

    @staticmethod
    def _offline_fallback(ip_str: str) -> tuple[str, str, str, float, float, str, str] | None:
        if ip_str in _EXACT_IP_GEO:
            country, city, lat, lon, continent = _EXACT_IP_GEO[ip_str]
            return (ip_str, country, city, lat, lon, continent, "offline_catalog")
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return None
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
            return None
        if isinstance(ip_obj, ipaddress.IPv4Address):
            for net, (country, city, lat, lon, continent) in _PREFIX_GEO:
                if ip_obj in net:
                    return (ip_str, country, city, lat, lon, continent, "offline_catalog")
            first = int(ip_str.split(".", 1)[0])
            if 1 <= first <= 50 or 63 <= first <= 76 or 96 <= first <= 99 or 128 <= first <= 176 or 192 <= first <= 199:
                return (ip_str, "United States", "Ashburn", 39.0438, -77.4874, "North America", "offline_catalog")
            if 51 <= first <= 62 or 77 <= first <= 95 or 141 <= first <= 151 or 178 <= first <= 195:
                return (ip_str, "Germany", "Frankfurt", 50.1109, 8.6821, "Europe", "offline_catalog")
            if 100 <= first <= 126 or 202 <= first <= 223:
                return (ip_str, "Singapore", "Singapore", 1.3521, 103.8198, "Asia", "offline_catalog")
            if 177 <= first <= 191 or 200 <= first <= 201:
                return (ip_str, "Brazil", "Sao Paulo", -23.5505, -46.6333, "South America", "offline_catalog")
            return (ip_str, "South Africa", "Johannesburg", -26.2041, 28.0473, "Africa", "offline_catalog")
        return None

    @staticmethod
    @lru_cache(maxsize=4096)
    def _lookup_cached(ip_str: str, reader_tag: str = "") -> tuple[str, str, str, float, float, str, str] | None:
        reader = GeoIP._reader
        kind = GeoIP._reader_kind
        if reader is not None:
            try:
                match = reader.get(ip_str)
                if match and isinstance(match, dict):
                    continent = match.get("continent", {}).get("names", {}).get("en", "Unknown")
                    country = match.get("country", {}).get("names", {}).get("en", "Unknown")
                    city = match.get("city", {}).get("names", {}).get("en", "Unknown")
                    loc = match.get("location", {})
                    lat = loc.get("latitude")
                    lon = loc.get("longitude")
                    if lat is not None and lon is not None and math.isfinite(float(lat)) and math.isfinite(float(lon)):
                        return (ip_str, str(country), str(city), float(lat), float(lon), str(continent), kind)
            except Exception:
                pass
        return GeoIP._offline_fallback(ip_str)

    @classmethod
    def lookup(cls, ip: str, *, geoip_db_path: str | Path | None = None) -> dict[str, Any] | None:
        ip_str = str(ip or "").strip()
        if not ip_str:
            return None
        _, kind = cls._ensure_reader(geoip_db_path)
        res = cls._lookup_cached(ip_str, f"{kind}:{cls._reader_path or ''}")
        if res is None:
            return None
        return {
            "ip": res[0],
            "country": res[1],
            "city": res[2],
            "lat": res[3],
            "lon": res[4],
            "continent": res[5],
            "source": res[6],
        }

    @classmethod
    def close(cls) -> None:
        if cls._reader is not None:
            try:
                if cls._reader_kind == "geolite2":
                    from geolite2 import geolite2  # type: ignore[import-not-found]

                    geolite2.close()
                elif hasattr(cls._reader, "close"):
                    cls._reader.close()
            except Exception:
                pass
        cls._reader = None
        cls._reader_kind = "none"
        cls._reader_path = None
        cls._lookup_cached.cache_clear()


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(value).strip())
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        return False


def build_world_map_flows(
    flows_or_evidence: list[Any],
    *,
    osint_ips: dict[str, Any] | None = None,
    home: dict[str, Any] | None = None,
    geoip_db_path: str | Path | None = None,
    max_arcs: int = 200,
) -> dict[str, Any]:
    """Build World Map arcs, peer points, and country/continent summaries from flows."""
    flows: list[dict[str, Any]] = []
    for item in flows_or_evidence or []:
        if isinstance(item, dict) and "kind" not in item:
            flows.append(item)
            continue
        kind = getattr(item, "kind", item.get("kind") if isinstance(item, dict) else None)
        attrs = getattr(item, "attributes", item.get("attributes") if isinstance(item, dict) else None) or {}
        if kind == "flow" and isinstance(attrs, dict):
            flows.append(attrs)
    home_cfg = {
        "lat": float((home or {}).get("lat", DEFAULT_HOME["lat"])),
        "lon": float((home or {}).get("lon", DEFAULT_HOME["lon"])),
        "city": str((home or {}).get("city", DEFAULT_HOME["city"])),
        "country": str((home or {}).get("country", DEFAULT_HOME["country"])),
        "continent": str((home or {}).get("continent", DEFAULT_HOME["continent"])),
    }

    ip_stats: dict[str, dict[str, Any]] = {}
    direction_totals: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0, "flows": 0})
    unmapped: set[str] = set()
    sources_used: set[str] = set()

    for f in flows or []:
        src = str(f.get("src", "") or "")
        dst = str(f.get("dst", "") or "")
        pkts = int(f.get("count", f.get("packets", 0)) or 0)
        nbytes = int(f.get("bytes", 0) or 0)
        src_pub = _is_public_ip(src)
        dst_pub = _is_public_ip(dst)

        if src_pub and dst_pub:
            direction_totals[(src, dst)]["packets"] += pkts
            direction_totals[(src, dst)]["bytes"] += nbytes
            direction_totals[(src, dst)]["flows"] += 1
        elif dst_pub:
            direction_totals[("HOME", dst)]["packets"] += pkts
            direction_totals[("HOME", dst)]["bytes"] += nbytes
            direction_totals[("HOME", dst)]["flows"] += 1
        elif src_pub:
            direction_totals[(src, "HOME")]["packets"] += pkts
            direction_totals[(src, "HOME")]["bytes"] += nbytes
            direction_totals[(src, "HOME")]["flows"] += 1

        for candidate in (src, dst):
            if not candidate or not _is_public_ip(candidate):
                continue
            if candidate not in ip_stats and candidate not in unmapped:
                geo = GeoIP.lookup(candidate, geoip_db_path=geoip_db_path)
                if geo is None:
                    unmapped.add(candidate)
                    continue
                sources_used.add(str(geo.get("source", "offline_catalog")))
                osint_entry = (osint_ips or {}).get(candidate, {})
                gn_class = str((osint_entry.get("greynoise") or {}).get("classification") or "")
                abuse_score = float(((osint_entry.get("abuseipdb") or {}).get("data") or {}).get("abuseConfidenceScore") or 0)
                vt_rep = float(((osint_entry.get("vt") or {}).get("data") or {}).get("attributes", {}).get("reputation") or 0)
                risk = "high" if (gn_class == "malicious" or abuse_score >= 50 or vt_rep < -5) else ("medium" if abuse_score >= 15 else "normal")
                ip_stats[candidate] = {
                    "ip": candidate,
                    "lat": geo["lat"],
                    "lon": geo["lon"],
                    "city": geo["city"],
                    "country": geo["country"],
                    "continent": geo["continent"],
                    "packets": 0,
                    "bytes": 0,
                    "flows": 0,
                    "risk": risk,
                    "ptr": osint_entry.get("ptr"),
                }
            if candidate in ip_stats:
                ip_stats[candidate]["packets"] += pkts
                ip_stats[candidate]["bytes"] += nbytes
                ip_stats[candidate]["flows"] += 1

    arcs: list[dict[str, Any]] = []
    ranked_edges = sorted(direction_totals.items(), key=lambda kv: (kv[1]["bytes"], kv[1]["packets"]), reverse=True)[:max_arcs]
    for (s_id, d_id), counts in ranked_edges:
        if s_id == "HOME":
            s_geo = home_cfg
            s_label = home_cfg["city"]
        else:
            s_geo = ip_stats.get(s_id)
            s_label = s_id
        if d_id == "HOME":
            d_geo = home_cfg
            d_label = home_cfg["city"]
        else:
            d_geo = ip_stats.get(d_id)
            d_label = d_id
        if not s_geo or not d_geo:
            continue
        risk = "normal"
        for peer_id in (s_id, d_id):
            if peer_id in ip_stats and ip_stats[peer_id]["risk"] == "high":
                risk = "high"
                break
            if peer_id in ip_stats and ip_stats[peer_id]["risk"] == "medium":
                risk = "medium"
        arcs.append(
            {
                "src": s_label,
                "dst": d_label,
                "src_id": s_id,
                "src_label": s_label,
                "dst_id": d_id,
                "dst_label": d_label,
                "src_lat": s_geo["lat"],
                "src_lon": s_geo["lon"],
                "dst_lat": d_geo["lat"],
                "dst_lon": d_geo["lon"],
                "src_country": s_geo["country"],
                "dst_country": d_geo["country"],
                "packets": counts["packets"],
                "bytes": counts["bytes"],
                "flows": counts["flows"],
                "risk": risk,
            }
        )

    country_agg: dict[str, dict[str, Any]] = {}
    continent_agg: dict[str, dict[str, Any]] = {}
    for pt in ip_stats.values():
        cn = pt["country"]
        ct = pt["continent"]
        c_row = country_agg.setdefault(
            cn,
            {
                "country": cn,
                "continent": ct,
                "ip_count": 0,
                "unique_ips": 0,
                "packets": 0,
                "bytes": 0,
                "high_risk_ips": 0,
            },
        )
        c_row["ip_count"] += 1
        c_row["unique_ips"] = c_row["ip_count"]
        c_row["packets"] += pt["packets"]
        c_row["bytes"] += pt["bytes"]
        if pt["risk"] == "high":
            c_row["high_risk_ips"] += 1

        ct_row = continent_agg.setdefault(
            ct,
            {"continent": ct, "ip_count": 0, "unique_ips": 0, "packets": 0, "bytes": 0},
        )
        ct_row["ip_count"] += 1
        ct_row["unique_ips"] = ct_row["ip_count"]
        ct_row["packets"] += pt["packets"]
        ct_row["bytes"] += pt["bytes"]

    points = sorted(ip_stats.values(), key=lambda p: (p["bytes"], p["packets"]), reverse=True)
    countries = sorted(country_agg.values(), key=lambda c: (c["bytes"], c["ip_count"]), reverse=True)
    continents = sorted(continent_agg.values(), key=lambda c: (c["bytes"], c["ip_count"]), reverse=True)

    return {
        "home": home_cfg,
        "points": points[:300],
        "arcs": arcs,
        "countries": countries[:50],
        "country_summary": countries[:50],
        "continents": continents,
        "continent_summary": continents,
        "mapped_public_ips": len(ip_stats),
        "unmapped_public_ips": len(unmapped),
        "mapped_ip_count": len(ip_stats),
        "unmapped_ip_count": len(unmapped),
        "source": next(iter(sources_used)) if sources_used else "offline_catalog",
    }


WORLD_LAND_PATHS: list[str] = [
    "M 42 75 L 95 58 L 160 55 L 222 48 L 285 52 L 325 75 L 335 98 L 308 118 L 295 142 L 278 165 L 258 178 L 265 198 L 248 202 L 235 190 L 218 208 L 232 225 L 255 245 L 268 258 L 245 256 L 225 232 L 195 215 L 178 195 L 155 162 L 145 125 L 118 98 L 82 95 L 48 88 Z",
    "M 342 22 L 415 16 L 442 36 L 420 62 L 385 82 L 352 72 L 338 45 Z",
    "M 262 190 L 295 194 L 298 202 L 266 198 Z",
    "M 272 248 L 308 232 L 352 242 L 398 268 L 408 292 L 392 332 L 365 362 L 335 398 L 318 438 L 298 446 L 286 418 L 292 365 L 278 318 L 265 278 Z",
    "M 476 92 L 494 86 L 502 108 L 482 114 Z",
    "M 480 122 L 505 112 L 516 95 L 535 60 L 568 48 L 605 56 L 622 78 L 598 95 L 595 118 L 575 135 L 558 148 L 538 142 L 522 152 L 500 144 L 478 142 Z",
    "M 455 158 L 512 154 L 568 164 L 610 185 L 638 228 L 624 252 L 602 288 L 585 335 L 558 352 L 532 342 L 518 298 L 508 265 L 472 245 L 452 212 L 445 182 Z",
    "M 624 298 L 638 295 L 635 330 L 620 332 Z",
    "M 595 62 L 668 46 L 765 44 L 882 54 L 948 64 L 932 82 L 888 92 L 865 112 L 845 142 L 838 172 L 818 195 L 795 215 L 775 238 L 760 228 L 748 208 L 725 202 L 705 228 L 692 204 L 665 192 L 635 208 L 615 192 L 602 162 L 578 148 L 588 118 Z",
    "M 875 118 L 892 108 L 902 132 L 882 154 L 868 148 Z",
    "M 772 252 L 802 262 L 796 276 L 764 265 Z M 812 248 L 845 252 L 852 268 L 818 264 Z",
    "M 815 312 L 875 302 L 918 322 L 928 358 L 902 385 L 852 382 L 812 365 L 806 335 Z",
    "M 962 368 L 980 356 L 986 382 L 966 402 Z",
]


__all__ = [
    "BUILTIN_WORLD_CITIES",
    "DEFAULT_HOME",
    "GeoIP",
    "WORLD_LAND_PATHS",
    "build_world_map_flows",
    "get_cities",
    "get_continents",
    "get_countries",
    "get_location_details",
    "load_geo_data",
]
