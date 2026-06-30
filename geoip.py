"""
geoip.py — IP -> (latitude, longitude, country, country_code, asn, org) using local MaxMind MMDB databases.
"""
import time
from pathlib import Path
import geoip2.database

CITY_DB = "/opt/dnsmalik-dashboard/geoip_db/GeoLite2-City.mmdb"
ASN_DB = "/opt/dnsmalik-dashboard/geoip_db/GeoLite2-ASN.mmdb"

# Global readers
_city_reader = None
_asn_reader = None

def get_city_reader():
    global _city_reader
    if _city_reader is None and Path(CITY_DB).exists():
        try:
            _city_reader = geoip2.database.Reader(CITY_DB)
        except Exception:
            pass
    return _city_reader

def get_asn_reader():
    global _asn_reader
    if _asn_reader is None and Path(ASN_DB).exists():
        try:
            _asn_reader = geoip2.database.Reader(ASN_DB)
        except Exception:
            pass
    return _asn_reader

async def lookup(ip: str, client = None) -> dict:
    """
    Resolve IP to geo and ASN data using local MMDB databases.
    Returns dict with ip, lat, lon, country, country_code, asn, org, source.
    """
    if not ip:
        return {
            "ip": ip,
            "lat": 0.0,
            "lon": 0.0,
            "country": "Unknown",
            "country_code": "??",
            "asn": "",
            "org": "",
            "source": "fallback",
        }

    if ip.startswith(("127.", "10.", "192.168.", "172.16.", "::1", "fe80:")):
        return {
            "ip": ip,
            "lat": 0.0,
            "lon": 0.0,
            "country": "Local Network",
            "country_code": "LO",
            "asn": "AS0",
            "org": "Private Network",
            "source": "private",
        }

    result = {
        "ip": ip,
        "lat": 0.0,
        "lon": 0.0,
        "country": "Unknown",
        "country_code": "??",
        "asn": "",
        "org": "",
        "source": "maxmind",
    }

    creader = get_city_reader()
    if creader:
        try:
            res = creader.city(ip)
            if res.location.latitude is not None:
                result["lat"] = res.location.latitude
            if res.location.longitude is not None:
                result["lon"] = res.location.longitude
            if res.country.name is not None:
                result["country"] = res.country.name
            if res.country.iso_code is not None:
                result["country_code"] = res.country.iso_code
        except Exception:
            pass

    areader = get_asn_reader()
    if areader:
        try:
            res = areader.asn(ip)
            if res.autonomous_system_number is not None:
                result["asn"] = f"AS{res.autonomous_system_number}"
            if res.autonomous_system_organization is not None:
                result["org"] = res.autonomous_system_organization
        except Exception:
            pass

    return result
