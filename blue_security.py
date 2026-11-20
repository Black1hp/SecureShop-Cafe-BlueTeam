"""CET431 typing behavior, geolocation and session-risk security primitives.

Browser keystroke timings and geolocation are untrusted signals, never authentication.
"""
import json
import math
import statistics
from datetime import datetime
from zoneinfo import ZoneInfo

ANOMALY_THRESHOLD = 3.0
FEATURES = ('speed', 'gap_1', 'gap_2', 'gap_3', 'gap_4', 'gap_5')


def parse_timing(raw):
    """Use compact aggregate timing features; no keys or typed strings are collected."""
    if not isinstance(raw, str) or len(raw) > 1024:
        return None
    try:
        data = json.loads(raw)
        gaps = data['gaps']
        if not isinstance(gaps, list) or not 5 <= len(gaps) <= 80:
            return None
        if any(type(g) not in (float, int) or not math.isfinite(g) or g < 10 or g > 3000 for g in gaps):
            return None
        total = sum(gaps) / 1000
        sample = {'speed': round(len(gaps) / total, 4)}
        for i, gap in enumerate(gaps[:5], start=1):
            sample['gap_' + str(i)] = int(round(gap / 20.0) * 20)  # 20 ms quantization
        return sample
    except (KeyError, ValueError, TypeError, json.JSONDecodeError, ZeroDivisionError):
        return None


def build_profile(samples):
    if len(samples) < 5:
        raise ValueError('Five samples required')
    return {f: {'mean': statistics.mean(s[f] for s in samples),
                'std': max(statistics.pstdev(s[f] for s in samples), 0.1 if f == 'speed' else 20.0)} for f in FEATURES}


def anomaly_score(sample, profile):
    return sum(abs(sample[f] - profile[f]['mean']) / max(profile[f]['std'], 0.1 if f == 'speed' else 20.0)
               for f in FEATURES) / len(FEATURES)


def haversine_km(lat1, lon1, lat2, lon2):
    values = (lat1, lon1, lat2, lon2)
    if any(not isinstance(x, (int, float)) or not math.isfinite(x) for x in values):
        raise ValueError('Invalid coordinates')
    if abs(lat1) > 90 or abs(lat2) > 90 or abs(lon1) > 180 or abs(lon2) > 180:
        raise ValueError('Invalid coordinate range')
    a, b = math.radians(lat1), math.radians(lat2)
    delta_lat, delta_lon = b - a, math.radians(lon2 - lon1)
    h = math.sin(delta_lat / 2)**2 + math.cos(a) * math.cos(b) * math.sin(delta_lon / 2)**2
    return 6371.0 * 2 * math.atan2(math.sqrt(h), math.sqrt(max(0.0, 1.0 - h)))


def local_hour_ok(now=None, zone='Africa/Cairo'):
    now = datetime.now(ZoneInfo(zone)) if now is None else now.astimezone(ZoneInfo(zone))
    return 8 <= now.hour < 22


def location_time_result(lat, lon, home_lat, home_lon, now=None):
    distance = haversine_km(lat, lon, home_lat, home_lon)
    if distance > 50:
        return False, 'location', distance
    if not local_hour_ok(now):
        return False, 'time', distance
    return True, 'allow', distance
