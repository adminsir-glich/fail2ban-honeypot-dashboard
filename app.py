"""
app.py — FastAPI dashboard backend for the dnsmalik.fail2ban honeypot.

Reads from three sources:
  • /opt/cowrie/var/log/cowrie/cowrie.json  — honeypot SSH attempts (the juicy data)
  • /var/log/fail2ban.log                  — bans being applied
  • /var/log/auth.log                     — real-SSH (port 2222) failures

Exposes 9 JSON endpoints. All live under /api/*.
Static dashboard served from /  (so the user can put their Globe.gl UI at /fail2ban via nginx).
"""
import asyncio
import json
import os
import re
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from geoip import lookup as geo_lookup
from watcher import CowrieTailer, AuthLogTailer

# ─── Configuration ────────────────────────────────────────────────────────────
COWRIE_LOG = "/opt/cowrie/var/log/cowrie/cowrie.json"
FAIL2BAN_LOG = "/var/log/fail2ban.log"
AUTH_LOG = "/var/log/auth.log"

# For the Globe.gl "your server" pin
SELF_LAT = 33.4656
SELF_LON = -111.9956
SELF_LABEL = "PHX1 (Honeypot)"

import secrets
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

security = HTTPBasic()

def get_current_username(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, "fail2ban")
    correct_password = secrets.compare_digest(credentials.password, "hello")
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# ─── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(title="dnsmalik.fail2ban API", version="1.0.0", dependencies=[Depends(get_current_username)])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Background state ────────────────────────────────────────────────────────
state = {
    "events": [],          # list of parsed cowrie events (most recent first)
    "max_events": 5000,    # keep this many in memory
    "geo_cache": {},       # ip -> geo dict (also kept in geoip.py)
    "last_attack_ts": None,
}

tailer = CowrieTailer(COWRIE_LOG)
auth_tailer = AuthLogTailer(AUTH_LOG)


async def _absorber_loop():
    """Always-on subscriber that absorbs every new event into state,
    regardless of whether any SSE client is connected."""
    q = tailer.subscribe()
    while True:
        ev = await q.get()
        # Avoid double-absorbing events from auth.log
        if isinstance(ev, dict) and ev.get("is_real_ssh"):
            continue
        _absorb_event(ev)


async def _auth_absorber_loop():
    """Always-on subscriber that absorbs every new auth.log event into state,
    and broadcasts it to the SSE stream."""
    q = auth_tailer.subscribe()
    while True:
        ev = await q.get()
        _absorb_event(ev)
        await tailer.broadcast(ev)


async def geo_lookup_background(ip: str):
    """Asynchronously resolve IP geo details in the background."""
    try:
        g = await geo_lookup(ip)
        state["geo_cache"][ip] = g
    except Exception:
        pass


def _tail_file(filepath: str, n: int = 500) -> list[str]:
    """Efficiently read the last n lines of a file without loading it entirely into RAM."""
    lines = []
    chunk_size = 4096
    if not Path(filepath).exists():
        return lines
    try:
        with open(filepath, "rb") as f:
            f.seek(0, 2)
            file_size = f.tell()
            offset = 0
            while len(lines) <= n and offset < file_size:
                offset += chunk_size
                if offset > file_size:
                    offset = file_size
                f.seek(-offset, 2)
                chunk = f.read(chunk_size)
                lines = chunk.split(b"\n") + lines[1:] if lines else chunk.split(b"\n")
            
            decoded = [line.decode("utf-8", errors="replace").strip() for line in lines[-n:]]
            return [line for line in decoded if line]
    except Exception:
        with open(filepath, "r", errors="replace") as f:
            return [line.strip() for line in f.readlines()[-n:] if line.strip()]


@app.on_event("startup")
async def startup():
    loop = asyncio.get_running_loop()
    tailer.start(loop)
    auth_tailer.start(loop)
    # Pre-load existing events into state
    if Path(COWRIE_LOG).exists():
        lines = _tail_file(COWRIE_LOG, state["max_events"])
        for line in lines:
            try:
                ev = json.loads(line)
                _absorb_event(ev)
            except json.JSONDecodeError:
                continue
    # Pre-load existing auth.log events (up to 1000 lines) into state
    if Path(AUTH_LOG).exists():
        try:
            lines = _tail_file(AUTH_LOG, 1000)
            for line in lines:
                ev = auth_tailer._parse_line(line)
                if ev:
                    _absorb_event(ev)
        except Exception as e:
            print(f"[startup] error preloading auth.log: {e}")

    # Start the always-on absorbers
    asyncio.create_task(_absorber_loop())
    asyncio.create_task(_auth_absorber_loop())


def _absorb_event(ev):
    """Update in-memory state from a parsed cowrie event."""
    if isinstance(ev, str):
        try:
            ev = json.loads(ev)
        except Exception:
            return
    if not isinstance(ev, dict):
        return

    state["events"].append(ev)
    if len(state["events"]) > state["max_events"]:
        state["events"] = state["events"][-state["max_events"]:]
    ts = ev.get("timestamp")
    if ts and (state["last_attack_ts"] is None or ts > state["last_attack_ts"]):
        state["last_attack_ts"] = ts
    
    # Proactively trigger GeoIP / ASN lookup for incoming events in the background
    ip = ev.get("src_ip")
    if ip and ip not in state["geo_cache"]:
        asyncio.create_task(geo_lookup_background(ip))


# ─── Helper: read fail2ban bans from fail2ban.log + DB ──────────────────────
def _read_fail2ban_bans() -> list[dict]:
    bans = []
    if not Path(FAIL2BAN_LOG).exists():
        return bans
    try:
        with open(FAIL2BAN_LOG, "r", errors="replace") as f:
            lines = f.readlines()
    except PermissionError:
        return bans
    # find last "Ban <ip>" per jail from the tail of the log (lightweight)
    last_ban: dict[str, dict] = {}  # key=(jail, ip) -> info
    ban_re = re.compile(r"\[(\w+)\] Ban (\S+)")
    unban_re = re.compile(r"\[(\w+)\] Unban (\S+)")
    for line in lines[-2000:]:
        m = ban_re.search(line)
        if m:
            jail, ip = m.group(1), m.group(2)
            ts_str = line.split(",")[0].strip()
            # calculate banned_until
            try:
                from datetime import datetime, timezone
                dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                bantime = 3600
                if jail == "cowrie":
                    bantime = 86400
                elif jail == "recidive":
                    bantime = 604800
                banned_until = dt.replace(tzinfo=timezone.utc).timestamp() + bantime
            except Exception:
                banned_until = 0.0
            last_ban[(jail, ip)] = {
                "jail": jail,
                "ip": ip,
                "banned_at": ts_str,
                "banned_until": banned_until
            }
        m = unban_re.search(line)
        if m:
            last_ban.pop((m.group(1), m.group(2)), None)
    return list(last_ban.values())


# ─── ROUTES ──────────────────────────────────────────────────────────────────

@app.get("/api/sys/stats")
async def system_stats():
    """Query the local stats collector API on port 8085 and return system metrics."""
    uptime_secs = 0.0
    try:
        with open("/proc/uptime", "r") as f:
            uptime_secs = float(f.readline().split()[0])
    except Exception:
        pass

    # Real jail count from fail2ban
    jail_count = 0
    jail_names = []
    try:
        import subprocess as sp
        result = sp.run(
            ["sudo", "fail2ban-client", "status"],
            capture_output=True, text=True, timeout=2
        )
        for line in result.stdout.splitlines():
            if "Number of jail:" in line:
                jail_count = int(line.split(":")[-1].strip())
            if "Jail list:" in line:
                jail_names = [j.strip() for j in line.split(":")[-1].split(",")]
    except Exception:
        pass

    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            r = await client.get("http://127.0.0.1:8085/api/stats")
            data = r.json()
            return {
                "cpu": data.get("cpu_usage", 0.0),
                "mem": data.get("mem_usage", 0.0),
                "net_speed": data.get("net_speed_text", "0 KB/s"),
                "active_conns": data.get("active_conns", 0),
                "uptime": uptime_secs,
                "jail_count": jail_count,
                "jail_names": jail_names
            }
    except Exception:
        return {
            "cpu": 0.0,
            "mem": 0.0,
            "net_speed": "0 KB/s",
            "active_conns": 0,
            "uptime": uptime_secs,
            "jail_count": jail_count,
            "jail_names": jail_names
        }

@app.get("/api/health")
async def health():
    return {"ok": True, "ts": time.time(), "events_in_memory": len(state["events"])}


@app.get("/api/stats/summary")
async def stats_summary():
    """Big-number cards: total attacks, unique IPs, unique countries, active bans, last attack, unique ASNs."""
    events = state["events"]
    ips = {e.get("src_ip") for e in events if e.get("src_ip")}
    countries = set()
    asns = set()
    for ip in ips:
        g = state["geo_cache"].get(ip)
        if g:
            countries.add(g.get("country_code", "??"))
            if g.get("asn"):
                asns.add(g["asn"])
    return {
        "total_events": len(events),
        "total_failed_logins": sum(1 for e in events if e.get("eventid") == "cowrie.login.failed"),
        "unique_ips": len(ips),
        "unique_countries": len(countries),
        "unique_asns": len(asns),
        "active_bans": len(_read_fail2ban_bans()),
        "last_attack_ts": state["last_attack_ts"],
        "server": {"lat": SELF_LAT, "lon": SELF_LON, "label": SELF_LABEL},
    }


@app.get("/api/attacks/recent")
async def attacks_recent(limit: int = Query(50, le=500)):
    """Latest N attacks — IP, country, username, password, timestamp, ASN, org."""
    out = []
    # Iterate reversed (newest first) without copying the whole list
    for ev in reversed(state["events"]):
        if ev.get("eventid") not in ("cowrie.login.failed", "cowrie.login.success"):
            continue
        ip = ev.get("src_ip", "?")
        geo = state["geo_cache"].get(ip, {})
        out.append({
            "ts": ev.get("timestamp"),
            "ip": ip,
            "country_code": geo.get("country_code", "??"),
            "country": geo.get("country", "Unknown"),
            "username": ev.get("username"),
            "password": ev.get("password"),
            "session": ev.get("session"),
            "asn": geo.get("asn", ""),
            "org": geo.get("org", ""),
            "ssh_version": "",  # filled from cowrie.client.version event
            "eventid": ev.get("eventid"),
            "is_real_ssh": ev.get("is_real_ssh", False)
        })
        if len(out) >= limit:
            break
    # Fill ssh_version from cached client.version events
    versions = {e.get("session"): e.get("version") for e in reversed(state["events"][-500:])
                if e.get("eventid") == "cowrie.client.version"}
    for item in out:
        item["ssh_version"] = versions.get(item["session"], "")
    return out


@app.get("/api/attacks/geo")
async def attacks_geo():
    """Data for Globe.gl: [{ip, lat, lon, count, country, country_code, asn, org}, ...]"""
    counter: Counter = Counter()
    for ev in state["events"]:
        if ev.get("eventid") in ("cowrie.login.failed", "cowrie.login.success"):
            ip = ev.get("src_ip")
            if ip:
                counter[ip] += 1
    out = []
    for ip, count in counter.most_common():
        geo = state["geo_cache"].get(ip)
        if not geo:
            # Sync lookup is OK for small N; for big sets we'd cache async
            geo = await geo_lookup(ip)
            state["geo_cache"][ip] = geo
        out.append({
            "ip": ip,
            "lat": geo["lat"],
            "lon": geo["lon"],
            "country": geo["country"],
            "country_code": geo["country_code"],
            "asn": geo.get("asn", ""),
            "org": geo.get("org", ""),
            "count": count,
        })
    return out


@app.get("/api/passwords/top")
async def passwords_top(limit: int = Query(20, le=100)):
    """Most-tried passwords: [{password, count}, ...]"""
    c: Counter = Counter()
    for ev in state["events"]:
        if ev.get("eventid") in ("cowrie.login.failed", "cowrie.login.success"):
            pw = ev.get("password")
            if pw and "[REDACTED]" not in pw:
                c[pw] += 1
    return [{"password": p, "count": n} for p, n in c.most_common(limit)]


@app.get("/api/usernames/top")
async def usernames_top(limit: int = Query(20, le=100)):
    c: Counter = Counter()
    for ev in state["events"]:
        if ev.get("eventid") in ("cowrie.login.failed", "cowrie.login.success"):
            u = ev.get("username")
            if u:
                c[u] += 1
    return [{"username": u, "count": n} for u, n in c.most_common(limit)]


@app.get("/api/countries/top")
async def countries_top(limit: int = Query(20, le=100)):
    c: Counter = Counter()
    for ev in state["events"]:
        if ev.get("eventid") in ("cowrie.login.failed", "cowrie.login.success"):
            ip = ev.get("src_ip")
            geo = state["geo_cache"].get(ip) if ip else None
            if geo and geo.get("country_code") not in (None, "??", "LO"):
                c[(geo["country_code"], geo["country"])] += 1
    return [{"country_code": cc, "country": name, "count": n}
            for (cc, name), n in c.most_common(limit)]


@app.get("/api/asns/top")
async def asns_top(limit: int = Query(8, le=100)):
    c: Counter = Counter()
    for ev in state["events"]:
        if ev.get("eventid") in ("cowrie.login.failed", "cowrie.login.success"):
            ip = ev.get("src_ip")
            geo = state["geo_cache"].get(ip) if ip else None
            if geo and geo.get("asn"):
                c[(geo["asn"], geo.get("org", "Unknown"))] += 1
    return [{"asn": asn, "org": org, "count": n} for (asn, org), n in c.most_common(limit)]


@app.get("/api/timeseries")
async def timeseries(bucket: str = Query("hour", pattern="^(minute|hour|day)$")):
    """Bucketed counts: [{ts, count}, ...] sorted oldest -> newest."""
    bucket_secs = {"minute": 60, "hour": 3600, "day": 86400}[bucket]
    c: Counter = Counter()
    for ev in state["events"]:
        if ev.get("eventid") not in ("cowrie.login.failed", "cowrie.login.success"):
            continue
        ts = ev.get("timestamp")
        if not ts:
            continue
        try:
            epoch = time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
            bucket_start = int(epoch // bucket_secs) * bucket_secs
            c[bucket_start] += 1
        except Exception:
            continue
    return [{"ts": k, "count": v} for k, v in sorted(c.items())]


@app.get("/api/bans/active")
async def bans_active():
    return _read_fail2ban_bans()


@app.get("/api/stream")
async def stream(request: Request):
    """Server-Sent Events: push each new cowrie event to subscribed clients."""
    queue = tailer.subscribe()

    async def event_gen():
        try:
            yield f"data: {json.dumps({'eventid': 'hello', 'ts': time.time()})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    ev = await asyncio.wait_for(queue.get(), timeout=15.0)
                    ip = ev.get("src_ip")
                    if ip and ip not in state["geo_cache"]:
                        g = await geo_lookup(ip)
                        state["geo_cache"][ip] = g
                    else:
                        g = state["geo_cache"].get(ip, {})
                    
                    # Enrich event with GeoIP details for the stream
                    ev_enriched = dict(ev)
                    ev_enriched["lat"] = g.get("lat", 0.0)
                    ev_enriched["lon"] = g.get("lon", 0.0)
                    ev_enriched["country"] = g.get("country", "Unknown")
                    ev_enriched["country_code"] = g.get("country_code", "??")
                    ev_enriched["asn"] = g.get("asn", "")
                    ev_enriched["org"] = g.get("org", "")
                    
                    yield f"data: {json.dumps(ev_enriched, default=str)}\n\n"
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            tailer.unsubscribe(queue)

    return StreamingResponse(event_gen(), media_type="text/event-stream")


@app.get("/api/sessions/{session_id}")
async def get_session_details(session_id: str):
    """Return all logs associated with a specific Cowrie session ID."""
    session_events = []
    if Path(COWRIE_LOG).exists():
        try:
            with open(COWRIE_LOG, "r", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                        if ev.get("session") == session_id:
                            session_events.append(ev)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    return session_events


# ─── Static dashboard ────────────────────────────────────────────────────────
STATIC_DIR = Path(__file__).parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def root_index():
    idx = STATIC_DIR / "index.html"
    if idx.exists():
        headers = {
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0"
        }
        return FileResponse(idx, headers=headers)
    return JSONResponse({
        "msg": "dnsmalik.fail2ban API is running. Dashboard not yet built.",
        "endpoints": [
            "/api/health", "/api/stats/summary",
            "/api/attacks/recent", "/api/attacks/geo",
            "/api/passwords/top", "/api/usernames/top",
            "/api/countries/top", "/api/timeseries",
            "/api/bans/active", "/api/stream",
        ],
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")
