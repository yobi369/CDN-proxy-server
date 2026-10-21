#!/usr/bin/env python3
"""Self-hostable HTTP caching proxy with a conservative adaptive policy."""
from __future__ import annotations
import asyncio, hashlib, hmac, ipaddress, json, logging, os, socket, sqlite3, time
from collections import OrderedDict, defaultdict, deque
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit
import aiohttp
from aiohttp import web

LOG = logging.getLogger("edgeproxy")

def env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        value = int(os.getenv(name, str(default)))
        return value if value >= minimum else default
    except ValueError:
        return default

class Config:
    host = os.getenv("PROXY_HOST", "127.0.0.1")
    port = env_int("PROXY_PORT", 8080)
    cache_dir = Path(os.getenv("PROXY_CACHE_DIR", "./cache"))
    db_path = os.getenv("PROXY_ANALYTICS_DB", "./analytics.db")
    max_cache_bytes = env_int("PROXY_MAX_CACHE_BYTES", 256 * 1024 * 1024)
    max_object_bytes = env_int("PROXY_MAX_OBJECT_BYTES", 8 * 1024 * 1024)
    default_ttl = env_int("PROXY_DEFAULT_TTL", 300)
    max_ttl = env_int("PROXY_MAX_TTL", 86400)
    timeout_seconds = env_int("PROXY_TIMEOUT_SECONDS", 15)
    max_requests_per_minute = env_int("PROXY_RATE_LIMIT", 120)
    allowed_hosts = frozenset(h.strip().lower().rstrip(".") for h in os.getenv("CDN_ALLOWED_HOSTS", "").split(",") if h.strip())
    stats_token = os.getenv("PROXY_STATS_TOKEN", "")

def validate_target(raw_url: str, allowed_hosts: frozenset[str]) -> str:
    """Validate absolute HTTP(S) URL and enforce exact hostname allowlisting."""
    if not raw_url or len(raw_url) > 4096:
        raise web.HTTPBadRequest(text="Invalid URL")
    try:
        parsed = urlsplit(raw_url)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError:
        raise web.HTTPBadRequest(text="Malformed URL")
    if parsed.scheme not in ("http", "https") or not hostname:
        raise web.HTTPBadRequest(text="Only absolute HTTP(S) URLs are supported")
    if parsed.username is not None or parsed.password is not None:
        raise web.HTTPBadRequest(text="Credentials in URLs are not allowed")
    expected_port = 443 if parsed.scheme == "https" else 80
    if port is not None and port != expected_port:
        raise web.HTTPBadRequest(text="Only the default port for the selected scheme is allowed")
    if not allowed_hosts or hostname not in allowed_hosts:
        raise web.HTTPForbidden(text="Target host is not in CDN_ALLOWED_HOSTS")
    return parsed.geturl()

def cache_policy(headers: dict[str, str], default_ttl: int, max_ttl: int) -> int:
    """Return remaining freshness seconds; zero means response is not safe to cache."""
    lowered = {str(k).lower(): str(v) for k, v in headers.items()}
    directives = {}
    for part in lowered.get("cache-control", "").lower().split(","):
        key, sep, value = part.strip().partition("=")
        if key:
            directives[key] = value.strip('"') if sep else None
    if any(k in directives for k in ("no-store", "private", "no-cache")):
        return 0
    if "no-cache" in lowered.get("pragma", "").lower():
        return 0
    if "set-cookie" in lowered or "vary" in lowered:
        # Until Vary-aware cache keys are implemented, never cache variant responses.
        return 0

    raw = directives.get("s-maxage", directives.get("max-age"))
    try:
        if raw is not None:
            ttl = int(raw)
        elif "expires" in lowered:
            expires = parsedate_to_datetime(lowered["expires"])
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            date_value = lowered.get("date")
            if date_value:
                origin_date = parsedate_to_datetime(date_value)
                if origin_date.tzinfo is None:
                    origin_date = origin_date.replace(tzinfo=timezone.utc)
            else:
                origin_date = datetime.now(timezone.utc)
            ttl = int((expires - origin_date).total_seconds())
        else:
            ttl = default_ttl
        age = max(0, int(lowered.get("age", "0")))
    except (ValueError, TypeError, OverflowError):
        return 0
    return max(0, min(ttl - age, max_ttl))

def is_public_ip(value: str) -> bool:
    """Return whether an IP address is globally routable (not private/reserved)."""
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False

class PublicOnlyResolver(aiohttp.abc.AbstractResolver):
    """Resolve hostnames once and reject non-global IPs to reduce SSRF/DNS-rebinding risk."""
    async def resolve(self, host, port=0, family=socket.AF_INET):
        loop = asyncio.get_running_loop()
        records = await loop.getaddrinfo(host, port, family=family, type=socket.SOCK_STREAM)
        resolved = []
        for record_family, _, proto, _, sockaddr in records:
            if not is_public_ip(sockaddr[0]):
                raise OSError("Refusing to connect to a non-public IP address")
            resolved.append({
                "hostname": host, "host": sockaddr[0], "port": sockaddr[1],
                "family": record_family, "proto": proto, "flags": socket.AI_NUMERICHOST,
            })
        if not resolved:
            raise OSError("Hostname did not resolve to a public address")
        return resolved

    async def close(self):
        return None

def request_may_use_cache(request):
    """Avoid shared caching for request-specific credentials or cache bypass directives."""
    if request.headers.get("Authorization") or request.headers.get("Cookie"):
        return False
    directives = request.headers.get("Cache-Control", "").lower()
    return "no-cache" not in directives and "no-store" not in directives

class AdaptivePolicy:
    """Explainable research baseline with bounded per-object history."""
    def __init__(self, max_keys: int = 10000):
        self.max_keys = max(1, max_keys)
        self.counts = OrderedDict()

    def record(self, key: str, hit: bool):
        counts = self.counts.setdefault(key, [0, 0])  # [hits, misses]
        counts[0 if hit else 1] += 1
        self.counts.move_to_end(key)
        while len(self.counts) > self.max_keys:
            self.counts.popitem(last=False)

    def adjust_ttl(self, key: str, origin_ttl: int) -> int:
        if origin_ttl <= 0:
            return 0
        hits, misses = self.counts.get(key, (0, 0))
        total = hits + misses
        if total >= 3 and hits / total >= 0.6:
            return origin_ttl
        return max(1, min(origin_ttl, origin_ttl // 2 or 1))

class CDNServer:
    def __init__(self):
        Config.cache_dir.mkdir(parents=True, exist_ok=True)
        self.session = None
        self.cache_lock = asyncio.Lock()
        self.rate_events = defaultdict(deque)
        self.policy = AdaptivePolicy()
        self.stats = {"hits": 0, "misses": 0, "bypasses": 0, "bytes_served": 0}
        with sqlite3.connect(Config.db_path) as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, client_ip TEXT,
                target_host TEXT NOT NULL, cache_status TEXT NOT NULL,
                response_size INTEGER NOT NULL, response_time_ms REAL NOT NULL)""")

    async def start(self, app):
        timeout = aiohttp.ClientTimeout(total=Config.timeout_seconds)
        connector = aiohttp.TCPConnector(limit=100, ttl_dns_cache=60, resolver=PublicOnlyResolver())
        self.session = aiohttp.ClientSession(timeout=timeout, connector=connector,
            auto_decompress=False, headers={"User-Agent": "CDN-Proxy-Server/2.0"})

    async def close(self, app):
        if self.session:
            await self.session.close()

    def _paths(self, target):
        key = hashlib.sha256(target.encode("utf-8")).hexdigest()
        return Config.cache_dir / f"{key}.body", Config.cache_dir / f"{key}.json"

    def _cache_size(self):
        total = 0
        try:
            for p in Config.cache_dir.iterdir():
                if p.is_file() and p.suffix in (".body", ".json"):
                    try: total += p.stat().st_size
                    except OSError: pass
        except OSError: pass
        return total

    async def _read_cache(self, target):
        body_path, meta_path = self._paths(target)
        try:
            meta = json.loads(await asyncio.to_thread(meta_path.read_text, encoding="utf-8"))
            age = time.time() - float(meta["stored_at"])
            if age < 0 or age >= int(meta["ttl"]): return None
            body = await asyncio.to_thread(body_path.read_bytes)
            return body, meta
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None

    async def _write_cache(self, target, body, headers, ttl):
        if ttl <= 0 or len(body) > Config.max_object_bytes or len(body) > Config.max_cache_bytes:
            return False
        async with self.cache_lock:
            return await self._write_cache_locked(target, body, headers, ttl)

    async def _write_cache_locked(self, target, body, headers, ttl):
        body_path, meta_path = self._paths(target)
        stored_at = time.time()
        meta = {"stored_at": stored_at, "ttl": ttl, "size": len(body), "headers": headers}
        meta_bytes = json.dumps(meta, separators=(",", ":")).encode("utf-8")
        new_size = len(body) + len(meta_bytes)
        if new_size > Config.max_cache_bytes:
            return False

        try:
            entries, size = [], 0
            for mp in Config.cache_dir.glob("*.json"):
                bp = mp.with_suffix(".body")
                try:
                    meta_size = mp.stat().st_size
                    body_size = bp.stat().st_size if bp.exists() else 0
                    if mp == meta_path:
                        continue
                    size += meta_size + body_size
                    try:
                        old_meta = json.loads(await asyncio.to_thread(mp.read_text, encoding="utf-8"))
                        stored = float(old_meta.get("stored_at", 0))
                    except (OSError, ValueError, TypeError):
                        stored = 0
                    entries.append((stored, mp, bp, meta_size + body_size))
                except OSError:
                    continue

            # Remove orphaned body files so abandoned writes do not consume the budget forever.
            known_bodies = {entry[2].name for entry in entries}
            known_bodies.add(body_path.name)
            for orphan in Config.cache_dir.glob("*.body"):
                if orphan.name not in known_bodies:
                    try:
                        orphan.unlink()
                    except OSError:
                        pass

            for _, old_meta, old_body, old_size in sorted(entries):
                if size + new_size <= Config.max_cache_bytes:
                    break
                try:
                    old_body.unlink(missing_ok=True)
                    old_meta.unlink(missing_ok=True)
                    size -= old_size
                except OSError:
                    pass
            if size + new_size > Config.max_cache_bytes:
                return False

            body_tmp = body_path.with_suffix(".body.tmp")
            meta_tmp = meta_path.with_suffix(".json.tmp")
            await asyncio.to_thread(body_tmp.write_bytes, body)
            await asyncio.to_thread(meta_tmp.write_bytes, meta_bytes)
            await asyncio.to_thread(body_tmp.replace, body_path)
            await asyncio.to_thread(meta_tmp.replace, meta_path)
            return True
        except OSError:
            LOG.exception("Cache write failed")
            return False

    def _rate_limited(self, ip):
        if ip not in self.rate_events and len(self.rate_events) >= 10000:
            for stale_ip in [key for key, queue in self.rate_events.items() if not queue]:
                self.rate_events.pop(stale_ip, None)
            if len(self.rate_events) >= 10000:
                return True
        now = time.monotonic()
        events = self.rate_events[ip]
        while events and now - events[0] >= 60: events.popleft()
        if len(events) >= Config.max_requests_per_minute: return True
        events.append(now)
        return False

    def _log(self, ip, host, status, size, elapsed_ms):
        try:
            with sqlite3.connect(Config.db_path, timeout=2) as conn:
                conn.execute("INSERT INTO requests(timestamp,client_ip,target_host,cache_status,response_size,response_time_ms) VALUES(?,?,?,?,?,?)",
                    (datetime.now(timezone.utc).isoformat(), ip, host, status, size, elapsed_ms))
        except sqlite3.Error: LOG.exception("Analytics write failed")

    def _stats_authorized(self, request):
        if not Config.stats_token:
            return False
        supplied = request.headers.get("Authorization", "")
        expected = f"Bearer {Config.stats_token}"
        return hmac.compare_digest(supplied, expected)

    async def _read_bounded_body(self, stream):
        chunks = []
        total = 0
        async for chunk in stream.iter_chunked(64 * 1024):
            total += len(chunk)
            if total > Config.max_object_bytes:
                raise web.HTTPBadGateway(text="Origin response exceeds configured object limit")
            chunks.append(chunk)
        return b"".join(chunks)

    @staticmethod
    def _origin_request_headers(request):
        # Forward only selected end-to-end headers; never forward Host or hop-by-hop fields.
        allowed = {
            "accept", "accept-language", "accept-encoding", "authorization", "cookie",
            "if-none-match", "if-modified-since", "if-match", "if-unmodified-since",
            "if-range", "range", "cache-control", "pragma", "user-agent",
        }
        headers = {name: value for name, value in request.headers.items()
                   if name.lower() in allowed}
        if not any(name.lower() == "accept-encoding" for name in headers):
            headers["Accept-Encoding"] = "identity"
        return headers

    async def handle_request(self, request):
        started = time.monotonic()
        ip = request.remote or "unknown"
        if self._rate_limited(ip): raise web.HTTPTooManyRequests(text="Rate limit exceeded")
        target = validate_target(request.query.get("url", ""), Config.allowed_hosts)
        host = urlsplit(target).hostname or ""
        cached = await self._read_cache(target) if request_may_use_cache(request) else None
        if cached:
            body, meta = cached
            self.stats["hits"] += 1; self.stats["bytes_served"] += len(body)
            self.policy.record(target, True)
            headers = dict(meta.get("headers", {})); self._safe_headers(headers)
            headers.update({"X-CDN-Cache": "HIT", "X-CDN-Server": "CDN-Proxy/2.0"})
            elapsed = (time.monotonic() - started) * 1000
            self._log(ip, host, "HIT", len(body), elapsed)
            return web.Response(body=body, headers=headers)
        if self.session is None: raise web.HTTPServiceUnavailable(text="Proxy is starting")
        try:
            async with self.session.get(target, headers=self._origin_request_headers(request),
                                        allow_redirects=False) as origin:
                try:
                    body = await self._read_bounded_body(origin.content)
                except web.HTTPBadGateway:
                    self.stats["bypasses"] += 1
                    raise
                headers = dict(origin.headers)
                ttl = cache_policy(headers, Config.default_ttl, Config.max_ttl)
                adjusted = self.policy.adjust_ttl(target, ttl)
                stored = (origin.status == 200 and request.method == "GET"
                          and request_may_use_cache(request)
                          and await self._write_cache(target, body, headers, adjusted))
                self.policy.record(target, False)
                status = "MISS" if stored else "BYPASS"
                self.stats["misses"] += 1; self.stats["bypasses"] += int(not stored); self.stats["bytes_served"] += len(body)
                self._safe_headers(headers)
                headers.update({"X-CDN-Cache": status, "X-CDN-Server": "CDN-Proxy/2.0"})
                elapsed = (time.monotonic() - started) * 1000
                self._log(ip, host, status, len(body), elapsed)
                return web.Response(body=body, status=origin.status, headers=headers)
        except web.HTTPException: raise
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            LOG.warning("Origin request failed for host %s: %s", host, type(exc).__name__)
            raise web.HTTPBadGateway(text="Origin request failed") from exc

    @staticmethod
    def _safe_headers(headers):
        # RFC hop-by-hop fields include any extra headers nominated by Connection.
        connection_value = next((str(value) for name, value in headers.items()
                                 if name.lower() == "connection"), "")
        connection_tokens = {token.strip().lower() for token in connection_value.split(",") if token.strip()}
        blocked = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                   "te", "trailer", "transfer-encoding", "upgrade", "content-length"}
        blocked.update(connection_tokens)
        for name in list(headers):
            if name.lower() in blocked:
                headers.pop(name, None)

    async def stats_handler(self, request):
        if not self._stats_authorized(request):
            raise web.HTTPUnauthorized(text="Stats require a configured bearer token")
        total = self.stats["hits"] + self.stats["misses"]
        return web.json_response({"service": "CDN-Proxy-Server", "version": "2.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "cache": {**self.stats, "hit_ratio": self.stats["hits"] / total if total else 0},
            "adaptive_policy": "conservative-reuse-v1", "cache_bytes_on_disk": self._cache_size(),
            "allowed_origin_count": len(Config.allowed_hosts)})

    async def health_handler(self, request):
        return web.json_response({"status": "ok", "service": "CDN-Proxy-Server", "version": "2.0.0"})

def create_app():
    server = CDNServer()
    app = web.Application(client_max_size=1024 * 1024)
    app["cdn_server"] = server
    app.router.add_get("/proxy", server.handle_request, allow_head=False)
    app.router.add_get("/stats", server.stats_handler)
    app.router.add_get("/health", server.health_handler)
    app.on_startup.append(server.start); app.on_cleanup.append(server.close)
    return app

if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    if not Config.allowed_hosts:
        raise SystemExit("Set CDN_ALLOWED_HOSTS to a comma-separated allowlist before starting.")
    web.run_app(create_app(), host=Config.host, port=Config.port)
