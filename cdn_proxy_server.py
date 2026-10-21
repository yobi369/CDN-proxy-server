#!/usr/bin/env python3
"""Self-hostable HTTP caching proxy with a conservative adaptive policy."""
from __future__ import annotations
import asyncio, hashlib, hmac, ipaddress, json, logging, os, re, socket, sqlite3, time
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
    access_token = os.getenv("PROXY_ACCESS_TOKEN", "")
    log_client_ip = os.getenv("PROXY_LOG_CLIENT_IP", "false").lower() in {"1", "true", "yes"}

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

def request_can_read_cache(request):
    """Allow cache reads unless credentials or explicit request directives prohibit sharing."""
    if request.headers.get("Authorization") or request.headers.get("Cookie"):
        return False
    directives = {}
    for part in request.headers.get("Cache-Control", "").lower().split(","):
        key, sep, value = part.strip().partition("=")
        if key:
            directives[key] = value.strip('"') if sep else None
    if any(key in directives for key in ("no-cache", "no-store")):
        return False
    if directives.get("max-age") == "0":
        return False
    return "no-cache" not in request.headers.get("Pragma", "").lower()


def request_may_use_cache(request):
    """Allow shared cache writes only for ordinary, non-conditional, non-range requests."""
    if not request_can_read_cache(request):
        return False
    return not any(request.headers.get(name) for name in (
        "Range", "If-Range", "If-None-Match", "If-Modified-Since",
        "If-Match", "If-Unmodified-Since",
    ))

class AdaptivePolicy:
    """Explainable research baseline with bounded, configurable policy parameters."""
    def __init__(self, max_keys: int = 10000, cold_ttl_fraction: float = 0.5,
                 warm_hit_threshold: float = 0.6, min_observations: int = 3):
        self.max_keys = max(1, max_keys)
        self.cold_ttl_fraction = min(1.0, max(0.05, float(cold_ttl_fraction)))
        self.warm_hit_threshold = min(1.0, max(0.0, float(warm_hit_threshold)))
        self.min_observations = max(1, int(min_observations))
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
        if total >= self.min_observations and hits / total >= self.warm_hit_threshold:
            return origin_ttl
        return max(1, min(origin_ttl, int(origin_ttl * self.cold_ttl_fraction)))

class CDNServer:
    def __init__(self):
        Config.cache_dir.mkdir(parents=True, exist_ok=True)
        self.session = None
        self.cache_lock = asyncio.Lock()
        self.rate_events = defaultdict(deque)
        self.policy = AdaptivePolicy()
        self.stats = {"hits": 0, "misses": 0, "bypasses": 0, "bytes_served": 0, "revalidations": 0, "purges": 0}
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

    async def _read_stale_cache(self, target):
        """Read an expired but structurally valid entry for conditional revalidation."""
        body_path, meta_path = self._paths(target)
        try:
            meta = json.loads(await asyncio.to_thread(meta_path.read_text, encoding="utf-8"))
            age = time.time() - float(meta["stored_at"])
            if age < 0 or int(meta["ttl"]) <= 0:
                return None
            body = await asyncio.to_thread(body_path.read_bytes)
            return body, meta
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None

    async def _delete_cache(self, target):
        async with self.cache_lock:
            body_path, meta_path = self._paths(target)
            existed = body_path.exists() or meta_path.exists()
            for path in (body_path, meta_path):
                try:
                    await asyncio.to_thread(path.unlink, missing_ok=True)
                except OSError:
                    LOG.warning("Unable to remove cache entry %s", path.name)
            return existed

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
        now = time.monotonic()
        if ip not in self.rate_events and len(self.rate_events) >= 10000:
            for stale_ip, queue in list(self.rate_events.items()):
                while queue and now - queue[0] >= 60:
                    queue.popleft()
                if not queue:
                    self.rate_events.pop(stale_ip, None)
            if len(self.rate_events) >= 10000:
                return True
        events = self.rate_events[ip]
        while events and now - events[0] >= 60:
            events.popleft()
        if len(events) >= Config.max_requests_per_minute:
            return True
        events.append(now)
        return False

    async def _log(self, ip, host, status, size, elapsed_ms):
        await asyncio.to_thread(self._log_sync, ip, host, status, size, elapsed_ms)

    @staticmethod
    def _log_sync(ip, host, status, size, elapsed_ms):
        try:
            with sqlite3.connect(Config.db_path, timeout=2) as conn:
                conn.execute("INSERT INTO requests(timestamp,client_ip,target_host,cache_status,response_size,response_time_ms) VALUES(?,?,?,?,?,?)",
                    (datetime.now(timezone.utc).isoformat(),
                     ip if Config.log_client_ip else None, host, status, size, elapsed_ms))
        except sqlite3.Error:
            LOG.exception("Analytics write failed")

    def _proxy_authorized(self, request):
        if Config.access_token:
            supplied = request.headers.get("X-Proxy-Token", "")
            return hmac.compare_digest(supplied, Config.access_token)
        # Tokenless mode is permitted only for loopback-bound local development.
        return Config.host.lower() in {"127.0.0.1", "::1", "localhost"}

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

    async def _collect_cacheable_body(self, stream):
        """Buffer a small response, or return a bounded prefix and iterator for streaming."""
        iterator = stream.iter_chunked(64 * 1024).__aiter__()
        chunks = []
        total = 0
        while True:
            try:
                chunk = await iterator.__anext__()
            except StopAsyncIteration:
                return b"".join(chunks), None
            chunks.append(chunk)
            total += len(chunk)
            if total > Config.max_object_bytes:
                return None, (chunks, iterator)

    async def _stream_bypass(self, request, origin, initial_chunks, iterator, target, ip, host, started):
        headers = dict(origin.headers)
        self._safe_headers(headers)
        headers.update({"X-CDN-Cache": "BYPASS", "X-CDN-Server": "CDN-Proxy/2.0"})
        response = web.StreamResponse(status=origin.status, headers=headers)
        total = 0
        try:
            await response.prepare(request)
            for chunk in initial_chunks:
                await response.write(chunk)
                total += len(chunk)
            async for chunk in iterator:
                await response.write(chunk)
                total += len(chunk)
            await response.write_eof()
        except (ConnectionResetError, BrokenPipeError):
            LOG.debug("Client disconnected during streamed response from %s", host)
        self.policy.record(target, False)
        self.stats["misses"] += 1
        self.stats["bypasses"] += 1
        self.stats["bytes_served"] += total
        elapsed = (time.monotonic() - started) * 1000
        await self._log(ip, host, "BYPASS", total, elapsed)
        return response

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

    @staticmethod
    def _header_value(headers, name):
        return next((str(value) for key, value in headers.items() if key.lower() == name.lower()), None)

    @staticmethod
    def _parse_http_date(value):
        if not value:
            return None
        try:
            parsed = parsedate_to_datetime(value)
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
        except (TypeError, ValueError, OverflowError):
            return None

    @staticmethod
    def _etag_matches(condition, current, weak=True):
        if not condition:
            return False
        tokens = re.findall(r'(?:W/)?"[^"]*"|\*', condition)
        if "*" in tokens:
            return True  # A cached representation exists.
        if not current:
            return False
        def normalize(tag):
            return tag[2:] if tag.startswith("W/") else tag
        for tag in tokens:
            if weak:
                if normalize(tag) == normalize(current):
                    return True
            elif not tag.startswith("W/") and not current.startswith("W/") and tag == current:
                return True
        return False

    def _if_range_matches(self, condition, etag, last_modified):
        if not condition:
            return True
        if condition.startswith('"') or condition.startswith("W/"):
            return self._etag_matches(condition, etag, weak=False)
        requested_date = self._parse_http_date(condition)
        modified_date = self._parse_http_date(last_modified)
        return bool(requested_date and modified_date and modified_date <= requested_date)

    def _cached_conditional_response(self, request, body, cached_headers):
        """Serve supported HTTP preconditions and single byte ranges from a fresh cache entry.

        Return None for unsupported/malformed range syntax so the origin handles it.
        """
        headers = dict(cached_headers)
        etag = self._header_value(headers, "ETag")
        last_modified = self._header_value(headers, "Last-Modified")
        if_match = request.headers.get("If-Match")
        if if_match and not self._etag_matches(if_match, etag, weak=False):
            self._safe_headers(headers)
            return web.Response(status=412, headers=headers)
        if_unmodified = request.headers.get("If-Unmodified-Since")
        if not if_match and if_unmodified and last_modified:
            modified_date = self._parse_http_date(last_modified)
            unmodified_date = self._parse_http_date(if_unmodified)
            if modified_date and unmodified_date and modified_date > unmodified_date:
                self._safe_headers(headers)
                return web.Response(status=412, headers=headers)

        if_none = request.headers.get("If-None-Match")
        if if_none and self._etag_matches(if_none, etag, weak=True):
            self._safe_headers(headers)
            return web.Response(status=304, headers=headers)
        if_modified = request.headers.get("If-Modified-Since")
        if not if_none and if_modified and last_modified:
            modified_date = self._parse_http_date(last_modified)
            requested_date = self._parse_http_date(if_modified)
            if modified_date and requested_date and modified_date <= requested_date:
                self._safe_headers(headers)
                return web.Response(status=304, headers=headers)

        range_value = request.headers.get("Range")
        if range_value:
            if_range = request.headers.get("If-Range")
            if if_range and not self._if_range_matches(if_range, etag, last_modified):
                range_value = None  # If-Range mismatch requires a full representation.
            else:
                if "," in range_value:
                    return None  # Multi-range responses are delegated to the origin.
                match = re.fullmatch(r"bytes=(\d*)-(\d*)", range_value.strip(), re.IGNORECASE)
                if not match or (not match.group(1) and not match.group(2)):
                    return None
                first, last = match.groups()
                length = len(body)
                if not first:
                    suffix = int(last)
                    if suffix <= 0 or length == 0:
                        headers["Content-Range"] = f"bytes */{length}"
                        self._safe_headers(headers)
                        return web.Response(status=416, headers=headers)
                    start = max(0, length - suffix)
                    end = length - 1
                else:
                    start = int(first)
                    end = int(last) if last else length - 1
                    if length == 0 or start >= length or start > end:
                        headers["Content-Range"] = f"bytes */{length}"
                        self._safe_headers(headers)
                        return web.Response(status=416, headers=headers)
                    end = min(end, length - 1)
                headers["Content-Range"] = f"bytes {start}-{end}/{length}"
                headers["Accept-Ranges"] = "bytes"
                self._safe_headers(headers)
                return web.Response(body=body[start:end + 1], status=206, headers=headers)

        headers.setdefault("Accept-Ranges", "bytes")
        self._safe_headers(headers)
        return web.Response(body=body, headers=headers)

    async def handle_request(self, request):
        started = time.monotonic()
        ip = request.remote or "unknown"
        if self._rate_limited(ip):
            raise web.HTTPTooManyRequests(text="Rate limit exceeded")
        if not self._proxy_authorized(request):
            raise web.HTTPUnauthorized(text="Proxy access requires X-Proxy-Token")
        target = validate_target(request.query.get("url", ""), Config.allowed_hosts)
        host = urlsplit(target).hostname or ""
        cache_allowed = request_may_use_cache(request)
        cache_read_allowed = request_can_read_cache(request)
        cached = await self._read_cache(target) if cache_read_allowed else None
        if cached:
            body, meta = cached
            if cache_allowed:
                self.stats["hits"] += 1; self.stats["bytes_served"] += len(body)
                self.policy.record(target, True)
                headers = dict(meta.get("headers", {})); self._safe_headers(headers)
                headers.update({"X-CDN-Cache": "HIT", "X-CDN-Server": "CDN-Proxy/2.0"})
                elapsed = (time.monotonic() - started) * 1000
                await self._log(ip, host, "HIT", len(body), elapsed)
                return web.Response(body=body, headers=headers)

            cached_response = self._cached_conditional_response(request, body, meta.get("headers", {}))
            if cached_response is not None:
                served_bytes = len(cached_response.body or b"")
                self.stats["hits"] += 1
                self.stats["bytes_served"] += served_bytes
                self.policy.record(target, True)
                cached_response.headers["X-CDN-Cache"] = "HIT"
                cached_response.headers["X-CDN-Server"] = "CDN-Proxy/2.0"
                elapsed = (time.monotonic() - started) * 1000
                await self._log(ip, host, f"HIT-{cached_response.status}", served_bytes, elapsed)
                return cached_response

        conditional_names = {"if-none-match", "if-modified-since", "if-match", "if-unmodified-since", "if-range"}
        client_has_condition = any(name.lower() in conditional_names for name in request.headers)
        stale = await self._read_stale_cache(target) if cache_allowed and not client_has_condition else None
        if self.session is None: raise web.HTTPServiceUnavailable(text="Proxy is starting")
        outbound_headers = self._origin_request_headers(request)
        if stale:
            old_headers = stale[1].get("headers", {})
            etag = next((v for k, v in old_headers.items() if k.lower() == "etag"), None)
            modified = next((v for k, v in old_headers.items() if k.lower() == "last-modified"), None)
            if etag:
                outbound_headers["If-None-Match"] = etag
            elif modified:
                outbound_headers["If-Modified-Since"] = modified
        try:
            async with self.session.get(target, headers=outbound_headers,
                                        allow_redirects=False) as origin:
                if origin.status == 304 and stale:
                    body, old_meta = stale
                    headers = dict(old_meta.get("headers", {}))
                    self._merge_response_headers(headers, dict(origin.headers))
                    if not any(k.lower() == "date" for k in origin.headers):
                        headers["Date"] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
                    if not any(k.lower() == "age" for k in origin.headers):
                        headers["Age"] = "0"
                    ttl = cache_policy(headers, Config.default_ttl, Config.max_ttl)
                    adjusted = self.policy.adjust_ttl(target, ttl)
                    stored = adjusted > 0 and await self._write_cache(target, body, headers, adjusted)
                    if not stored:
                        await self._delete_cache(target)
                    self.policy.record(target, True)
                    self.stats["hits"] += 1
                    self.stats["revalidations"] += 1
                    self.stats["bytes_served"] += len(body)
                    self._safe_headers(headers)
                    headers.update({"X-CDN-Cache": "REVALIDATED", "X-CDN-Server": "CDN-Proxy/2.0"})
                    elapsed = (time.monotonic() - started) * 1000
                    await self._log(ip, host, "REVALIDATED", len(body), elapsed)
                    return web.Response(body=body, status=200, headers=headers)

                headers = dict(origin.headers)
                ttl = cache_policy(headers, Config.default_ttl, Config.max_ttl)
                adjusted = self.policy.adjust_ttl(target, ttl)
                content_length = self._header_value(headers, "Content-Length")
                try:
                    known_large = content_length is not None and int(content_length) > Config.max_object_bytes
                except ValueError:
                    known_large = False
                if known_large:
                    iterator = origin.content.iter_chunked(64 * 1024).__aiter__()
                    return await self._stream_bypass(
                        request, origin, [], iterator, target, ip, host, started
                    )

                body, overflow = await self._collect_cacheable_body(origin.content)
                if overflow is not None:
                    initial_chunks, iterator = overflow
                    return await self._stream_bypass(
                        request, origin, initial_chunks, iterator, target, ip, host, started
                    )
                stored = (origin.status == 200 and request.method == "GET"
                          and request_may_use_cache(request)
                          and await self._write_cache(target, body, headers, adjusted))
                self.policy.record(target, False)
                status = "MISS" if stored else "BYPASS"
                self.stats["misses"] += 1
                self.stats["bypasses"] += int(not stored)
                self.stats["bytes_served"] += len(body)
                self._safe_headers(headers)
                headers.update({"X-CDN-Cache": status, "X-CDN-Server": "CDN-Proxy/2.0"})
                elapsed = (time.monotonic() - started) * 1000
                await self._log(ip, host, status, len(body), elapsed)
                return web.Response(body=body, status=origin.status, headers=headers)
        except web.HTTPException: raise
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            LOG.warning("Origin request failed for host %s: %s", host, type(exc).__name__)
            raise web.HTTPBadGateway(text="Origin request failed") from exc

    @staticmethod
    def _merge_response_headers(existing, updates):
        for name, value in updates.items():
            for old_name in list(existing):
                if old_name.lower() == name.lower():
                    existing.pop(old_name, None)
            existing[name] = value

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

    async def purge_handler(self, request):
        started = time.monotonic()
        ip = request.remote or "unknown"
        if self._rate_limited(ip):
            raise web.HTTPTooManyRequests(text="Rate limit exceeded")
        if not self._proxy_authorized(request):
            raise web.HTTPUnauthorized(text="Cache purge requires X-Proxy-Token")
        target = validate_target(request.query.get("url", ""), Config.allowed_hosts)
        purged = await self._delete_cache(target)
        self.stats["purges"] += int(purged)
        elapsed = (time.monotonic() - started) * 1000
        await self._log(ip, urlsplit(target).hostname or "", "PURGE" if purged else "PURGE-MISS", 0, elapsed)
        return web.json_response({"purged": purged, "target_host": urlsplit(target).hostname})

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
    app.router.add_delete("/cache", server.purge_handler)
    app.router.add_get("/health", server.health_handler)
    app.on_startup.append(server.start); app.on_cleanup.append(server.close)
    return app

if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    if not Config.allowed_hosts:
        raise SystemExit("Set CDN_ALLOWED_HOSTS to a comma-separated allowlist before starting.")
    if Config.host.lower() not in {"127.0.0.1", "::1", "localhost"} and not Config.access_token:
        raise SystemExit("Set PROXY_ACCESS_TOKEN before binding beyond loopback.")
    web.run_app(create_app(), host=Config.host, port=Config.port)
