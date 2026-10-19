#!/usr/bin/env python3
"""A bounded, SSRF-resistant HTTP caching proxy built on aiohttp.

This service is intended to be deployed behind a trusted TLS-terminating proxy.
For public deployment, set PROXY_API_KEY and explicitly configure CORS_ORIGINS.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import socket
import sqlite3
import time
from collections import defaultdict, deque
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import aiofiles
import aiohttp
from aiohttp import web

LOG = logging.getLogger("cdn_proxy")
SERVER_HEADER = "CDN-Proxy/2.0"
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "content-length",
}
FORWARDED_HEADERS = {
    "content-type", "content-language", "cache-control",
    "etag", "last-modified", "expires", "accept-ranges", "content-range",
}
SENSITIVE_CACHE_HEADERS = {"set-cookie", "www-authenticate"}


def env_int(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < minimum:
        raise RuntimeError(f"{name} must be >= {minimum}")
    return value


def allowed_target(url: str) -> tuple[bool, str]:
    """Validate syntax and reject non-public destinations before making a request.

    SafeResolver repeats the address check on the actual DNS answers, including
    redirect targets, to reduce DNS-rebinding and redirect-based SSRF risk.
    """
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            return False, "Only http and https URLs are supported"
        if not parsed.hostname or parsed.username is not None or parsed.password is not None:
            return False, "URL must have a hostname and must not contain credentials"
        if parsed.port not in (None, 80, 443):
            return False, "Only standard HTTP/HTTPS ports are allowed"
        if any(ord(ch) < 32 for ch in url):
            return False, "URL contains control characters"
        host = parsed.hostname.rstrip(".").lower()
        if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
            return False, "Local destinations are not allowed"
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None and not address.is_global:
            return False, "Non-public IP addresses are not allowed"
        return True, ""
    except ValueError:
        return False, "Malformed URL"


class SafeResolver(aiohttp.abc.AbstractResolver):
    """DNS resolver that refuses private, loopback, link-local and reserved IPs."""
    def __init__(self) -> None:
        self._resolver = aiohttp.resolver.DefaultResolver()

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        results = await self._resolver.resolve(host, port, family)
        if not results:
            raise OSError("Hostname did not resolve")
        for item in results:
            address = ipaddress.ip_address(item["host"].split("%", 1)[0])
            if not address.is_global:
                raise OSError("DNS resolved to a non-public IP address")
        return results

    async def close(self) -> None:
        await self._resolver.close()


class SlidingWindowLimiter:
    """Bounded in-process per-client rate limiter; use a shared store for multi-worker deployments."""
    def __init__(self, limit: int, window_seconds: int = 60, max_clients: int = 10000):
        self.limit = limit
        self.window = window_seconds
        self.max_clients = max_clients
        self.events: dict[str, deque[float]] = {}
        self.lock = asyncio.Lock()

    async def allow(self, client: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window
        async with self.lock:
            if client not in self.events and len(self.events) >= self.max_clients:
                # Drop the least recently touched client to cap memory usage.
                oldest = min(self.events, key=lambda key: self.events[key][-1] if self.events[key] else 0)
                self.events.pop(oldest, None)
            bucket = self.events.setdefault(client, deque())
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return False
            bucket.append(now)
            return True


class CDNServer:
    def __init__(self) -> None:
        self.cache_dir = Path(os.getenv("CACHE_DIR", "./cache"))
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_cache_size = env_int("MAX_CACHE_SIZE_BYTES", 1024 * 1024 * 1024)
        self.max_response_size = env_int("MAX_RESPONSE_SIZE_BYTES", 25 * 1024 * 1024)
        self.cache_ttl = env_int("CACHE_TTL_SECONDS", 3600)
        self.timeout_seconds = env_int("UPSTREAM_TIMEOUT_SECONDS", 20)
        self.rate_limiter = SlidingWindowLimiter(env_int("RATE_LIMIT_PER_MINUTE", 120))
        self.api_key = os.getenv("PROXY_API_KEY", "")
        self.allowed_origins = {x.strip() for x in os.getenv("CORS_ORIGINS", "").split(",") if x.strip()}
        self.analytics_db = os.getenv("ANALYTICS_DB", "./analytics.db")
        self.cache_stats = {"hits": 0, "misses": 0, "bypasses": 0, "bandwidth_saved": 0}
        self._cache_lock = asyncio.Lock()
        self._db_lock = asyncio.Lock()
        self._session: aiohttp.ClientSession | None = None
        self._initialize_database()

    def _connect_db(self):
        conn = sqlite3.connect(self.analytics_db, timeout=5)
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _initialize_database(self) -> None:
        conn = self._connect_db()
        try:
            with conn:
                conn.execute("""CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, client_ip TEXT,
                    url_hash TEXT NOT NULL, cache_hit INTEGER NOT NULL,
                    response_size INTEGER NOT NULL, response_time REAL NOT NULL,
                    status_code INTEGER NOT NULL)""")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp)")
        finally:
            conn.close()

    async def start(self, app: web.Application) -> None:
        connector = aiohttp.TCPConnector(
            resolver=SafeResolver(), use_dns_cache=True, ttl_dns_cache=60,
            limit=100, limit_per_host=20, enable_cleanup_closed=True,
        )
        timeout = aiohttp.ClientTimeout(total=self.timeout_seconds, connect=5, sock_read=10)
        self._session = aiohttp.ClientSession(
            connector=connector, timeout=timeout, trust_env=False,
            raise_for_status=False, auto_decompress=True,
            headers={"User-Agent": SERVER_HEADER},
        )

    async def close(self, app: web.Application) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    @staticmethod
    def cache_key(url: str) -> str:
        return hashlib.sha256(url.encode("utf-8")).hexdigest()

    def _paths(self, key: str) -> tuple[Path, Path]:
        return self.cache_dir / f"{key}.body", self.cache_dir / f"{key}.json"

    async def _get_cached(self, url: str):
        body_path, meta_path = self._paths(self.cache_key(url))
        try:
            async with aiofiles.open(meta_path, "r", encoding="utf-8") as handle:
                meta = json.loads(await handle.read())
            age = time.time() - float(meta["stored_at"])
            if age < 0 or age > min(self.cache_ttl, int(meta.get("ttl", self.cache_ttl))):
                return None
            if not body_path.is_file() or body_path.stat().st_size != int(meta["size"]):
                return None
            async with aiofiles.open(body_path, "rb") as handle:
                body = await handle.read(self.max_response_size + 1)
            if len(body) > self.max_response_size:
                return None
            body_path.touch()
            return body, meta
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None

    async def _cache_response(self, url: str, body: bytes, headers, status: int) -> bool:
        directives = headers.get("Cache-Control", "").lower()
        if status != 200 or len(body) > min(self.max_response_size, self.max_cache_size):
            return False
        if any(token in directives for token in ("no-store", "private", "no-cache")):
            return False
        # Without varying the cache key on request headers, bypass all Vary responses.
        if headers.get("Vary") or "set-cookie" in {k.lower() for k in headers}:
            return False
        ttl = self.cache_ttl
        for directive in directives.split(","):
            directive = directive.strip()
            if directive.startswith("s-maxage=") or directive.startswith("max-age="):
                with suppress(ValueError):
                    ttl = min(ttl, max(0, int(directive.split("=", 1)[1])))
                break
        if ttl <= 0:
            return False
        key = self.cache_key(url)
        body_path, meta_path = self._paths(key)
        meta = {
            "stored_at": time.time(), "ttl": ttl, "size": len(body),
            "headers": {k: v for k, v in headers.items() if k.lower() in FORWARDED_HEADERS},
            "status": status,
        }
        async with self._cache_lock:
            temp_body = body_path.with_suffix(".body.tmp")
            temp_meta = meta_path.with_suffix(".json.tmp")
            try:
                async with aiofiles.open(temp_body, "wb") as handle:
                    await handle.write(body)
                async with aiofiles.open(temp_meta, "w", encoding="utf-8") as handle:
                    await handle.write(json.dumps(meta))
                await asyncio.to_thread(os.replace, temp_body, body_path)
                await asyncio.to_thread(os.replace, temp_meta, meta_path)
                await self._evict_cache(exclude=key)
                return True
            except OSError:
                LOG.exception("Unable to write cache entry")
                for path in (temp_body, temp_meta):
                    with suppress(OSError):
                        path.unlink()
                return False

    async def _evict_cache(self, exclude: str = "") -> None:
        entries = []
        total = 0
        for body in self.cache_dir.glob("*.body"):
            try:
                size = body.stat().st_size
                total += size
                entries.append((body.stat().st_mtime, body, size))
            except OSError:
                continue
        entries.sort(key=lambda item: item[0])
        for _, body, size in entries:
            if total <= self.max_cache_size:
                break
            key = body.stem
            if key == exclude and len(entries) > 1:
                continue
            for path in (body, self.cache_dir / f"{key}.json"):
                with suppress(OSError):
                    path.unlink()
            total -= size

    async def _log_request(self, client_ip: str, url: str, hit: bool, size: int, elapsed: float, status: int):
        record = (datetime.now(timezone.utc).isoformat(), client_ip, self.cache_key(url), int(hit), size, elapsed, status)
        async with self._db_lock:
            def insert():
                conn = self._connect_db()
                try:
                    with conn:
                        conn.execute("""INSERT INTO requests
                            (timestamp, client_ip, url_hash, cache_hit, response_size, response_time, status_code)
                            VALUES (?, ?, ?, ?, ?, ?, ?)""", record)
                finally:
                    conn.close()
            try:
                await asyncio.to_thread(insert)
            except sqlite3.Error:
                LOG.exception("Analytics write failed")

    def _authorize(self, request: web.Request) -> bool:
        if not self.api_key:
            return True
        supplied = request.headers.get("Authorization", "")
        if supplied.startswith("Bearer "):
            supplied = supplied[7:]
        return __import__("hmac").compare_digest(supplied, self.api_key)

    async def handle_request(self, request: web.Request) -> web.Response:
        started = time.monotonic()
        client_ip = request.remote or "unknown"
        if not self._authorize(request):
            return web.json_response({"error": "unauthorized"}, status=401, headers={"WWW-Authenticate": "Bearer"})
        if not await self.rate_limiter.allow(client_ip):
            return web.json_response({"error": "rate limit exceeded"}, status=429, headers={"Retry-After": "60"})
        target_url = request.query.get("url", "")
        if not target_url:
            return web.json_response({"error": "missing required 'url' parameter"}, status=400)
        ok, reason = allowed_target(target_url)
        if not ok:
            return web.json_response({"error": reason}, status=400)
        if self._session is None:
            return web.json_response({"error": "upstream client is not ready"}, status=503)

        cached = await self._get_cached(target_url)
        if cached:
            body, meta = cached
            self.cache_stats["hits"] += 1
            self.cache_stats["bandwidth_saved"] += len(body)
            await self._log_request(client_ip, target_url, True, len(body), time.monotonic() - started, 200)
            headers = dict(meta.get("headers", {}))
            headers.update({"X-CDN-Cache": "HIT", "X-CDN-Server": SERVER_HEADER})
            return web.Response(body=body, status=int(meta.get("status", 200)), headers=headers)

        try:
            # Resolver validates DNS answers for the origin and every redirect.
            async with self._session.get(target_url, allow_redirects=True, max_redirects=5) as response:
                if response.content_length is not None and response.content_length > self.max_response_size:
                    return web.json_response({"error": "upstream response exceeds configured size limit"}, status=413)
                chunks = []
                size = 0
                async for chunk in response.content.iter_chunked(64 * 1024):
                    size += len(chunk)
                    if size > self.max_response_size:
                        return web.json_response({"error": "upstream response exceeds configured size limit"}, status=413)
                    chunks.append(chunk)
                body = b"".join(chunks)
                headers = {k: v for k, v in response.headers.items() if k.lower() in FORWARDED_HEADERS}
                status = response.status
                if status == 200:
                    await self._cache_response(target_url, body, headers, status)
                self.cache_stats["misses"] += 1
                await self._log_request(client_ip, target_url, False, len(body), time.monotonic() - started, status)
                headers.update({"X-CDN-Cache": "MISS", "X-CDN-Server": SERVER_HEADER})
                return web.Response(body=body, status=status, headers=headers)
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError, ValueError) as exc:
            LOG.info("Upstream request failed (%s)", type(exc).__name__)
            return web.json_response({"error": "upstream request failed"}, status=502)

    async def stats_handler(self, request: web.Request) -> web.Response:
        if not self._authorize(request):
            return web.json_response({"error": "unauthorized"}, status=401)
        total = self.cache_stats["hits"] + self.cache_stats["misses"]
        return web.json_response({
            "cache_stats": dict(self.cache_stats),
            "cache_hit_ratio": self.cache_stats["hits"] / total if total else 0.0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    async def health_handler(self, request: web.Request) -> web.Response:
        return web.json_response({"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()})


def create_app() -> web.Application:
    bind = os.getenv("HOST", "127.0.0.1")
    api_key = os.getenv("PROXY_API_KEY", "")
    if bind not in {"127.0.0.1", "::1", "localhost"} and not api_key:
        raise RuntimeError("Set PROXY_API_KEY before binding to a non-loopback interface")
    cdn = CDNServer()
    app = web.Application(client_max_size=1024 * 1024)
    app["cdn"] = cdn
    app.router.add_get("/proxy", cdn.handle_request)
    app.router.add_get("/stats", cdn.stats_handler)
    app.router.add_get("/health", cdn.health_handler)

    @web.middleware
    async def cors_middleware(request: web.Request, handler):
        origin = request.headers.get("Origin")
        if request.method == "OPTIONS":
            response = web.Response(status=204)
        else:
            response = await handler(request)
        if origin and origin in cdn.allowed_origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
            response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        return response

    app.middlewares.append(cors_middleware)
    app.on_startup.append(cdn.start)
    app.on_cleanup.append(cdn.close)
    return app


if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    host = os.getenv("HOST", "127.0.0.1")
    port = env_int("PORT", 8080)
    application = create_app()
    LOG.info("Starting CDN proxy on %s:%s", host, port)
    web.run_app(application, host=host, port=port)
