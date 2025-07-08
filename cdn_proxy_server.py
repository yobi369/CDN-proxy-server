#!/usr/bin/env python3
"""
CDN Proxy Server - Foundation
A high-performance caching proxy server for CDN services
"""

import asyncio
import aiohttp
import hashlib
import json
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Tuple
import sqlite3
from aiohttp import web, ClientSession
import aiofiles

# Configuration
CONFIG = {
    'port': 8080,
    'cache_dir': './cache',
    'max_cache_size': 1024 * 1024 * 1024,  # 1GB
    'cache_ttl': 3600,  # 1 hour
    'analytics_db': './analytics.db',
    'allowed_origins': ['*'],  # Configure for production
    'rate_limit': 1000,  # requests per minute per IP
}

class CDNServer:
    def __init__(self):
        self.cache_dir = Path(CONFIG['cache_dir'])
        self.cache_dir.mkdir(exist_ok=True)
        self.analytics_db = CONFIG['analytics_db']
        self.rate_limiter = {}
        self.cache_stats = {'hits': 0, 'misses': 0, 'bandwidth_saved': 0}
        self.init_database()
        
    def init_database(self):
        """Initialize analytics database"""
        conn = sqlite3.connect(self.analytics_db)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY,
                timestamp DATETIME,
                client_ip TEXT,
                url TEXT,
                cache_hit BOOLEAN,
                response_size INTEGER,
                response_time REAL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS bandwidth_usage (
                date DATE PRIMARY KEY,
                total_requests INTEGER,
                cache_hits INTEGER,
                bandwidth_served INTEGER,
                bandwidth_saved INTEGER
            )
        ''')
        conn.commit()
        conn.close()

    def get_cache_key(self, url: str) -> str:
        """Generate cache key from URL"""
        return hashlib.md5(url.encode()).hexdigest()

    def get_cache_path(self, cache_key: str) -> Path:
        """Get cache file path"""
        return self.cache_dir / f"{cache_key}.cache"

    def get_cache_meta_path(self, cache_key: str) -> Path:
        """Get cache metadata file path"""
        return self.cache_dir / f"{cache_key}.meta"

    async def is_cached(self, url: str) -> Tuple[bool, Optional[Path], Optional[Dict]]:
        """Check if URL is cached and valid"""
        cache_key = self.get_cache_key(url)
        cache_path = self.get_cache_path(cache_key)
        meta_path = self.get_cache_meta_path(cache_key)
        
        if not cache_path.exists() or not meta_path.exists():
            return False, None, None
            
        try:
            async with aiofiles.open(meta_path, 'r') as f:
                meta = json.loads(await f.read())
                
            # Check if cache is expired
            cached_time = datetime.fromisoformat(meta['timestamp'])
            if datetime.now() - cached_time > timedelta(seconds=CONFIG['cache_ttl']):
                return False, None, None
                
            return True, cache_path, meta
        except Exception:
            return False, None, None

    async def cache_response(self, url: str, content: bytes, headers: Dict):
        """Cache response content and metadata"""
        cache_key = self.get_cache_key(url)
        cache_path = self.get_cache_path(cache_key)
        meta_path = self.get_cache_meta_path(cache_key)
        
        # Store content
        async with aiofiles.open(cache_path, 'wb') as f:
            await f.write(content)
            
        # Store metadata
        meta = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'headers': dict(headers),
            'size': len(content)
        }
        async with aiofiles.open(meta_path, 'w') as f:
            await f.write(json.dumps(meta))

    def check_rate_limit(self, client_ip: str) -> bool:
        """Check if client is within rate limits"""
        now = time.time()
        minute = int(now // 60)
        
        if client_ip not in self.rate_limiter:
            self.rate_limiter[client_ip] = {}
            
        if minute not in self.rate_limiter[client_ip]:
            self.rate_limiter[client_ip][minute] = 0
            
        # Clean old entries
        for old_minute in list(self.rate_limiter[client_ip].keys()):
            if old_minute < minute - 1:
                del self.rate_limiter[client_ip][old_minute]
                
        if self.rate_limiter[client_ip][minute] >= CONFIG['rate_limit']:
            return False
            
        self.rate_limiter[client_ip][minute] += 1
        return True

    def log_request(self, client_ip: str, url: str, cache_hit: bool, 
                   response_size: int, response_time: float):
        """Log request for analytics"""
        conn = sqlite3.connect(self.analytics_db)
        conn.execute('''
            INSERT INTO requests 
            (timestamp, client_ip, url, cache_hit, response_size, response_time)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (datetime.now(), client_ip, url, cache_hit, response_size, response_time))
        conn.commit()
        conn.close()

    async def handle_request(self, request):
        """Main request handler"""
        start_time = time.time()
        client_ip = request.remote
        
        # Rate limiting
        if not self.check_rate_limit(client_ip):
            return web.Response(status=429, text="Rate limit exceeded")
        
        # Get target URL from query parameter
        target_url = request.query.get('url')
        if not target_url:
            return web.Response(status=400, text="Missing 'url' parameter")
        
        # Check cache first
        is_cached, cache_path, meta = await self.is_cached(target_url)
        
        if is_cached:
            # Serve from cache
            async with aiofiles.open(cache_path, 'rb') as f:
                content = await f.read()
            
            headers = meta['headers']
            headers['X-CDN-Cache'] = 'HIT'
            headers['X-CDN-Server'] = 'CDN-Proxy-v1.0'
            
            self.cache_stats['hits'] += 1
            self.cache_stats['bandwidth_saved'] += len(content)
            
            response_time = time.time() - start_time
            self.log_request(client_ip, target_url, True, len(content), response_time)
            
            return web.Response(body=content, headers=headers)
        
        # Fetch from origin
        try:
            async with ClientSession() as session:
                async with session.get(target_url) as response:
                    content = await response.read()
                    headers = dict(response.headers)
                    
                    # Cache the response
                    await self.cache_response(target_url, content, headers)
                    
                    headers['X-CDN-Cache'] = 'MISS'
                    headers['X-CDN-Server'] = 'CDN-Proxy-v1.0'
                    
                    self.cache_stats['misses'] += 1
                    
                    response_time = time.time() - start_time
                    self.log_request(client_ip, target_url, False, len(content), response_time)
                    
                    return web.Response(body=content, headers=headers, status=response.status)
                    
        except Exception as e:
            logging.error(f"Error fetching {target_url}: {e}")
            return web.Response(status=502, text="Bad Gateway")

    async def stats_handler(self, request):
        """Return CDN statistics"""
        stats = {
            'cache_stats': self.cache_stats,
            'timestamp': datetime.now().isoformat(),
            'cache_hit_ratio': self.cache_stats['hits'] / max(1, self.cache_stats['hits'] + self.cache_stats['misses'])
        }
        return web.json_response(stats)

    async def health_handler(self, request):
        """Health check endpoint"""
        return web.json_response({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

def create_app():
    """Create and configure the web application"""
    cdn = CDNServer()
    app = web.Application()
    
    # Routes
    app.router.add_get('/proxy', cdn.handle_request)
    app.router.add_get('/stats', cdn.stats_handler)
    app.router.add_get('/health', cdn.health_handler)
    
    # CORS middleware
    async def cors_middleware(request, handler):
        response = await handler(request)
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return response
    
    app.middlewares.append(cors_middleware)
    
    return app

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    app = create_app()
    
    print(f"""
🚀 CDN Proxy Server Starting
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Port: {CONFIG['port']}
Cache Directory: {CONFIG['cache_dir']}
Max Cache Size: {CONFIG['max_cache_size'] / (1024*1024):.0f}MB

Usage:
• Proxy: http://localhost:{CONFIG['port']}/proxy?url=https://example.com/image.jpg
• Stats: http://localhost:{CONFIG['port']}/stats
• Health: http://localhost:{CONFIG['port']}/health

💰 Revenue Opportunities:
• Pay-per-GB bandwidth
• Monthly subscriptions
• Enterprise API access
• White-label solutions
    """)
    
    web.run_app(app, host='0.0.0.0', port=CONFIG['port'])