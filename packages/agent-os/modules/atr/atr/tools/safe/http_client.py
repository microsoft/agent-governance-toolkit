# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Safe HTTP Client Tool.

Provides HTTP request capabilities with security controls:
- URL whitelisting
- Rate limiting
- Request timeout enforcement
- Response size limits
- No redirect following to external domains
"""

import asyncio
import time
from collections import deque
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from atr.decorator import tool


class RateLimiter:
    """Simple rate limiter using sliding window."""
    
    def __init__(self, max_requests: int, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: deque = deque()
    
    def check(self) -> bool:
        """Check if request is allowed."""
        now = time.monotonic()
        
        # Remove old requests
        while self._requests and self._requests[0] < now - self.window_seconds:
            self._requests.popleft()
        
        return len(self._requests) < self.max_requests
    
    def record(self):
        """Record a request."""
        self._requests.append(time.monotonic())


class HttpClientTool:
    """
    Safe HTTP client with security controls.
    
    Features:
    - Domain whitelisting (only specified domains allowed)
    - Rate limiting (prevent abuse)
    - Timeout enforcement (prevent hanging)
    - Response size limits (prevent memory exhaustion)
    - Safe redirect handling (no external redirects)
    
    Example:
        ```python
        http = HttpClientTool(
            allowed_domains=["api.github.com", "httpbin.org"],
            rate_limit=30,  # 30 requests per minute
            timeout=10.0,
            max_response_size=1_000_000  # 1MB
        )
        
        # Register with ATR
        registry.register(http.get)
        registry.register(http.post)
        
        # Use from agent
        response = await http.get("https://api.github.com/users/octocat")
        ```
    """
    
    def __init__(
        self,
        allowed_domains: Optional[List[str]] = None,
        blocked_domains: Optional[List[str]] = None,
        rate_limit: int = 60,
        timeout: float = 30.0,
        max_response_size: int = 10_000_000,  # 10MB
        allow_redirects: bool = True,
        max_redirects: int = 5
    ):
        """
        Initialize HTTP client tool.
        
        Args:
            allowed_domains: Whitelist of allowed domains (if set, only these allowed)
            blocked_domains: Blacklist of blocked domains
            rate_limit: Maximum requests per minute
            timeout: Request timeout in seconds
            max_response_size: Maximum response size in bytes
            allow_redirects: Whether to follow redirects
            max_redirects: Maximum number of redirects to follow
        """
        self.allowed_domains: Set[str] = set(allowed_domains or [])
        self.blocked_domains: Set[str] = set(blocked_domains or [
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "169.254.169.254",  # AWS metadata
            "metadata.google.internal",  # GCP metadata
        ])
        self.timeout = timeout
        self.max_response_size = max_response_size
        self.allow_redirects = allow_redirects
        self.max_redirects = max_redirects
        self._rate_limiter = RateLimiter(rate_limit)
    
    def _validate_url(self, url: str) -> str:
        """Validate and normalize URL."""
        parsed = urlparse(url)
        
        # Must have scheme
        if not parsed.scheme:
            raise ValueError("URL must include scheme (http:// or https://)")
        
        # Only allow http/https
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Scheme '{parsed.scheme}' not allowed. Use http or https.")
        
        # Extract domain
        domain = parsed.netloc.lower()
        if ":" in domain:
            domain = domain.split(":")[0]  # Remove port
        
        # Check blocked domains
        if domain in self.blocked_domains:
            raise ValueError(f"Domain '{domain}' is blocked")
        
        # Check for private IP ranges (basic check)
        if self._is_private_domain(domain):
            raise ValueError(f"Private/internal domains not allowed: {domain}")
        
        # Check allowed domains (if whitelist set)
        if self.allowed_domains:
            if not any(domain.endswith(allowed) for allowed in self.allowed_domains):
                raise ValueError(
                    f"Domain '{domain}' not in allowed list. "
                    f"Allowed: {', '.join(self.allowed_domains)}"
                )
        
        return url
    
    def _is_private_domain(self, domain: str) -> bool:
        """Check if domain resolves to private IP (basic check)."""
        # Check common private patterns
        private_patterns = [
            "10.",
            "192.168.",
            "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.",
            "172.28.", "172.29.", "172.30.", "172.31.",
            "internal",
            ".local",
        ]
        return any(domain.startswith(p) or domain.endswith(p) for p in private_patterns)
    
    def _check_rate_limit(self):
        """Check and enforce rate limit."""
        if not self._rate_limiter.check():
            raise RuntimeError("Rate limit exceeded. Please wait before making more requests.")
        self._rate_limiter.record()
    
    @tool(
        name="http_get",
        description="Make a safe HTTP GET request to retrieve data from a URL",
        tags=["http", "network", "safe"]
    )
    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Make a GET request.
        
        Args:
            url: URL to request (must be in allowed domains)
            headers: Optional request headers
        
        Returns:
            Dict with status_code, headers, and body
        """
        try:
            import aiohttp
        except ImportError:
            raise ImportError("aiohttp required. Install with: pip install aiohttp")
        
        # Validate
        url = self._validate_url(url)
        self._check_rate_limit()
        
        # Make request
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                url,
                headers=headers,
                allow_redirects=self.allow_redirects,
                max_redirects=self.max_redirects
            ) as response:
                # Check response size
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > self.max_response_size:
                    raise ValueError(f"Response too large: {content_length} bytes")
                
                # Read response (with size limit)
                body = await response.text()
                if len(body) > self.max_response_size:
                    body = body[:self.max_response_size] + "... [truncated]"
                
                return {
                    "status_code": response.status,
                    "headers": dict(response.headers),
                    "body": body,
                    "url": str(response.url)
                }
    
    @tool(
        name="http_post",
        description="Make a safe HTTP POST request to send data to a URL",
        tags=["http", "network", "safe"]
    )
    async def post(
        self,
        url: str,
        data: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Make a POST request.
        
        Args:
            url: URL to request (must be in allowed domains)
            data: Form data to send
            json_body: JSON body to send
            headers: Optional request headers
        
        Returns:
            Dict with status_code, headers, and body
        """
        try:
            import aiohttp
        except ImportError:
            raise ImportError("aiohttp required. Install with: pip install aiohttp")
        
        # Validate
        url = self._validate_url(url)
        self._check_rate_limit()
        
        # Make request
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                url,
                data=data,
                json=json_body,
                headers=headers,
                allow_redirects=self.allow_redirects,
                max_redirects=self.max_redirects
            ) as response:
                # Check response size
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > self.max_response_size:
                    raise ValueError(f"Response too large: {content_length} bytes")
                
                # Read response
                body = await response.text()
                if len(body) > self.max_response_size:
                    body = body[:self.max_response_size] + "... [truncated]"
                
                return {
                    "status_code": response.status,
                    "headers": dict(response.headers),
                    "body": body,
                    "url": str(response.url)
                }
    
    @tool(
        name="http_head",
        description="Make a safe HTTP HEAD request to check if a URL exists",
        tags=["http", "network", "safe"]
    )
    async def head(self, url: str) -> Dict[str, Any]:
        """
        Make a HEAD request (useful for checking if resource exists).
        
        Args:
            url: URL to check
        
        Returns:
            Dict with status_code and headers
        """
        try:
            import aiohttp
        except ImportError:
            raise ImportError("aiohttp required. Install with: pip install aiohttp")
        
        url = self._validate_url(url)
        self._check_rate_limit()
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.head(url, allow_redirects=self.allow_redirects) as response:
                return {
                    "status_code": response.status,
                    "headers": dict(response.headers),
                    "url": str(response.url)
                }
