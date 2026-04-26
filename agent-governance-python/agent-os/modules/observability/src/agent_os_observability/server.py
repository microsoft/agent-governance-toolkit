# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
HTTP Metrics Server for Agent OS Kernel.

Standalone server exposing /metrics endpoint for Prometheus scraping.

Usage:
    # Start server
    python -m agent_os_observability.server
    
    # Or programmatically
    from agent_os_observability import MetricsServer
    server = MetricsServer(port=9090)
    server.start()
    
    # Scrape with Prometheus
    # scrape_configs:
    #   - job_name: 'agent-os'
    #     static_configs:
    #       - targets: ['localhost:9090']
"""

import asyncio
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional
from .metrics import KernelMetrics


class MetricsHandler(BaseHTTPRequestHandler):
    """HTTP handler for /metrics endpoint."""
    
    # Class-level metrics instance (set by server)
    metrics: Optional[KernelMetrics] = None
    
    def do_GET(self):
        """Handle GET requests."""
        if self.path == "/metrics":
            self._serve_metrics()
        elif self.path == "/health":
            self._serve_health()
        elif self.path == "/ready":
            self._serve_ready()
        else:
            self.send_error(404, "Not Found")
    
    def _serve_metrics(self):
        """Serve Prometheus metrics."""
        if self.metrics is None:
            self.send_error(500, "Metrics not initialized")
            return
        
        content = self.metrics.export()
        self.send_response(200)
        self.send_header("Content-Type", self.metrics.content_type())
        self.send_header("Content-Length", len(content))
        self.end_headers()
        self.wfile.write(content)
    
    def _serve_health(self):
        """Serve health check."""
        content = b'{"status": "healthy"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(content))
        self.end_headers()
        self.wfile.write(content)
    
    def _serve_ready(self):
        """Serve readiness check."""
        content = b'{"ready": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(content))
        self.end_headers()
        self.wfile.write(content)
    
    def log_message(self, format, *args):
        """Suppress default logging (too noisy for /metrics)."""
        pass


class MetricsServer:
    """
    Standalone HTTP server for Agent OS metrics.
    
    Endpoints:
        GET /metrics - Prometheus metrics
        GET /health  - Health check ({"status": "healthy"})
        GET /ready   - Readiness check ({"ready": true})
    
    Example:
        # Start with default metrics
        server = MetricsServer(port=9090)
        server.start()
        
        # Share metrics with kernel
        from agent_os import StatelessKernel
        kernel = StatelessKernel(metrics=server.metrics)
        
        # Stop server
        server.stop()
    """
    
    def __init__(
        self,
        port: int = 9090,
        host: str = "0.0.0.0",
        metrics: Optional[KernelMetrics] = None
    ):
        self.port = port
        self.host = host
        self.metrics = metrics or KernelMetrics()
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
    
    def start(self, blocking: bool = False):
        """
        Start the metrics server.
        
        Args:
            blocking: If True, block the current thread. Default False (background).
        """
        # Set metrics on handler class
        MetricsHandler.metrics = self.metrics
        
        self._server = HTTPServer((self.host, self.port), MetricsHandler)
        
        if blocking:
            print(f"Agent OS Metrics Server running on http://{self.host}:{self.port}")
            print(f"  /metrics - Prometheus metrics")
            print(f"  /health  - Health check")
            print(f"  /ready   - Readiness check")
            self._server.serve_forever()
        else:
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            print(f"Agent OS Metrics Server started on http://{self.host}:{self.port}/metrics")
    
    def stop(self):
        """Stop the metrics server."""
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, *args):
        self.stop()


# =============================================================================
# FastAPI Integration
# =============================================================================

def create_fastapi_router(metrics: Optional[KernelMetrics] = None):
    """
    Create FastAPI router for metrics.
    
    Usage:
        from fastapi import FastAPI
        from agent_os_observability import create_fastapi_router, KernelMetrics
        
        app = FastAPI()
        metrics = KernelMetrics()
        app.include_router(create_fastapi_router(metrics))
    """
    try:
        from fastapi import APIRouter, Response
    except ImportError:
        raise ImportError("FastAPI not installed. Install with: pip install fastapi")
    
    router = APIRouter(tags=["observability"])
    _metrics = metrics or KernelMetrics()
    
    @router.get("/metrics")
    def get_metrics():
        return Response(
            content=_metrics.export(),
            media_type=_metrics.content_type()
        )
    
    @router.get("/health")
    def health():
        return {"status": "healthy"}
    
    @router.get("/ready")
    def ready():
        return {"ready": True}
    
    return router


# =============================================================================
# CLI Entry Point
# =============================================================================

def main():
    """Run metrics server from command line."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Agent OS Metrics Server")
    parser.add_argument("--port", type=int, default=9090, help="Port to listen on")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    args = parser.parse_args()
    
    server = MetricsServer(port=args.port, host=args.host)
    
    try:
        server.start(blocking=True)
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.stop()


if __name__ == "__main__":
    main()
