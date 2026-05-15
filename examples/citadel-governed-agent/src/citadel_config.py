# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Citadel Gateway Configuration

Handles configuration for routing requests through a Citadel APIM gateway
and exporting audit events to Azure Monitor.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CitadelGatewayConfig:
    """Configuration for connecting to a Citadel APIM gateway.

    Attributes:
        gateway_url: Base URL of the Citadel APIM gateway.
        api_key: APIM subscription key for authentication.
        jwt_token: Optional JWT bearer token for additional auth.
        timeout_seconds: Request timeout in seconds.
    """

    gateway_url: str = ""
    api_key: str = ""
    jwt_token: str = ""
    timeout_seconds: int = 30

    @classmethod
    def from_env(cls) -> CitadelGatewayConfig:
        """Load configuration from environment variables."""
        return cls(
            gateway_url=os.environ.get("CITADEL_GATEWAY_URL", ""),
            api_key=os.environ.get("CITADEL_API_KEY", ""),
            jwt_token=os.environ.get("CITADEL_JWT_TOKEN", ""),
            timeout_seconds=int(os.environ.get("CITADEL_TIMEOUT", "30")),
        )

    @property
    def is_configured(self) -> bool:
        """Check if gateway configuration is complete."""
        return bool(self.gateway_url and self.api_key)

    def get_headers(self) -> dict[str, str]:
        """Build request headers for Citadel gateway calls."""
        headers: dict[str, str] = {
            "Ocp-Apim-Subscription-Key": self.api_key,
        }
        if self.jwt_token:
            headers["Authorization"] = f"Bearer {self.jwt_token}"
        return headers


@dataclass
class CitadelExporterConfig:
    """Configuration for exporting audit events to Citadel's observability stack.

    Attributes:
        eventhub_connection_string: Azure Event Hub connection string.
        appinsights_connection_string: Application Insights connection string.
        enabled: Whether export is enabled.
        batch_size: Number of events to batch before sending.
        flush_interval_seconds: Maximum time between flushes.
    """

    eventhub_connection_string: str = ""
    appinsights_connection_string: str = ""
    enabled: bool = True
    batch_size: int = 50
    flush_interval_seconds: int = 10

    @classmethod
    def from_env(cls) -> CitadelExporterConfig:
        """Load configuration from environment variables."""
        return cls(
            eventhub_connection_string=os.environ.get(
                "CITADEL_EVENTHUB_CONNECTION_STRING", ""
            ),
            appinsights_connection_string=os.environ.get(
                "CITADEL_APPINSIGHTS_CONNECTION_STRING", ""
            ),
            enabled=os.environ.get("CITADEL_EXPORT_ENABLED", "true").lower() == "true",
            batch_size=int(os.environ.get("CITADEL_EXPORT_BATCH_SIZE", "50")),
            flush_interval_seconds=int(
                os.environ.get("CITADEL_EXPORT_FLUSH_INTERVAL", "10")
            ),
        )

    @property
    def has_eventhub(self) -> bool:
        """Check if Event Hub export is configured."""
        return bool(self.eventhub_connection_string)

    @property
    def has_appinsights(self) -> bool:
        """Check if Application Insights export is configured."""
        return bool(self.appinsights_connection_string)


@dataclass
class MockGateway:
    """Mock Citadel gateway for local testing without Azure dependencies.

    Simulates gateway-level policy enforcement: rate limiting, content
    filtering, and subscription validation.
    """

    call_count: int = 0
    rate_limit: int = 100
    rate_window_seconds: int = 3600
    _call_timestamps: list[float] = field(default_factory=list)

    def process_request(
        self,
        endpoint: str,
        payload: dict,
        headers: Optional[dict[str, str]] = None,
    ) -> dict:
        """Simulate a gateway-processed LLM request.

        Args:
            endpoint: The model endpoint path.
            payload: The request payload.
            headers: Optional request headers.

        Returns:
            Simulated response with gateway metadata.
        """
        import time

        self.call_count += 1
        now = time.time()
        self._call_timestamps = [
            t for t in self._call_timestamps if now - t < self.rate_window_seconds
        ]
        self._call_timestamps.append(now)

        if len(self._call_timestamps) > self.rate_limit:
            return {
                "status": 429,
                "error": "Rate limit exceeded",
                "gateway": "citadel-mock",
                "remaining": 0,
            }

        return {
            "status": 200,
            "data": {
                "response": f"Mock LLM response for {endpoint}",
                "model": "gpt-4o-mock",
            },
            "gateway": "citadel-mock",
            "remaining": self.rate_limit - len(self._call_timestamps),
            "apim_request_id": f"mock-{self.call_count:06d}",
        }
