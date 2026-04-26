# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Base Adapter Protocol

Defines the common interface that all layer adapters must implement.
This ensures consistent integration patterns across the stack.
"""

from typing import Dict, Any, Optional, Protocol, runtime_checkable
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime


@dataclass
class AdapterStatus:
    """Status of a layer adapter connection."""
    
    connected: bool
    layer_name: str
    version: Optional[str] = None
    last_health_check: Optional[datetime] = None
    latency_ms: Optional[float] = None
    error: Optional[str] = None


@runtime_checkable
class AdapterProtocol(Protocol):
    """Protocol that all layer adapters must implement."""
    
    def connect(self) -> bool:
        """Establish connection to the layer service."""
        ...
    
    def disconnect(self) -> None:
        """Disconnect from the layer service."""
        ...
    
    def health_check(self) -> AdapterStatus:
        """Check health of the layer connection."""
        ...
    
    def get_layer_name(self) -> str:
        """Get the name of the layer this adapter connects to."""
        ...


class BaseLayerAdapter(ABC):
    """
    Abstract base class for layer adapters.
    
    Provides common functionality for connecting to and interacting
    with lower-layer services in the stack.
    """
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        mock_mode: bool = False,
    ):
        """
        Initialize the adapter.
        
        Args:
            config: Optional configuration for the layer connection
            mock_mode: If True, use mock implementation (for testing)
        """
        self.config = config or {}
        self.mock_mode = mock_mode
        self._connected = False
        self._last_health_check: Optional[datetime] = None
        self._client: Optional[Any] = None
    
    @abstractmethod
    def get_layer_name(self) -> str:
        """Get the name of the layer this adapter connects to."""
        pass
    
    @abstractmethod
    def _create_client(self) -> Any:
        """Create the client for connecting to the layer service."""
        pass
    
    @abstractmethod
    def _mock_client(self) -> Any:
        """Create a mock client for testing."""
        pass
    
    def connect(self) -> bool:
        """
        Establish connection to the layer service.
        
        Returns:
            True if connection successful, False otherwise
        """
        if self._connected:
            return True
        
        try:
            if self.mock_mode:
                self._client = self._mock_client()
            else:
                self._client = self._create_client()
            
            self._connected = True
            self._last_health_check = datetime.now()
            return True
        
        except Exception as e:
            self._connected = False
            return False
    
    def disconnect(self) -> None:
        """Disconnect from the layer service."""
        if self._client and hasattr(self._client, 'close'):
            try:
                self._client.close()
            except Exception:
                pass
        
        self._client = None
        self._connected = False
    
    def health_check(self) -> AdapterStatus:
        """
        Check health of the layer connection.
        
        Returns:
            AdapterStatus with connection details
        """
        self._last_health_check = datetime.now()
        
        if not self._connected or not self._client:
            return AdapterStatus(
                connected=False,
                layer_name=self.get_layer_name(),
                error="Not connected",
            )
        
        try:
            # Attempt a lightweight operation to verify connection
            start = datetime.now()
            self._health_ping()
            latency = (datetime.now() - start).total_seconds() * 1000
            
            return AdapterStatus(
                connected=True,
                layer_name=self.get_layer_name(),
                version=self._get_version(),
                last_health_check=self._last_health_check,
                latency_ms=latency,
            )
        
        except Exception as e:
            self._connected = False
            return AdapterStatus(
                connected=False,
                layer_name=self.get_layer_name(),
                last_health_check=self._last_health_check,
                error=str(e),
            )
    
    def _health_ping(self) -> None:
        """
        Perform a health ping to verify connection.
        Override in subclasses for layer-specific health checks.
        """
        pass
    
    def _get_version(self) -> Optional[str]:
        """
        Get the version of the connected layer service.
        Override in subclasses for layer-specific version retrieval.
        """
        return None
    
    @property
    def is_connected(self) -> bool:
        """Check if adapter is connected."""
        return self._connected
    
    def ensure_connected(self) -> None:
        """Ensure adapter is connected, raising if not."""
        if not self._connected:
            if not self.connect():
                raise ConnectionError(
                    f"Failed to connect to {self.get_layer_name()}"
                )
