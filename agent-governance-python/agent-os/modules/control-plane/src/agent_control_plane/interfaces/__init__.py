# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Control Plane - Interfaces Module

This module defines the abstract interfaces that allow for:
1. Dependency injection of kernels (e.g., scak can implement KernelInterface)
2. Plugin-based architecture for validators, executors, and context routers
3. Runtime configuration without hard imports

Layer 3: The Framework
- Allowed dependencies: iatp, cmvk, caas
- Forbidden dependencies: scak, mute-agent (these should implement our interfaces)
"""

from .kernel_interface import (
    KernelInterface,
    KernelCapability,
    KernelMetadata,
)

from .plugin_interface import (
    ValidatorInterface,
    ExecutorInterface,
    ContextRouterInterface,
    PolicyProviderInterface,
    PluginCapability,
    PluginMetadata,
)

from .protocol_interfaces import (
    MessageSecurityInterface,
    VerificationInterface,
    ContextRoutingInterface,
)

__all__ = [
    # Kernel Interface (for scak and other kernel implementations)
    "KernelInterface",
    "KernelCapability",
    "KernelMetadata",
    
    # Plugin Interfaces (for extensibility)
    "ValidatorInterface",
    "ExecutorInterface",
    "ContextRouterInterface",
    "PolicyProviderInterface",
    "PluginCapability",
    "PluginMetadata",
    
    # Protocol Interfaces (for iatp, cmvk, caas integration)
    "MessageSecurityInterface",
    "VerificationInterface",
    "ContextRoutingInterface",
]
