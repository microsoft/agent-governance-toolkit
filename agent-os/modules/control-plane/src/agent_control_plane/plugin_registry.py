# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Plugin Registry - Runtime Registration and Dependency Injection

This module provides a central registry for managing pluggable components:
- Kernels (e.g., SCAK, default kernel)
- Validators (e.g., capability validators, risk validators)
- Executors (e.g., sandboxed, remote, distributed)
- Context routers (e.g., CAAS integration)
- Policy providers (e.g., file-based, database, remote)
- Protocol integrations (iatp, cmvk, caas)

Layer 3: The Framework
- Components are registered at runtime via config or dependency injection
- No hard imports of specific implementations (scak, mute-agent are forbidden)
- Allowed dependencies: iatp, cmvk, caas (optional)
"""

from typing import Any, Dict, List, Optional, Type, TypeVar, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import logging
import importlib

from .interfaces.kernel_interface import KernelInterface, KernelMetadata, KernelCapability
from .interfaces.plugin_interface import (
    PluginInterface,
    PluginMetadata,
    ValidatorInterface,
    ExecutorInterface,
    ContextRouterInterface,
    PolicyProviderInterface,
    SupervisorInterface,
    CapabilityValidatorInterface,
)
from .interfaces.protocol_interfaces import (
    MessageSecurityInterface,
    VerificationInterface,
    ContextRoutingInterface,
)


logger = logging.getLogger("PluginRegistry")


class PluginType(Enum):
    """Types of plugins that can be registered"""
    KERNEL = "kernel"
    VALIDATOR = "validator"
    EXECUTOR = "executor"
    CONTEXT_ROUTER = "context_router"
    POLICY_PROVIDER = "policy_provider"
    SUPERVISOR = "supervisor"
    MESSAGE_SECURITY = "message_security"
    VERIFIER = "verifier"


@dataclass
class PluginRegistration:
    """Registration record for a plugin"""
    plugin_id: str
    plugin_type: PluginType
    instance: Any
    metadata: Union[PluginMetadata, KernelMetadata]
    registered_at: datetime = field(default_factory=datetime.now)
    is_active: bool = True
    config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RegistryConfiguration:
    """Configuration for the plugin registry"""
    # Allow lazy loading of plugins
    lazy_loading: bool = True
    
    # Plugin discovery paths
    plugin_paths: List[str] = field(default_factory=list)
    
    # Auto-register built-in plugins
    auto_register_builtins: bool = True
    
    # Forbidden dependencies (will raise error if detected)
    forbidden_dependencies: List[str] = field(default_factory=lambda: ["scak", "mute_agent"])
    
    # Allowed protocol dependencies
    allowed_protocols: List[str] = field(default_factory=lambda: ["iatp", "cmvk", "caas"])


class PluginRegistry:
    """
    Central registry for pluggable components.
    
    The registry manages:
    - Registration and lookup of plugins
    - Dependency injection configuration
    - Plugin lifecycle (initialize, configure, shutdown)
    - Plugin discovery from paths
    
    Example Usage:
        ```python
        registry = PluginRegistry()
        
        # Register a custom kernel
        registry.register_kernel(my_kernel, config={"timeout": 30})
        
        # Register a validator
        registry.register_validator(my_validator, action_types=["code_execution"])
        
        # Get the active kernel
        kernel = registry.get_kernel()
        
        # Get validators for an action type
        validators = registry.get_validators_for_action("code_execution")
        ```
    """
    
    _instance: Optional["PluginRegistry"] = None
    
    def __new__(cls, *args, **kwargs):
        """Singleton pattern - ensure single registry instance"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, config: Optional[RegistryConfiguration] = None):
        if self._initialized:
            return
        
        self.config = config or RegistryConfiguration()
        self._plugins: Dict[str, PluginRegistration] = {}
        self._active_kernel: Optional[str] = None
        self._validator_mappings: Dict[str, List[str]] = {}  # action_type -> plugin_ids
        self._executor_mappings: Dict[str, str] = {}  # action_type -> plugin_id
        self._initialized = True
        
        logger.info("Plugin registry initialized")
    
    @classmethod
    def reset(cls):
        """Reset the singleton instance (mainly for testing)"""
        cls._instance = None
    
    # =========================================================================
    # Kernel Registration
    # =========================================================================
    
    def register_kernel(
        self,
        kernel: KernelInterface,
        plugin_id: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
        set_active: bool = True
    ) -> str:
        """
        Register a kernel implementation.
        
        Args:
            kernel: The kernel instance to register
            plugin_id: Optional ID (defaults to kernel name)
            config: Optional configuration for the kernel
            set_active: Whether to set this as the active kernel
            
        Returns:
            The plugin ID
        """
        self._check_forbidden_dependencies(kernel)
        
        plugin_id = plugin_id or kernel.metadata.name
        
        if config:
            kernel.configure(config)
        
        registration = PluginRegistration(
            plugin_id=plugin_id,
            plugin_type=PluginType.KERNEL,
            instance=kernel,
            metadata=kernel.metadata,
            config=config or {}
        )
        
        self._plugins[plugin_id] = registration
        
        if set_active:
            self._active_kernel = plugin_id
        
        kernel.metadata.is_loaded = True
        kernel.metadata.load_timestamp = datetime.now()
        
        logger.info(f"Registered kernel: {plugin_id} (version {kernel.metadata.version})")
        return plugin_id
    
    def get_kernel(self, plugin_id: Optional[str] = None) -> Optional[KernelInterface]:
        """
        Get a kernel by ID or the active kernel.
        
        Args:
            plugin_id: Optional specific kernel ID
            
        Returns:
            The kernel instance or None
        """
        target_id = plugin_id or self._active_kernel
        if not target_id or target_id not in self._plugins:
            return None
        
        registration = self._plugins[target_id]
        if registration.plugin_type != PluginType.KERNEL:
            return None
        
        return registration.instance
    
    def set_active_kernel(self, plugin_id: str) -> bool:
        """Set the active kernel by ID"""
        if plugin_id not in self._plugins:
            return False
        if self._plugins[plugin_id].plugin_type != PluginType.KERNEL:
            return False
        
        self._active_kernel = plugin_id
        return True
    
    # =========================================================================
    # Validator Registration
    # =========================================================================
    
    def register_validator(
        self,
        validator: ValidatorInterface,
        plugin_id: Optional[str] = None,
        action_types: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Register a validator.
        
        Args:
            validator: The validator instance
            plugin_id: Optional ID (defaults to validator name)
            action_types: List of action types this validator handles
            config: Optional configuration
            
        Returns:
            The plugin ID
        """
        self._check_forbidden_dependencies(validator)
        
        plugin_id = plugin_id or validator.metadata.name
        
        if config:
            validator.configure(config)
        
        registration = PluginRegistration(
            plugin_id=plugin_id,
            plugin_type=PluginType.VALIDATOR,
            instance=validator,
            metadata=validator.metadata,
            config=config or {}
        )
        
        self._plugins[plugin_id] = registration
        
        # Map to action types
        if action_types:
            for action_type in action_types:
                if action_type not in self._validator_mappings:
                    self._validator_mappings[action_type] = []
                self._validator_mappings[action_type].append(plugin_id)
        
        validator.metadata.is_loaded = True
        validator.metadata.load_timestamp = datetime.now()
        
        logger.info(f"Registered validator: {plugin_id}")
        return plugin_id
    
    def get_validators_for_action(self, action_type: str) -> List[ValidatorInterface]:
        """Get all validators for an action type"""
        plugin_ids = self._validator_mappings.get(action_type, [])
        return [
            self._plugins[pid].instance 
            for pid in plugin_ids 
            if pid in self._plugins
        ]
    
    def get_all_validators(self) -> List[ValidatorInterface]:
        """Get all registered validators"""
        return [
            reg.instance for reg in self._plugins.values()
            if reg.plugin_type == PluginType.VALIDATOR
        ]
    
    # =========================================================================
    # Executor Registration
    # =========================================================================
    
    def register_executor(
        self,
        executor: ExecutorInterface,
        plugin_id: Optional[str] = None,
        action_types: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Register an executor.
        
        Args:
            executor: The executor instance
            plugin_id: Optional ID
            action_types: List of action types this executor handles
            config: Optional configuration
            
        Returns:
            The plugin ID
        """
        self._check_forbidden_dependencies(executor)
        
        plugin_id = plugin_id or executor.metadata.name
        
        if config:
            executor.configure(config)
        
        registration = PluginRegistration(
            plugin_id=plugin_id,
            plugin_type=PluginType.EXECUTOR,
            instance=executor,
            metadata=executor.metadata,
            config=config or {}
        )
        
        self._plugins[plugin_id] = registration
        
        # Map to action types
        if action_types:
            for action_type in action_types:
                self._executor_mappings[action_type] = plugin_id
        
        executor.metadata.is_loaded = True
        executor.metadata.load_timestamp = datetime.now()
        
        logger.info(f"Registered executor: {plugin_id}")
        return plugin_id
    
    def get_executor_for_action(self, action_type: str) -> Optional[ExecutorInterface]:
        """Get the executor for an action type"""
        plugin_id = self._executor_mappings.get(action_type)
        if not plugin_id or plugin_id not in self._plugins:
            return None
        return self._plugins[plugin_id].instance
    
    # =========================================================================
    # Context Router Registration
    # =========================================================================
    
    def register_context_router(
        self,
        router: Union[ContextRouterInterface, ContextRoutingInterface],
        plugin_id: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> str:
        """Register a context router (for caas integration)"""
        self._check_forbidden_dependencies(router)
        
        # Get plugin ID - prefer metadata if available
        if plugin_id:
            pass  # Use provided plugin_id
        elif hasattr(router, 'metadata') and hasattr(router.metadata, 'name'):  # type: ignore
            plugin_id = router.metadata.name  # type: ignore
        else:
            plugin_id = f"router_{id(router)}"
        
        if config and hasattr(router, 'configure'):
            router.configure(config)  # type: ignore
        
        # Get metadata if available
        if hasattr(router, 'metadata'):
            metadata = router.metadata  # type: ignore
        else:
            metadata = PluginMetadata(
                name=plugin_id,
                version="1.0.0",
                description="Context router",
                plugin_type="context_router"
            )
        
        registration = PluginRegistration(
            plugin_id=plugin_id,
            plugin_type=PluginType.CONTEXT_ROUTER,
            instance=router,
            metadata=metadata,
            config=config or {}
        )
        
        self._plugins[plugin_id] = registration
        logger.info(f"Registered context router: {plugin_id}")
        return plugin_id
    
    def get_context_router(self, plugin_id: Optional[str] = None) -> Optional[Union[ContextRouterInterface, ContextRoutingInterface]]:
        """Get a context router by ID or the first available"""
        if plugin_id:
            if plugin_id in self._plugins and self._plugins[plugin_id].plugin_type == PluginType.CONTEXT_ROUTER:
                return self._plugins[plugin_id].instance
            return None
        
        # Return first available router
        for reg in self._plugins.values():
            if reg.plugin_type == PluginType.CONTEXT_ROUTER:
                return reg.instance
        return None
    
    # =========================================================================
    # Policy Provider Registration
    # =========================================================================
    
    def register_policy_provider(
        self,
        provider: PolicyProviderInterface,
        plugin_id: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> str:
        """Register a policy provider"""
        self._check_forbidden_dependencies(provider)
        
        plugin_id = plugin_id or provider.metadata.name
        
        if config:
            provider.configure(config)
        
        registration = PluginRegistration(
            plugin_id=plugin_id,
            plugin_type=PluginType.POLICY_PROVIDER,
            instance=provider,
            metadata=provider.metadata,
            config=config or {}
        )
        
        self._plugins[plugin_id] = registration
        logger.info(f"Registered policy provider: {plugin_id}")
        return plugin_id
    
    def get_policy_providers(self) -> List[PolicyProviderInterface]:
        """Get all registered policy providers"""
        return [
            reg.instance for reg in self._plugins.values()
            if reg.plugin_type == PluginType.POLICY_PROVIDER
        ]
    
    # =========================================================================
    # Supervisor Registration
    # =========================================================================
    
    def register_supervisor(
        self,
        supervisor: SupervisorInterface,
        plugin_id: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> str:
        """Register a supervisor agent"""
        self._check_forbidden_dependencies(supervisor)
        
        plugin_id = plugin_id or supervisor.metadata.name
        
        if config:
            supervisor.configure(config)
        
        registration = PluginRegistration(
            plugin_id=plugin_id,
            plugin_type=PluginType.SUPERVISOR,
            instance=supervisor,
            metadata=supervisor.metadata,
            config=config or {}
        )
        
        self._plugins[plugin_id] = registration
        logger.info(f"Registered supervisor: {plugin_id}")
        return plugin_id
    
    def get_supervisors(self) -> List[SupervisorInterface]:
        """Get all registered supervisors"""
        return [
            reg.instance for reg in self._plugins.values()
            if reg.plugin_type == PluginType.SUPERVISOR
        ]
    
    # =========================================================================
    # Protocol Integration (iatp, cmvk, caas)
    # =========================================================================
    
    def register_message_security(
        self,
        security: MessageSecurityInterface,
        plugin_id: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> str:
        """Register a message security provider (for iatp integration)"""
        plugin_id = plugin_id or f"message_security_{id(security)}"
        
        registration = PluginRegistration(
            plugin_id=plugin_id,
            plugin_type=PluginType.MESSAGE_SECURITY,
            instance=security,
            metadata=PluginMetadata(
                name=plugin_id,
                version="1.0.0",
                description="Message security provider",
                plugin_type="message_security"
            ),
            config=config or {}
        )
        
        self._plugins[plugin_id] = registration
        logger.info(f"Registered message security: {plugin_id}")
        return plugin_id
    
    def get_message_security(self) -> Optional[MessageSecurityInterface]:
        """Get the message security provider"""
        for reg in self._plugins.values():
            if reg.plugin_type == PluginType.MESSAGE_SECURITY:
                return reg.instance
        return None
    
    def register_verifier(
        self,
        verifier: VerificationInterface,
        plugin_id: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> str:
        """Register a verifier (for cmvk integration)"""
        plugin_id = plugin_id or f"verifier_{id(verifier)}"
        
        registration = PluginRegistration(
            plugin_id=plugin_id,
            plugin_type=PluginType.VERIFIER,
            instance=verifier,
            metadata=PluginMetadata(
                name=plugin_id,
                version="1.0.0",
                description="Verification provider",
                plugin_type="verifier"
            ),
            config=config or {}
        )
        
        self._plugins[plugin_id] = registration
        logger.info(f"Registered verifier: {plugin_id}")
        return plugin_id
    
    def get_verifier(self) -> Optional[VerificationInterface]:
        """Get the verification provider"""
        for reg in self._plugins.values():
            if reg.plugin_type == PluginType.VERIFIER:
                return reg.instance
        return None
    
    # =========================================================================
    # Plugin Discovery and Loading
    # =========================================================================
    
    def discover_plugins(self, path: Optional[str] = None) -> List[str]:
        """
        Discover plugins from a path.
        
        Args:
            path: Path to search for plugins (or use config paths)
            
        Returns:
            List of discovered plugin IDs
        """
        paths = [path] if path else self.config.plugin_paths
        discovered = []
        
        for plugin_path in paths:
            try:
                # Import module and look for plugin classes
                module = importlib.import_module(plugin_path)
                
                # Look for classes implementing our interfaces
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if isinstance(attr, type):
                        if issubclass(attr, KernelInterface) and attr != KernelInterface:
                            discovered.append(f"{plugin_path}.{attr_name}")
                        elif issubclass(attr, ValidatorInterface) and attr != ValidatorInterface:
                            discovered.append(f"{plugin_path}.{attr_name}")
                            
            except ImportError as e:
                logger.warning(f"Failed to import plugin path {plugin_path}: {e}")
        
        return discovered
    
    def load_plugin_from_path(
        self,
        module_path: str,
        class_name: str,
        config: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Load and register a plugin from a module path.
        
        Args:
            module_path: Python module path
            class_name: Name of the plugin class
            config: Optional configuration
            
        Returns:
            The plugin ID
        """
        # Check for forbidden dependencies
        for forbidden in self.config.forbidden_dependencies:
            if forbidden in module_path:
                raise ValueError(
                    f"Cannot load plugin from forbidden dependency: {forbidden}. "
                    f"Forbidden dependencies: {self.config.forbidden_dependencies}"
                )
        
        module = importlib.import_module(module_path)
        plugin_class = getattr(module, class_name)
        instance = plugin_class()
        
        if isinstance(instance, KernelInterface):
            return self.register_kernel(instance, config=config)
        elif isinstance(instance, ValidatorInterface):
            return self.register_validator(instance, config=config)
        elif isinstance(instance, ExecutorInterface):
            return self.register_executor(instance, config=config)
        elif isinstance(instance, ContextRouterInterface):
            return self.register_context_router(instance, config=config)
        elif isinstance(instance, PolicyProviderInterface):
            return self.register_policy_provider(instance, config=config)
        elif isinstance(instance, SupervisorInterface):
            return self.register_supervisor(instance, config=config)
        else:
            raise TypeError(f"Unknown plugin type: {type(instance)}")
    
    # =========================================================================
    # Plugin Lifecycle
    # =========================================================================
    
    def initialize_all(self) -> None:
        """Initialize all registered plugins"""
        for registration in self._plugins.values():
            if hasattr(registration.instance, 'initialize'):
                registration.instance.initialize()
        logger.info(f"Initialized {len(self._plugins)} plugins")
    
    def shutdown_all(self) -> None:
        """Shutdown all registered plugins"""
        for registration in self._plugins.values():
            if hasattr(registration.instance, 'shutdown'):
                registration.instance.shutdown()
        logger.info("All plugins shut down")
    
    def health_check_all(self) -> Dict[str, Dict[str, Any]]:
        """Run health check on all plugins"""
        results = {}
        for plugin_id, registration in self._plugins.items():
            if hasattr(registration.instance, 'health_check'):
                results[plugin_id] = registration.instance.health_check()
            else:
                results[plugin_id] = {"status": "unknown", "reason": "no health_check method"}
        return results
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    def _check_forbidden_dependencies(self, instance: Any) -> None:
        """Check if an instance comes from a forbidden dependency"""
        module = type(instance).__module__
        for forbidden in self.config.forbidden_dependencies:
            if forbidden in module:
                raise ValueError(
                    f"Cannot register plugin from forbidden dependency: {forbidden}. "
                    f"Plugin module: {module}. "
                    f"Forbidden dependencies: {self.config.forbidden_dependencies}"
                )
    
    def get_plugin(self, plugin_id: str) -> Optional[Any]:
        """Get any plugin by ID"""
        if plugin_id in self._plugins:
            return self._plugins[plugin_id].instance
        return None
    
    def unregister_plugin(self, plugin_id: str) -> bool:
        """Unregister a plugin"""
        if plugin_id not in self._plugins:
            return False
        
        registration = self._plugins[plugin_id]
        
        # Shutdown if possible
        if hasattr(registration.instance, 'shutdown'):
            registration.instance.shutdown()
        
        # Remove from mappings
        for action_type, plugin_ids in list(self._validator_mappings.items()):
            if plugin_id in plugin_ids:
                plugin_ids.remove(plugin_id)
        
        for action_type, pid in list(self._executor_mappings.items()):
            if pid == plugin_id:
                del self._executor_mappings[action_type]
        
        # Clear active kernel if needed
        if self._active_kernel == plugin_id:
            self._active_kernel = None
        
        del self._plugins[plugin_id]
        logger.info(f"Unregistered plugin: {plugin_id}")
        return True
    
    def list_plugins(self, plugin_type: Optional[PluginType] = None) -> List[Dict[str, Any]]:
        """List all registered plugins"""
        plugins = []
        for plugin_id, registration in self._plugins.items():
            if plugin_type and registration.plugin_type != plugin_type:
                continue
            
            plugins.append({
                "plugin_id": plugin_id,
                "type": registration.plugin_type.value,
                "name": registration.metadata.name,
                "version": registration.metadata.version,
                "is_active": registration.is_active,
                "registered_at": registration.registered_at.isoformat()
            })
        
        return plugins
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get registry statistics"""
        type_counts = {}
        for registration in self._plugins.values():
            type_name = registration.plugin_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
        
        return {
            "total_plugins": len(self._plugins),
            "plugins_by_type": type_counts,
            "active_kernel": self._active_kernel,
            "validator_mappings": len(self._validator_mappings),
            "executor_mappings": len(self._executor_mappings)
        }


# Convenience function to get the global registry
def get_registry() -> PluginRegistry:
    """Get the global plugin registry instance"""
    return PluginRegistry()
