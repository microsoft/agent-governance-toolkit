# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Execution layer for Agent Tool Registry.

Provides sandboxed execution of tools using Docker containers.
This module handles the actual execution of registered tools, with support
for both local (unsafe) and Docker-based (safe) sandboxed execution.
"""

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Optional
import tempfile
import os
import json


class ExecutorError(Exception):
    """Base exception for executor errors."""
    pass


class ExecutionTimeoutError(ExecutorError):
    """Raised when execution exceeds timeout."""
    pass


class Executor(ABC):
    """Abstract base class for tool executors.
    
    Executors handle the actual execution of registered tools,
    providing different execution environments (local, Docker, etc.).
    """
    
    @abstractmethod
    def execute(
        self,
        func: Callable[..., Any],
        args: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> Any:
        """Execute a callable function.
        
        Args:
            func: The callable function to execute.
            args: Dictionary of arguments to pass to the function.
            timeout: Execution timeout in seconds (None for no timeout).
            
        Returns:
            The result of the function execution.
            
        Raises:
            ExecutorError: If execution fails.
            ExecutionTimeoutError: If execution exceeds timeout.
        """
        pass


class LocalExecutor(Executor):
    """Executor that runs tools directly on the host machine.
    
    WARNING: This executor provides no sandboxing and should only be used
    with trusted code. For untrusted code, use DockerExecutor.
    """
    
    def execute(
        self,
        func: Callable[..., Any],
        args: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> Any:
        """Execute a callable function directly on the host.
        
        Args:
            func: The callable function to execute.
            args: Dictionary of arguments to pass to the function.
            timeout: Execution timeout in seconds (ignored for local execution).
            
        Returns:
            The result of the function execution.
            
        Raises:
            ExecutorError: If execution fails.
        """
        if args is None:
            args = {}
        
        try:
            return func(**args)
        except Exception as e:
            raise ExecutorError(f"Local execution failed: {str(e)}") from e


class DockerExecutor(Executor):
    """Executor that runs tools in isolated Docker containers.
    
    This executor provides sandboxed execution by running tools inside
    ephemeral Docker containers. Containers are automatically cleaned up
    after execution completes or fails.
    
    Attributes:
        image: Docker image to use for execution (default: python:3.9-slim).
        auto_pull: Whether to automatically pull the image if not available.
    """
    
    def __init__(
        self,
        image: str = "python:3.9-slim",
        auto_pull: bool = True,
    ):
        """Initialize Docker executor.
        
        Args:
            image: Docker image to use for execution.
            auto_pull: Whether to automatically pull the image if not available.
            
        Raises:
            ImportError: If docker package is not installed.
            ExecutorError: If Docker daemon is not accessible.
        """
        try:
            import docker
        except ImportError:
            raise ImportError(
                "docker package is required for DockerExecutor. "
                "Install it with: pip install docker"
            )
        
        self.image = image
        self.auto_pull = auto_pull
        
        try:
            self._client = docker.from_env()
            # Test Docker connection
            self._client.ping()
        except Exception as e:
            raise ExecutorError(
                f"Failed to connect to Docker daemon: {str(e)}. "
                "Make sure Docker is installed and running."
            ) from e
        
        # Pull image if needed
        if self.auto_pull:
            self._ensure_image()
    
    def _ensure_image(self) -> None:
        """Ensure the Docker image is available, pulling if necessary."""
        try:
            self._client.images.get(self.image)
        except Exception:
            # Image not found, try to pull it
            try:
                self._client.images.pull(self.image)
            except Exception as e:
                raise ExecutorError(
                    f"Failed to pull Docker image '{self.image}': {str(e)}"
                ) from e
    
    def execute(
        self,
        func: Callable[..., Any],
        args: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> Any:
        """Execute a callable function in a Docker container.
        
        The function is serialized and executed inside an ephemeral container.
        The container is automatically removed after execution.
        
        Args:
            func: The callable function to execute.
            args: Dictionary of arguments to pass to the function.
            timeout: Execution timeout in seconds (None for no timeout).
            
        Returns:
            The result of the function execution.
            
        Raises:
            ExecutorError: If execution fails.
            ExecutionTimeoutError: If execution exceeds timeout.
        """
        if args is None:
            args = {}
        
        # Import required modules
        import docker
        import inspect
        import textwrap
        
        container = None
        try:
            # Get the function source
            try:
                full_source = inspect.getsource(func)
            except (OSError, TypeError):
                raise ExecutorError(
                    "Cannot execute function in Docker: source code unavailable. "
                    "This typically happens with built-in functions or lambdas."
                )
            
            func_name = func.__name__
            
            # Extract just the function definition (skip decorators)
            # Split into lines and find where the def statement starts
            lines = full_source.split('\n')
            func_start_idx = 0
            for i, line in enumerate(lines):
                if line.strip().startswith('def '):
                    func_start_idx = i
                    break
            
            # Get the function definition without decorators
            func_lines = lines[func_start_idx:]
            
            # Dedent to remove any leading indentation
            func_source = textwrap.dedent('\n'.join(func_lines))
            
            # Create execution script
            script = self._create_execution_script(func_source, func_name, args)
            
            # Create temporary directory for script
            with tempfile.TemporaryDirectory() as temp_dir:
                script_path = os.path.join(temp_dir, "execute.py")
                with open(script_path, "w") as f:
                    f.write(script)
                
                # Create container with volume mount
                container = self._client.containers.create(
                    image=self.image,
                    command=["python", "/app/execute.py"],
                    volumes={temp_dir: {"bind": "/app", "mode": "ro"}},
                    network_mode="none",  # Disable network for security
                    mem_limit="512m",  # Limit memory
                    detach=True,
                    auto_remove=False,  # We'll remove manually after getting logs
                )
                
                # Start container
                container.start()
                
                # Wait for completion with timeout
                try:
                    exit_code = container.wait(timeout=timeout)
                    
                    # Get container status
                    if isinstance(exit_code, dict):
                        exit_code = exit_code.get("StatusCode", 0)
                    
                    # Get logs
                    logs = container.logs().decode("utf-8")
                    
                    if exit_code != 0:
                        raise ExecutorError(
                            f"Container execution failed with exit code {exit_code}:\n{logs}"
                        )
                    
                    # Parse result from logs
                    result = self._parse_result(logs)
                    return result
                    
                except Exception as e:
                    # Check if it's a timeout
                    error_str = str(e).lower()
                    if "timeout" in error_str or "timed out" in error_str:
                        raise ExecutionTimeoutError(
                            f"Execution exceeded timeout of {timeout} seconds"
                        ) from e
                    # Re-raise if it's already one of our exception types
                    if isinstance(e, (ExecutorError, ExecutionTimeoutError)):
                        raise
                    # Wrap other exceptions
                    raise ExecutorError(f"Docker execution failed: {str(e)}") from e
                
        except ExecutorError:
            raise
        except ExecutionTimeoutError:
            raise
        except Exception as e:
            raise ExecutorError(f"Docker execution failed: {str(e)}") from e
        finally:
            # Clean up container
            if container is not None:
                try:
                    container.stop(timeout=1)
                except Exception:
                    pass
                try:
                    container.remove(force=True)
                except Exception:
                    pass
    
    def _create_execution_script(
        self,
        func_source: str,
        func_name: str,
        args: Dict[str, Any],
    ) -> str:
        """Create Python script for container execution.
        
        Args:
            func_source: Source code of the function.
            func_name: Name of the function.
            args: Arguments to pass to the function.
            
        Returns:
            Complete Python script as string.
        """
        # Serialize args to JSON and escape for embedding in script
        args_json = json.dumps(args).replace('\\', '\\\\').replace("'", "\\'")
        
        # Build the script with common imports
        script_parts = [
            "import json",
            "import sys",
            "from typing import List, Dict, Optional, Any, Tuple, Set",  # Common type hints
            "",
            "# Define the function",
            func_source,
            "",
            "# Parse arguments",
            f"args = json.loads('{args_json}')",
            "",
            "# Execute function",
            "try:",
            f"    result = {func_name}(**args)",
            "    # Print result with marker for parsing",
            '    print("__RESULT_START__")',
            '    print(json.dumps({"success": True, "result": result}))',
            '    print("__RESULT_END__")',
            "except Exception as e:",
            '    print("__RESULT_START__")',
            '    print(json.dumps({"success": False, "error": str(e)}))',
            '    print("__RESULT_END__")',
            "    sys.exit(1)",
        ]
        
        return "\n".join(script_parts)
    
    def _parse_result(self, logs: str) -> Any:
        """Parse execution result from container logs.
        
        Args:
            logs: Container logs output.
            
        Returns:
            The execution result.
            
        Raises:
            ExecutorError: If result parsing fails.
        """
        try:
            # Find result between markers
            start_marker = "__RESULT_START__"
            end_marker = "__RESULT_END__"
            
            if start_marker not in logs or end_marker not in logs:
                raise ExecutorError(f"Could not find result markers in logs:\n{logs}")
            
            start_idx = logs.index(start_marker) + len(start_marker)
            end_idx = logs.index(end_marker)
            result_json = logs[start_idx:end_idx].strip()
            
            result_data = json.loads(result_json)
            
            if not result_data.get("success"):
                error = result_data.get("error", "Unknown error")
                raise ExecutorError(f"Function execution failed: {error}")
            
            return result_data.get("result")
            
        except json.JSONDecodeError as e:
            raise ExecutorError(f"Failed to parse result JSON: {str(e)}") from e
        except ExecutorError:
            raise
        except Exception as e:
            raise ExecutorError(f"Failed to parse result: {str(e)}") from e
    
    def __del__(self):
        """Clean up Docker client."""
        if hasattr(self, "_client"):
            try:
                self._client.close()
            except Exception:
                pass
