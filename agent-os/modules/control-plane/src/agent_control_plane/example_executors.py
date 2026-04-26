# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example Executors for Agent Control Plane

These are example/demonstration executors showing how to implement
action handlers. In production, these would be replaced with actual
implementations that interface with real systems.
"""

from typing import Dict, Any
from .execution_engine import ExecutionContext


def file_read_executor(parameters: Dict[str, Any], context: ExecutionContext) -> Any:
    """
    Example executor for file read operations
    
    In production, this would:
    - Actually read files from the filesystem
    - Apply additional security checks
    - Handle errors appropriately
    """
    path = parameters.get('path')
    if not path:
        raise ValueError("Missing 'path' parameter")
    
    # This is a simulation - real implementation would read actual files
    return {
        "action": "file_read",
        "path": path,
        "content": f"[Simulated content of {path}]",
        "sandbox_level": context.sandbox_level.value,
        "note": "This is a simulated response. Replace with actual file reading in production."
    }


def file_write_executor(parameters: Dict[str, Any], context: ExecutionContext) -> Any:
    """
    Example executor for file write operations
    
    In production, this would:
    - Actually write files to the filesystem
    - Verify write permissions
    - Handle atomic writes
    """
    path = parameters.get('path')
    content = parameters.get('content')
    
    if not path:
        raise ValueError("Missing 'path' parameter")
    if not content:
        raise ValueError("Missing 'content' parameter")
    
    # This is a simulation - real implementation would write actual files
    return {
        "action": "file_write",
        "path": path,
        "bytes_written": len(str(content)),
        "sandbox_level": context.sandbox_level.value,
        "note": "This is a simulated response. Replace with actual file writing in production."
    }


def code_execution_executor(parameters: Dict[str, Any], context: ExecutionContext) -> Any:
    """
    Example executor for code execution
    
    In production, this would:
    - Execute code in an isolated container
    - Capture stdout/stderr
    - Enforce resource limits
    - Handle timeouts
    """
    code = parameters.get('code')
    language = parameters.get('language', 'python')
    
    if not code:
        raise ValueError("Missing 'code' parameter")
    
    # This is a simulation - real implementation would execute in container
    return {
        "action": "code_execution",
        "language": language,
        "output": "[Simulated execution output]",
        "exit_code": 0,
        "sandbox_level": context.sandbox_level.value,
        "note": "This is a simulated response. Replace with actual code execution in production."
    }


def api_call_executor(parameters: Dict[str, Any], context: ExecutionContext) -> Any:
    """
    Example executor for API calls
    
    In production, this would:
    - Make actual HTTP requests
    - Apply rate limiting
    - Handle retries
    - Validate SSL certificates
    """
    url = parameters.get('url')
    method = parameters.get('method', 'GET')
    
    if not url:
        raise ValueError("Missing 'url' parameter")
    
    if not context.allowed_network:
        raise PermissionError("Network access not allowed in this context")
    
    # This is a simulation - real implementation would make actual HTTP requests
    return {
        "action": "api_call",
        "url": url,
        "method": method,
        "status_code": 200,
        "response": "[Simulated API response]",
        "note": "This is a simulated response. Replace with actual HTTP requests in production."
    }


def database_query_executor(parameters: Dict[str, Any], context: ExecutionContext) -> Any:
    """
    Example executor for database queries
    
    In production, this would:
    - Execute actual SQL queries
    - Use connection pooling
    - Apply query timeouts
    - Sanitize inputs
    """
    query = parameters.get('query')
    database = parameters.get('database', 'default')
    
    if not query:
        raise ValueError("Missing 'query' parameter")
    
    # This is a simulation - real implementation would execute actual queries
    return {
        "action": "database_query",
        "database": database,
        "rows": "[Simulated query results]",
        "row_count": 0,
        "note": "This is a simulated response. Replace with actual database queries in production."
    }


def database_write_executor(parameters: Dict[str, Any], context: ExecutionContext) -> Any:
    """
    Example executor for database writes
    
    In production, this would:
    - Execute actual write operations
    - Use transactions
    - Handle rollbacks
    - Validate data integrity
    """
    query = parameters.get('query')
    database = parameters.get('database', 'default')
    
    if not query:
        raise ValueError("Missing 'query' parameter")
    
    # This is a simulation - real implementation would execute actual writes
    return {
        "action": "database_write",
        "database": database,
        "rows_affected": 0,
        "note": "This is a simulated response. Replace with actual database writes in production."
    }


def workflow_trigger_executor(parameters: Dict[str, Any], context: ExecutionContext) -> Any:
    """
    Example executor for workflow triggers
    
    In production, this would:
    - Trigger actual workflows
    - Track workflow execution
    - Handle callbacks
    """
    workflow_id = parameters.get('workflow_id')
    workflow_params = parameters.get('params', {})
    
    if not workflow_id:
        raise ValueError("Missing 'workflow_id' parameter")
    
    # This is a simulation - real implementation would trigger actual workflows
    return {
        "action": "workflow_trigger",
        "workflow_id": workflow_id,
        "execution_id": "[Simulated execution ID]",
        "status": "started",
        "note": "This is a simulated response. Replace with actual workflow triggers in production."
    }
