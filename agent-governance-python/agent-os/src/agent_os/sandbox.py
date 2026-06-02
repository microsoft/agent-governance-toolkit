# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Execution Sandbox for Agent OS

Provides defense-in-depth restrictions on agent-supplied code via import hooks,
restricted builtins, sys.modules shadowing, and AST-based static analysis.

.. warning::
   This is an **in-process, soft sandbox**. It raises the cost of common
   stdlib-bypass techniques (``subprocess``, ``os.system``, ``eval``,
   ``importlib.import_module``, ``sys.modules`` lookup, dunder traversal),
   but a determined attacker who can execute arbitrary Python in this
   interpreter can still escape (e.g. via C-extension memory tricks, frame
   introspection in compiled code, ``gc`` walks of live objects, or simply
   by exploiting any unblocked third-party module already loaded).

   **For strong isolation, run untrusted code in a separate OS process** with
   ``seccomp``/AppArmor/landlock/Job-Objects, a container, a microVM
   (Firecracker/gVisor), or a WASM runtime. Use this sandbox only as a
   defense-in-depth layer.
"""

from __future__ import annotations

import ast
import builtins as _py_builtins
import importlib.abc
import importlib.machinery
import os
import pathlib
import sys
import threading
import warnings
from dataclasses import dataclass, field
from typing import Any, Callable

from pydantic import BaseModel, Field

from agent_os.exceptions import SecurityError


class SandboxSecurityWarning(UserWarning):
    """Warning category emitted by the sandbox for security-relevant events.

    Lets callers filter sandbox warnings independently of other ``UserWarning``s.
    """


_SAMPLE_DISCLAIMER = (
    "\u26a0\ufe0f  These are SAMPLE sandbox rules provided as a starting point. "
    "You MUST review, customise, and extend them for your specific use case "
    "before deploying to production."
)

# Modules whose top-level name must be blocked from import inside the sandbox.
# Each of these has been used in real Python sandbox-escape PoCs:
#   sys, builtins         -> sys.modules / __builtins__ traversal
#   gc, inspect           -> walking live objects to reach dangerous classes
#   pickle, marshal, code -> arbitrary code execution on deserialisation
#   posix, nt, _posixsubprocess -> low-level stdlib backends behind os/subprocess
#   multiprocessing, threading  -> spawn helpers that wrap subprocess/os
#   pty, fcntl, signal    -> process-control surface
_DEFAULT_BLOCKED_MODULES: list[str] = [
    "subprocess",
    "os",
    "shutil",
    "socket",
    "ctypes",
    "importlib",
    "sys",
    "builtins",
    "gc",
    "inspect",
    "pickle",
    "marshal",
    "code",
    "codeop",
    "pty",
    "fcntl",
    "signal",
    "posix",
    "nt",
    "_posixsubprocess",
    "multiprocessing",
    "threading",
    "_thread",
    "asyncio",
]

_DEFAULT_BLOCKED_BUILTINS: list[str] = [
    "exec",
    "eval",
    "compile",
    "__import__",
    "open",
    "breakpoint",
    "input",
    "help",
    "globals",
    "locals",
    "vars",
    "getattr",
    "setattr",
    "delattr",
    "memoryview",
]

# Builtins permitted by default inside ``create_restricted_globals``. Anything
# not on this list and not explicitly blocked is omitted (fail-closed).
_SAFE_BUILTINS_WHITELIST: frozenset[str] = frozenset({
    # Constants
    "True", "False", "None", "Ellipsis", "NotImplemented", "__build_class__",
    # Core types
    "bool", "int", "float", "complex", "str", "bytes", "bytearray",
    "list", "tuple", "set", "frozenset", "dict", "slice", "range",
    "type", "object", "property", "staticmethod", "classmethod", "super",
    # Numeric / iteration helpers
    "abs", "all", "any", "ascii", "bin", "chr", "divmod", "enumerate",
    "filter", "format", "hex", "id", "isinstance", "issubclass", "iter",
    "len", "map", "max", "min", "next", "oct", "ord", "pow", "print",
    "repr", "reversed", "round", "sorted", "sum", "zip", "hash",
    "callable",
    # Exception classes (allow user code to raise/handle)
    "Exception", "BaseException", "ArithmeticError", "AssertionError",
    "AttributeError", "EOFError", "FloatingPointError", "GeneratorExit",
    "ImportError", "IndexError", "KeyError", "KeyboardInterrupt",
    "LookupError", "MemoryError", "NameError", "NotImplementedError",
    "OSError", "OverflowError", "RecursionError", "ReferenceError",
    "RuntimeError", "StopIteration", "StopAsyncIteration", "SyntaxError",
    "SystemError", "TypeError", "UnboundLocalError", "UnicodeError",
    "ValueError", "ZeroDivisionError",
})

# Dunder attribute names commonly used in Python sandbox escapes
# (e.g. ``().__class__.__bases__[0].__subclasses__()``).
_DANGEROUS_ATTR_NAMES: frozenset[str] = frozenset({
    "__class__", "__bases__", "__base__", "__mro__", "__subclasses__",
    "__globals__", "__builtins__", "__import__", "__loader__", "__spec__",
    "__dict__", "__getattribute__", "__reduce__", "__reduce_ex__",
    "__subclasshook__", "__init_subclass__", "__code__", "__closure__",
    "__func__", "__self__", "__module__", "__wrapped__",
    "func_globals", "gi_frame", "gi_code", "cr_frame", "cr_code",
    "f_globals", "f_locals", "f_builtins", "f_back",
})


# ---------------------------------------------------------------------------
# Externalised configuration dataclass
# ---------------------------------------------------------------------------

@dataclass
class SandboxSecurityConfig:
    """Structured configuration for sandbox security rules, loadable from YAML.

    Attributes:
        blocked_modules: Python modules to deny inside the sandbox.
        blocked_builtins: Built-in functions to block.
        disclaimer: Disclaimer text shown in logs.
    """

    blocked_modules: list[str] = field(default_factory=lambda: list(_DEFAULT_BLOCKED_MODULES))
    blocked_builtins: list[str] = field(default_factory=lambda: list(_DEFAULT_BLOCKED_BUILTINS))
    disclaimer: str = ""


def load_sandbox_config(path: str) -> SandboxSecurityConfig:
    """Load sandbox security configuration from a YAML file.

    Args:
        path: Path to a YAML file with a ``sandbox`` section.

    Returns:
        SandboxSecurityConfig populated from the YAML data.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If the YAML is missing the ``sandbox`` section.
    """
    import yaml

    if not os.path.exists(path):
        raise FileNotFoundError(f"Sandbox config not found: {path}")

    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh.read())

    if not isinstance(data, dict) or "sandbox" not in data:
        raise ValueError(f"YAML file must contain a 'sandbox' section: {path}")

    sp = data["sandbox"]
    return SandboxSecurityConfig(
        blocked_modules=sp.get("blocked_modules", list(_DEFAULT_BLOCKED_MODULES)),
        blocked_builtins=sp.get("blocked_builtins", list(_DEFAULT_BLOCKED_BUILTINS)),
        disclaimer=data.get("disclaimer", ""),
    )


class SandboxConfig(BaseModel):
    """Configuration for the execution sandbox.

    Attributes:
        blocked_modules: Top-level module names denied at import time and
            shadowed in ``sys.modules`` while a sandboxed function runs.
        blocked_builtins: Built-in names replaced with raising stubs in the
            restricted globals.
        allowed_paths: Filesystem roots that ``check_file_access`` will permit.
        max_memory_mb / max_cpu_seconds: Informational hints — this in-process
            sandbox does not enforce resource limits. Use OS-level isolation
            (cgroups, Job Objects, rlimit) for hard guarantees.
        shadow_sys_modules: When True (default), ``execute_sandboxed`` replaces
            blocked entries in ``sys.modules`` with a trap proxy that raises
            ``SecurityError`` on any access, closing the
            ``sys.modules['os'].system(...)`` escape. Disable only when you
            know other concurrent threads need these modules during execution.
        enforce_ast_validation: When True (default), ``execute_code_sandboxed``
            runs ``validate_code`` first and refuses to execute on any
            violation (fail-closed).
    """

    blocked_modules: list[str] = Field(default_factory=lambda: list(_DEFAULT_BLOCKED_MODULES))
    blocked_builtins: list[str] = Field(default_factory=lambda: list(_DEFAULT_BLOCKED_BUILTINS))
    allowed_paths: list[str] = Field(default_factory=list)
    max_memory_mb: int | None = None
    max_cpu_seconds: int | None = None
    shadow_sys_modules: bool = True
    enforce_ast_validation: bool = True


@dataclass
class SecurityViolation:
    """Represents a security violation found during static analysis."""

    line: int
    column: int
    violation_type: str
    description: str
    severity: str = "high"


class SandboxImportHook(importlib.abc.MetaPathFinder):
    """Import hook that blocks imports of dangerous modules.

    Intercepts import attempts for blocked modules and raises SecurityError.
    Can be installed/uninstalled dynamically via install()/uninstall().
    """

    def __init__(self, blocked_modules: list[str]) -> None:
        self._blocked_modules = set(blocked_modules)

    def find_module(
        self,
        fullname: str,
        path: Any = None,
    ) -> SandboxImportHook | None:
        """Check if this module should be blocked (legacy API)."""
        top_level = fullname.split(".")[0]
        if top_level in self._blocked_modules:
            return self
        return None

    def load_module(self, fullname: str) -> None:
        """Block the import by raising SecurityError (legacy API)."""
        raise SecurityError(
            f"Import of '{fullname}' is blocked by sandbox policy",
            error_code="BLOCKED_IMPORT",
            details={"module": fullname},
        )

    def find_spec(
        self,
        fullname: str,
        path: Any = None,
        target: Any = None,
    ) -> None:
        """Intercept import via the modern finder protocol."""
        top_level = fullname.split(".")[0]
        if top_level in self._blocked_modules:
            raise SecurityError(
                f"Import of '{fullname}' is blocked by sandbox policy",
                error_code="BLOCKED_IMPORT",
                details={"module": fullname},
            )
        return None

    def install(self) -> None:
        """Install this hook into sys.meta_path."""
        if self not in sys.meta_path:
            sys.meta_path.insert(0, self)

    def uninstall(self) -> None:
        """Remove this hook from sys.meta_path."""
        while self in sys.meta_path:
            sys.meta_path.remove(self)


class _ASTSecurityVisitor(ast.NodeVisitor):
    """AST visitor that detects security violations in code."""

    def __init__(self, blocked_modules: set, blocked_builtins: set) -> None:
        self._blocked_modules = blocked_modules
        self._blocked_builtins = blocked_builtins
        self.violations: list[SecurityViolation] = []

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            top_level = alias.name.split(".")[0]
            if top_level in self._blocked_modules:
                self.violations.append(
                    SecurityViolation(
                        line=node.lineno,
                        column=node.col_offset,
                        violation_type="blocked_import",
                        description=f"Import of blocked module '{alias.name}'",
                    )
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.module:
            top_level = node.module.split(".")[0]
            if top_level in self._blocked_modules:
                self.violations.append(
                    SecurityViolation(
                        line=node.lineno,
                        column=node.col_offset,
                        violation_type="blocked_import",
                        description=f"Import from blocked module '{node.module}'",
                    )
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        # Detect calls to blocked builtins: eval(...), exec(...)
        if isinstance(node.func, ast.Name) and node.func.id in self._blocked_builtins:
            self.violations.append(
                SecurityViolation(
                    line=node.lineno,
                    column=node.col_offset,
                    violation_type="blocked_builtin",
                    description=f"Call to blocked builtin '{node.func.id}'",
                )
            )

        # Detect getattr(x, '<dangerous_dunder>') bypass
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
        ):
            attr_arg = node.args[1]
            if (
                isinstance(attr_arg, ast.Constant)
                and isinstance(attr_arg.value, str)
                and attr_arg.value in _DANGEROUS_ATTR_NAMES
            ):
                self.violations.append(
                    SecurityViolation(
                        line=node.lineno,
                        column=node.col_offset,
                        violation_type="dunder_escape",
                        description=(
                            f"getattr() used to reach dangerous attribute "
                            f"'{attr_arg.value}'"
                        ),
                    )
                )

        # Detect os.system(...) style calls
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                if node.func.value.id in self._blocked_modules:
                    self.violations.append(
                        SecurityViolation(
                            line=node.lineno,
                            column=node.col_offset,
                            violation_type="blocked_module_call",
                            description=(
                                f"Call to blocked module "
                                f"'{node.func.value.id}.{node.func.attr}'"
                            ),
                        )
                    )

                # Detect importlib.import_module('blocked_mod') bypass
                if (
                    node.func.value.id == "importlib"
                    and node.func.attr == "import_module"
                    and node.args
                ):
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant) and isinstance(
                        arg.value, str
                    ):
                        top_level = arg.value.split(".")[0]
                        if top_level in self._blocked_modules:
                            self.violations.append(
                                SecurityViolation(
                                    line=node.lineno,
                                    column=node.col_offset,
                                    violation_type="blocked_import",
                                    description=(
                                        f"Dynamic import of blocked module "
                                        f"'{arg.value}' via importlib"
                                    ),
                                )
                            )

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:  # noqa: N802
        """Detect dunder traversal escapes like ``().__class__.__bases__``."""
        if node.attr in _DANGEROUS_ATTR_NAMES:
            self.violations.append(
                SecurityViolation(
                    line=node.lineno,
                    column=node.col_offset,
                    violation_type="dunder_escape",
                    description=(
                        f"Access to dangerous attribute '{node.attr}' "
                        "(common sandbox-escape pattern)"
                    ),
                    severity="critical",
                )
            )
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:  # noqa: N802
        """Detect ``sys.modules['os']`` lookups even though ``sys`` is blocked."""
        if (
            isinstance(node.value, ast.Attribute)
            and node.value.attr == "modules"
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "sys"
        ):
            self.violations.append(
                SecurityViolation(
                    line=node.lineno,
                    column=node.col_offset,
                    violation_type="sys_modules_access",
                    description="Access to sys.modules (sandbox bypass attempt)",
                    severity="critical",
                )
            )
        self.generic_visit(node)


class _BlockedModuleProxy:
    """Trap object substituted into ``sys.modules`` for blocked modules.

    Any attribute access, call, item lookup, or repr raises ``SecurityError``,
    closing the ``sys.modules['os'].system(...)`` escape path.

    Notes:
        ``__class__`` is also denied at the Python level to frustrate the
        ``type(proxy).__mro__[1].__subclasses__()`` traversal escape. Python
        callers that need the type can still use ``type(obj)`` (C-level
        ``Py_TYPE``), but a sandboxed *function* (where AST validation does
        not apply) at least cannot reach the proxy's class through standard
        attribute lookup.
    """

    __slots__ = ("_name",)

    def __init__(self, name: str) -> None:
        object.__setattr__(self, "_name", name)

    def _deny(self, op: str) -> None:
        name = object.__getattribute__(self, "_name")
        raise SecurityError(
            f"Access to blocked module '{name}' (operation: {op}) "
            "is denied by sandbox policy",
            error_code="BLOCKED_MODULE_ACCESS",
            details={"module": name, "operation": op},
        )

    def __getattribute__(self, item: str) -> Any:
        # ``_deny`` must be retrievable by our own methods, but nothing else
        # (including ``__class__``) is allowed through.
        if item == "_deny":
            return object.__getattribute__(self, item)
        object.__getattribute__(self, "_deny")(f"getattr {item}")

    def __setattr__(self, key: str, value: Any) -> None:
        object.__getattribute__(self, "_deny")(f"setattr {key}")

    def __delattr__(self, item: str) -> None:
        object.__getattribute__(self, "_deny")(f"delattr {item}")

    def __call__(self, *args: Any, **kwargs: Any) -> None:
        object.__getattribute__(self, "_deny")("call")

    def __getitem__(self, item: Any) -> None:
        object.__getattribute__(self, "_deny")("getitem")

    def __repr__(self) -> str:
        name = object.__getattribute__(self, "_name")
        return f"<BlockedModuleProxy {name!r}>"


# ---------------------------------------------------------------------------
# Process-wide shadow coordination
# ---------------------------------------------------------------------------
#
# ``sys.modules`` is a process-global mapping, so all ``ExecutionSandbox``
# instances must coordinate when they replace its entries with proxies.
# Without this, two failure modes are possible:
#
#   1. Nested ``execute_sandboxed`` calls: an inner call's ``finally`` clears
#      the shadow while the outer call is still executing, restoring real
#      ``os``/``subprocess``/etc. mid-flight.
#   2. Concurrent calls from multiple threads (or multiple sandbox instances):
#      a thread's restore step can wipe another thread's still-active shadow,
#      or can write proxies back into ``sys.modules`` as "originals" and
#      leak them permanently.
#
# We solve both with a single module-level ``RLock`` plus a shared snapshot
# and depth counter. Only the *outermost* enter snapshots, and only the
# *outermost* exit restores. Overlapping sandboxed execution across threads
# serializes on the lock — this is the correct behaviour since
# ``sys.modules`` cannot be partitioned per thread.
_SANDBOX_SHADOW_LOCK = threading.RLock()
_SANDBOX_SHADOW_DEPTH = 0
_SANDBOX_SHADOW_ORIGINALS: dict[str, Any] = {}
_SANDBOX_INSTALLED_HOOKS: list[Any] = []


def _enter_sys_modules_shadow(blocked_modules: list[str]) -> None:
    """Acquire the shadow lock and (if outermost) replace blocked modules.

    Safe to call recursively from the same thread; other threads block on
    the lock until the holder exits. Callers MUST pair every call with
    :func:`_exit_sys_modules_shadow` in a ``finally`` block.
    """
    global _SANDBOX_SHADOW_DEPTH
    _SANDBOX_SHADOW_LOCK.acquire()
    try:
        if _SANDBOX_SHADOW_DEPTH == 0:
            _SANDBOX_SHADOW_ORIGINALS.clear()
            for name in blocked_modules:
                to_shadow = [
                    key for key in list(sys.modules)
                    if key == name or key.startswith(name + ".")
                ]
                for key in to_shadow:
                    current = sys.modules[key]
                    # Defensive: never snapshot a proxy as the "original".
                    if isinstance(current, _BlockedModuleProxy):
                        continue
                    _SANDBOX_SHADOW_ORIGINALS[key] = current
                    sys.modules[key] = _BlockedModuleProxy(key)
        _SANDBOX_SHADOW_DEPTH += 1
    except BaseException:
        _SANDBOX_SHADOW_LOCK.release()
        raise


def _exit_sys_modules_shadow() -> None:
    """Decrement depth; restore ``sys.modules`` on the outermost exit."""
    global _SANDBOX_SHADOW_DEPTH
    try:
        _SANDBOX_SHADOW_DEPTH -= 1
        if _SANDBOX_SHADOW_DEPTH <= 0:
            _SANDBOX_SHADOW_DEPTH = 0
            for key, original in _SANDBOX_SHADOW_ORIGINALS.items():
                # Only restore if the proxy we installed is still there.
                # If something else replaced it, leave that in place.
                if isinstance(sys.modules.get(key), _BlockedModuleProxy):
                    sys.modules[key] = original
            _SANDBOX_SHADOW_ORIGINALS.clear()
    finally:
        _SANDBOX_SHADOW_LOCK.release()


def _install_hook_reentrant(hook: Any) -> None:
    """Install a meta-path hook with depth tracking.

    Must be called while ``_SANDBOX_SHADOW_LOCK`` is held (i.e. between
    ``_enter_sys_modules_shadow`` and ``_exit_sys_modules_shadow``) to
    serialize updates to ``sys.meta_path``.

    Tracks whether *this* call owns the install: ``SandboxImportHook.install``
    is idempotent, so nested same-instance calls would otherwise let the
    inner ``_uninstall_hook_reentrant`` remove the hook while the outer
    call still needs it.
    """
    already_installed = hook in sys.meta_path
    hook.install()
    _SANDBOX_INSTALLED_HOOKS.append((hook, not already_installed))


def _uninstall_hook_reentrant() -> None:
    """Remove the most recently installed hook (LIFO).

    Only calls ``hook.uninstall()`` if this layer was the one that actually
    installed it; nested same-instance calls leave the hook in place for
    the outer call.
    """
    if _SANDBOX_INSTALLED_HOOKS:
        hook, owns_install = _SANDBOX_INSTALLED_HOOKS.pop()
        if owns_install:
            hook.uninstall()





class ExecutionSandbox:
    """Restricted execution environment that frustrates stdlib bypass.

    Combines import hooks, ``sys.modules`` shadowing, restricted builtins, and
    AST-based static analysis. **This is not a true security boundary** — see
    the module docstring for the threat model and recommended OS-level
    alternatives.
    """

    def __init__(
        self,
        config: SandboxConfig | None = None,
        policy: Any = None,
    ) -> None:
        if config is None:
            warnings.warn(
                "ExecutionSandbox() uses built-in sample rules. This is an "
                "in-process soft sandbox and does NOT provide a security "
                "boundary against a determined attacker. Use OS-level "
                "isolation (containers, seccomp, microVMs) for untrusted "
                "code. For production sandbox rules, load an explicit config "
                "via load_sandbox_config(). "
                "See examples/policies/sandbox-safety.yaml.",
                category=SandboxSecurityWarning,
                stacklevel=2,
            )
        self.config = config or SandboxConfig()
        self.policy = policy
        self._hook = SandboxImportHook(self.config.blocked_modules)

    def check_import(self, module_name: str) -> bool:
        """Check if a module import is allowed.

        Args:
            module_name: The module name to check.

        Returns:
            True if the import is allowed, False if blocked.
        """
        top_level = module_name.split(".")[0]
        return top_level not in self.config.blocked_modules

    def check_builtin(self, name: str) -> bool:
        """Check if a builtin call is allowed.

        Args:
            name: The builtin name to check.

        Returns:
            True if the builtin is allowed, False if blocked.
        """
        return name not in self.config.blocked_builtins

    def check_file_access(self, path: str, mode: str = "r") -> bool:
        """Check if file access is allowed based on allowed_paths.

        Args:
            path: The file path to check.
            mode: The access mode (e.g., 'r', 'w').

        Returns:
            True if the access is allowed, False if blocked.
        """
        if not self.config.allowed_paths:
            return False

        # Resolve symlinks and '..' to prevent path traversal attacks
        try:
            resolved = pathlib.Path(path).resolve()
        except (OSError, ValueError):
            return False

        for allowed in self.config.allowed_paths:
            try:
                allowed_resolved = pathlib.Path(allowed).resolve()
            except (OSError, ValueError):
                continue
            # Use is_relative_to for safe containment check
            if resolved == allowed_resolved or resolved.is_relative_to(
                allowed_resolved
            ):
                return True
        return False

    def create_restricted_globals(
        self,
        user_globals: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a restricted globals dict with a whitelist of safe builtins.

        Only names in :data:`_SAFE_BUILTINS_WHITELIST` are exposed. Names in
        ``config.blocked_builtins`` are replaced with raising stubs so that
        explicit attempts to call them produce a clear ``SecurityError``.
        Everything else (e.g. ``open``, ``__import__``, ``breakpoint``,
        ``__loader__``) is omitted entirely — fail-closed.

        Args:
            user_globals: Optional dict of user-provided globals to merge in.
                A ``__builtins__`` key in ``user_globals`` is ignored.

        Returns:
            A globals dict suitable for ``exec(code, restricted)``.
        """
        safe_builtins: dict[str, Any] = {}
        all_builtins = vars(_py_builtins)
        for name in _SAFE_BUILTINS_WHITELIST:
            if name in all_builtins:
                safe_builtins[name] = all_builtins[name]

        # Replace blocked names with raising stubs so callers get a clear
        # SecurityError instead of NameError (better signal for auditors).
        for name in self.config.blocked_builtins:
            safe_builtins[name] = _make_blocked_builtin(name)

        restricted: dict[str, Any] = {"__builtins__": safe_builtins}

        if user_globals:
            for k, v in user_globals.items():
                if k != "__builtins__":
                    restricted[k] = v

        return restricted

    def validate_code(self, code: str) -> list[SecurityViolation]:
        """Validate code via AST static analysis for blocked calls.

        Args:
            code: Python source code to analyze.

        Returns:
            A list of SecurityViolation instances found in the code.
        """
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return [
                SecurityViolation(
                    line=0,
                    column=0,
                    violation_type="syntax_error",
                    description="Code contains syntax errors and cannot be analyzed",
                    severity="medium",
                )
            ]

        visitor = _ASTSecurityVisitor(
            blocked_modules=set(self.config.blocked_modules),
            blocked_builtins=set(self.config.blocked_builtins),
        )
        visitor.visit(tree)
        return visitor.violations

    def _shadow_sys_modules(self) -> None:
        """Replace blocked entries in ``sys.modules`` with trap proxies.

        Closes the ``sys.modules['os'].system(...)`` escape that the import
        hook alone cannot stop (preloaded modules are already cached).
        Caller must invoke :meth:`_restore_sys_modules` to clean up.

        Reentrant and thread-safe via :func:`_enter_sys_modules_shadow`:
        only the outermost call across the whole process actually snapshots
        and replaces entries; concurrent calls from other threads serialize
        on the shared shadow lock.
        """
        _enter_sys_modules_shadow(self.config.blocked_modules)

    def _restore_sys_modules(self) -> None:
        """Restore ``sys.modules`` entries replaced by :meth:`_shadow_sys_modules`.

        Only the outermost paired call across the whole process actually
        restores; inner calls just decrement the depth counter.
        """
        _exit_sys_modules_shadow()

    def execute_sandboxed(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Run a function with import hooks and (optionally) sys.modules shadowing.

        Args:
            func: The function to execute.
            *args: Positional arguments passed to the function.
            **kwargs: Keyword arguments passed to the function.

        Returns:
            The return value of the function.

        Note:
            ``func`` is already-compiled bytecode and is **not** AST-validated
            — this path therefore only protects against accidental misuse by
            *trusted* host code. For untrusted source code, always use
            :meth:`execute_code_sandboxed`, which runs AST validation first.

            When ``config.shadow_sys_modules`` is True (default), this
            temporarily replaces blocked entries in the *process-wide*
            ``sys.modules`` cache. Concurrent ``execute_sandboxed`` calls
            from other threads serialize on a shared lock; nested calls
            on the same thread share the shadow without double-snapshotting.
            Disable ``shadow_sys_modules`` if you need concurrent host
            access to those modules.

            Because the shared shadow lock is held for the entire duration
            of ``func`` execution, a long-running or non-terminating
            sandboxed function will block other threads that try to enter
            the sandbox. Use the subprocess-based providers in
            :mod:`agent_os.sandbox_provider` for adversarial workloads.
        """
        if self.config.shadow_sys_modules:
            # Acquire the shared lock + reentrant shadow first, then install
            # the per-instance import hook under that lock. Pairing both
            # under one lock prevents another thread from observing a
            # half-installed sandbox.
            self._shadow_sys_modules()
            try:
                _install_hook_reentrant(self._hook)
                try:
                    return func(*args, **kwargs)
                finally:
                    _uninstall_hook_reentrant()
            finally:
                self._restore_sys_modules()
        else:
            self._hook.install()
            try:
                return func(*args, **kwargs)
            finally:
                self._hook.uninstall()

    def execute_code_sandboxed(
        self,
        code: str,
        user_globals: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Validate, then ``exec`` source code under all sandbox protections.

        Fail-closed flow:

        1. Parse and AST-validate ``code``. Any violation raises
           ``SecurityError`` before any code runs (when
           ``config.enforce_ast_validation`` is True).
        2. Build restricted globals (whitelist builtins + raising stubs).
        3. Install the import hook and shadow ``sys.modules``.
        4. Execute ``code`` and return the resulting globals dict.

        Args:
            code: Python source to execute.
            user_globals: Optional extra names to expose to the code.

        Returns:
            The post-execution globals dict (without ``__builtins__``).

        Raises:
            SecurityError: If validation finds any violation, or if execution
                triggers a blocked import / builtin / sys.modules access.
        """
        if self.config.enforce_ast_validation:
            violations = self.validate_code(code)
            if violations:
                descriptions = "; ".join(
                    f"line {v.line}: {v.description}" for v in violations
                )
                raise SecurityError(
                    f"Sandboxed code rejected by static analysis: {descriptions}",
                    error_code="SANDBOX_VALIDATION_FAILED",
                    details={
                        "violations": [
                            {
                                "line": v.line,
                                "column": v.column,
                                "type": v.violation_type,
                                "description": v.description,
                                "severity": v.severity,
                            }
                            for v in violations
                        ]
                    },
                )

        restricted = self.create_restricted_globals(user_globals)

        def _run() -> None:
            exec(code, restricted)  # noqa: S102 - sandboxed execution by design

        try:
            self.execute_sandboxed(_run)
        except SecurityError:
            raise
        except Exception as e:
            # Re-wrap unexpected errors so callers always see SecurityError
            # for sandbox-related failures (fail-closed signalling).
            raise SecurityError(
                f"Sandboxed execution failed: {e}",
                error_code="SANDBOX_EXECUTION_ERROR",
                details={"error_type": type(e).__name__, "error": str(e)},
            ) from e

        # Strip restricted builtins from the returned dict; callers only
        # want the user-visible names that were created.
        return {k: v for k, v in restricted.items() if k != "__builtins__"}


def _make_blocked_builtin(name: str) -> Callable[..., None]:
    """Create a function that raises SecurityError when called."""

    def _blocked(*args: Any, **kwargs: Any) -> None:
        raise SecurityError(
            f"Builtin '{name}' is blocked by sandbox policy",
            error_code="BLOCKED_BUILTIN",
            details={"builtin": name},
        )

    _blocked.__name__ = f"blocked_{name}"
    return _blocked
