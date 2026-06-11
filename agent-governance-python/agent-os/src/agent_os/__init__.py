import warnings
warnings.warn(
    "agent-os-kernel is deprecated and will be removed in a future release. "
    "Use agent-governance-toolkit-core instead. "
    "See https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/package-consolidation/MIGRATION.md",
    DeprecationWarning,
    stacklevel=2,
)

# Keep in sync with the ``version`` field in pyproject.toml.
__version__ = "4.1.0"
