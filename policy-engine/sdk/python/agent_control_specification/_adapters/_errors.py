from __future__ import annotations


class AdapterUnsupportedError(NotImplementedError):
    """Raised when a duck-typed adapter cannot safely wrap the requested shape."""
