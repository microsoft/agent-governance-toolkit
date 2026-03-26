# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic context/memory management
"""
Tiered Context Manager — single-tier context storage.

All items are stored in one flat list regardless of the layer label
passed through the public API.  Hot/Warm/Cold labels are preserved on
each item for compatibility but do not affect retrieval behaviour.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import uuid

from caas.models import ContextLayer, ContextTriadItem, ContextTriadState


class ContextTriadManager:
    """
    Manages context items in a single flat list.

    The original Hot/Warm/Cold method signatures are preserved so that
    callers continue to work without changes.
    """

    def __init__(self):
        """Initialize the Tiered Context Manager."""
        self.state = ContextTriadState()

    # -- internal helper ---------------------------------------------------

    def _add_item(
        self,
        layer: ContextLayer,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        priority: float = 1.0,
    ) -> str:
        item_id = str(uuid.uuid4())
        item = ContextTriadItem(
            id=item_id,
            layer=layer,
            content=content,
            metadata=metadata or {},
            timestamp=datetime.now(timezone.utc).isoformat(),
            priority=priority,
        )
        # Single backing list — use hot_context for all items
        self.state.hot_context.append(item)
        return item_id

    # -- public add methods (signatures unchanged) -------------------------

    def add_hot_context(
        self,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        priority: float = 1.0,
    ) -> str:
        """Add context labelled as *hot*."""
        return self._add_item(ContextLayer.HOT, content, metadata, priority)

    def add_warm_context(
        self,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        priority: float = 1.0,
    ) -> str:
        """Add context labelled as *warm*."""
        return self._add_item(ContextLayer.WARM, content, metadata, priority)

    def add_cold_context(
        self,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        priority: float = 1.0,
    ) -> str:
        """Add context labelled as *cold*."""
        return self._add_item(ContextLayer.COLD, content, metadata, priority)

    # -- retrieval helpers -------------------------------------------------

    def _format_items(
        self,
        items: List[ContextTriadItem],
        header: str,
        max_tokens: int = 1000,
        include_metadata: bool = False,
    ) -> str:
        if not items:
            return ""
        sorted_items = sorted(items, key=lambda x: (-x.priority, x.timestamp or ""))
        parts: List[str] = [f"# {header}\n"]
        total = len(parts[0])
        limit = max_tokens * 4
        for item in sorted_items:
            if include_metadata:
                text = f"\n## {item.metadata.get('source', item.metadata.get('category', 'Unknown'))}\n{item.content}\n"
            else:
                text = f"\n{item.content}\n"
            if total + len(text) > limit:
                break
            parts.append(text)
            total += len(text)
        return "".join(parts)

    def get_hot_context(self, max_tokens: int = 1000, include_metadata: bool = False) -> str:
        """Return items labelled *hot*."""
        items = [i for i in self.state.hot_context if i.layer == ContextLayer.HOT]
        return self._format_items(items, "Hot Context (Current Situation)", max_tokens, include_metadata)

    def get_warm_context(self, max_tokens: int = 500, include_metadata: bool = False) -> str:
        """Return items labelled *warm*."""
        items = [i for i in self.state.hot_context if i.layer == ContextLayer.WARM]
        return self._format_items(items, "Warm Context (User Persona)", max_tokens, include_metadata)

    def get_cold_context(
        self,
        query: Optional[str] = None,
        max_tokens: int = 1000,
        include_metadata: bool = False,
    ) -> str:
        """Return items labelled *cold*, optionally filtered by *query*."""
        items = [i for i in self.state.hot_context if i.layer == ContextLayer.COLD]
        if query:
            q = query.lower()
            items = [i for i in items if q in i.content.lower() or q in str(i.metadata).lower()]
        return self._format_items(items, "Cold Context (Historical Archive)", max_tokens, include_metadata)

    def get_full_context(
        self,
        include_hot: bool = True,
        include_warm: bool = True,
        include_cold: bool = False,
        cold_query: Optional[str] = None,
        max_tokens_per_layer: Optional[Dict[str, int]] = None,
        include_metadata: bool = False,
    ) -> Dict[str, Any]:
        """Return context from requested layers."""
        if max_tokens_per_layer is None:
            max_tokens_per_layer = {"hot": 1000, "warm": 500, "cold": 1000}

        all_items = self.state.hot_context
        result: Dict[str, Any] = {
            "hot_context": "",
            "warm_context": "",
            "cold_context": "",
            "layers_included": [],
            "total_tokens": 0,
            "metadata": {
                "hot_items_count": sum(1 for i in all_items if i.layer == ContextLayer.HOT),
                "warm_items_count": sum(1 for i in all_items if i.layer == ContextLayer.WARM),
                "cold_items_count": sum(1 for i in all_items if i.layer == ContextLayer.COLD),
            },
        }

        if include_hot:
            ctx = self.get_hot_context(max_tokens_per_layer.get("hot", 1000), include_metadata)
            if ctx:
                result["hot_context"] = ctx
                result["layers_included"].append("hot")
                result["total_tokens"] += len(ctx) // 4

        if include_warm:
            ctx = self.get_warm_context(max_tokens_per_layer.get("warm", 500), include_metadata)
            if ctx:
                result["warm_context"] = ctx
                result["layers_included"].append("warm")
                result["total_tokens"] += len(ctx) // 4

        if include_cold and cold_query:
            ctx = self.get_cold_context(cold_query, max_tokens_per_layer.get("cold", 1000), include_metadata)
            if ctx:
                result["cold_context"] = ctx
                result["layers_included"].append("cold")
                result["total_tokens"] += len(ctx) // 4

        return result

    # -- mutation helpers --------------------------------------------------

    def clear_hot_context(self):
        """Remove items labelled *hot*."""
        self.state.hot_context = [i for i in self.state.hot_context if i.layer != ContextLayer.HOT]

    def clear_warm_context(self):
        """Remove items labelled *warm*."""
        self.state.hot_context = [i for i in self.state.hot_context if i.layer != ContextLayer.WARM]

    def clear_cold_context(self):
        """Remove items labelled *cold*."""
        self.state.hot_context = [i for i in self.state.hot_context if i.layer != ContextLayer.COLD]

    def clear_all(self):
        """Clear all context items."""
        self.state = ContextTriadState()

    def remove_item(self, item_id: str, layer: Optional[ContextLayer] = None) -> bool:
        """Remove a specific item by ID."""
        for i, item in enumerate(self.state.hot_context):
            if item.id == item_id and (layer is None or item.layer == layer):
                del self.state.hot_context[i]
                return True
        return False

    def get_state(self) -> ContextTriadState:
        """Return the current state."""
        return self.state

    def set_state(self, state: ContextTriadState):
        """Replace the current state."""
        self.state = state
