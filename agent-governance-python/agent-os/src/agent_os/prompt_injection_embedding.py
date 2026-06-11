# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Optional embedding evidence signal for prompt-injection review/routing.

This is an **optional, default-off** companion to the rules-based
``PromptInjectionDetector``. When explicitly enabled, it produces an auditable
**nearest-neighbour margin** for a piece of text against a labelled exemplar
bank — a semantic-similarity score that surfaces injection cases the
deterministic rules miss.

Design posture (deliberate, see ``docs/benchmarks/prompt-injection-methodology.md``):

* **Disabled by default** — inert unless ``EmbeddingSignalConfig.enabled`` is set.
* **Evidence-only** — returns a margin; it does **not** block, deny, or enforce.
  Governance metadata / policy decides any action. ``EmbeddingEvidence.blocks``
  is always ``False``.
* **No hosted-inference requirement** — the embedder is a local, pluggable
  callable. The default uses ``fastembed`` (a local ONNX model), which is an
  **optional** dependency: it is never required unless the signal is enabled and
  no embedder is injected.
* **Additive** — existing detector behaviour is unchanged.

The kNN-margin logic is portable research evidence: ``margin = mean top-k cosine
similarity to attack exemplars − mean top-k cosine similarity to benign
exemplars``. A higher margin means "more like known attacks". The signal is
intended to feed review/routing, not to auto-block.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

# An embedder maps texts to fixed-width float vectors. Injectable so the logic
# is testable without any model download, and so callers can supply any local
# embedding backend.
Embedder = Callable[[Sequence[str]], Sequence[Sequence[float]]]

DEFAULT_MODEL_ID = "BAAI/bge-small-en-v1.5"
DEFAULT_K = 5


class EmbeddingSignalUnavailable(RuntimeError):
    """Raised when the signal is enabled but no usable embedder is available."""


@dataclass(frozen=True)
class EmbeddingEvidence:
    """Auditable, non-enforcing output of the embedding signal."""

    margin: float
    """Higher = more similar to known attacks than to benign controls."""
    k: int
    bank_size: int
    blocks: bool = False
    """Always False — embeddings are evidence only and never block on their own."""
    note: str = "evidence-only; embeddings do not block on their own"


@dataclass
class EmbeddingSignalConfig:
    """Configuration. The signal is OFF unless ``enabled`` is explicitly True."""

    enabled: bool = False
    k: int = DEFAULT_K
    model_id: str = DEFAULT_MODEL_ID


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b):
        dot += x * y
        na += x * x
        nb += y * y
    denom = math.sqrt(na) * math.sqrt(nb)
    return dot / denom if denom else 0.0


def _topk_mean_cos(query: Sequence[float], bank: Sequence[Sequence[float]], k: int) -> float:
    sims = sorted((_cosine(query, ref) for ref in bank), reverse=True)
    top = sims[:k]
    return sum(top) / len(top) if top else 0.0


class EmbeddingSignal:
    """Optional, default-off embedding evidence signal.

    Args:
        config: behaviour flags; ``enabled`` defaults to False (inert).
        exemplars: labelled bank as ``(text, is_attack)`` pairs.
        embedder: optional local embedder. If omitted and the signal is enabled,
            a ``fastembed`` backend is built lazily (optional dependency).
    """

    def __init__(
        self,
        config: EmbeddingSignalConfig,
        exemplars: Sequence[tuple[str, bool]],
        embedder: Optional[Embedder] = None,
    ) -> None:
        if not exemplars:
            raise ValueError("exemplar bank must be non-empty")
        self.config = config
        self._exemplars = list(exemplars)
        self._embedder = embedder
        self._pos: Optional[list[Sequence[float]]] = None
        self._neg: Optional[list[Sequence[float]]] = None
        # Only touch the embedder when actually enabled — fully inert when off.
        if config.enabled:
            self._build()

    def _resolve_embedder(self) -> Embedder:
        if self._embedder is None:
            self._embedder = _build_fastembed_embedder(self.config.model_id)
        return self._embedder

    def _build(self) -> None:
        pos_texts = [t for t, is_attack in self._exemplars if is_attack]
        neg_texts = [t for t, is_attack in self._exemplars if not is_attack]
        if not pos_texts or not neg_texts:
            raise ValueError("exemplar bank needs both attack and benign examples")
        embed = self._resolve_embedder()
        self._pos = [list(v) for v in embed(pos_texts)]
        self._neg = [list(v) for v in embed(neg_texts)]

    def score(self, text: str) -> Optional[EmbeddingEvidence]:
        """Return evidence for ``text``, or ``None`` when the signal is disabled.

        Never blocks: the returned ``EmbeddingEvidence`` is advisory only.
        """
        if not self.config.enabled:
            return None
        if self._pos is None or self._neg is None:
            self._build()
        assert self._pos is not None and self._neg is not None
        query = list(self._resolve_embedder()([text])[0])
        k = max(1, min(self.config.k, len(self._pos), len(self._neg)))
        margin = _topk_mean_cos(query, self._pos, k) - _topk_mean_cos(query, self._neg, k)
        return EmbeddingEvidence(margin=float(margin), k=k, bank_size=len(self._pos) + len(self._neg))


def _build_fastembed_embedder(model_id: str) -> Embedder:
    """Build the default local (ONNX) embedder. Optional dependency.

    Raises ``EmbeddingSignalUnavailable`` if ``fastembed`` is not installed, so an
    enabled-but-unequipped deployment fails safe with a clear message rather than
    an opaque import error.
    """
    try:
        from fastembed import TextEmbedding  # type: ignore
    except ImportError as exc:  # pragma: no cover - exercised via tests with a fake
        raise EmbeddingSignalUnavailable(
            "embedding signal enabled but optional dependency 'fastembed' is not "
            "installed; install the 'embedding' extra or inject an embedder"
        ) from exc

    model = TextEmbedding(model_name=model_id)

    def embed(texts: Sequence[str]) -> Sequence[Sequence[float]]:
        return [list(map(float, v)) for v in model.embed(list(texts))]

    return embed
