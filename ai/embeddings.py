"""Embedding backends for FeeFix AI.

Policy: **free, open, local models only — never a paid/token-gated API.**

Two backends, one contract::

    backend.name            → "neural" | "ngram"
    backend.embed(texts)    → list[list[float]]   (L2-normalised)

1. **neural** — ``fastembed`` running quantized ONNX ``all-MiniLM-L6-v2``
   locally on CPU (open weights, Apache-2.0/MIT). Best quality; used when the
   model weights are already present or downloadable.
2. **ngram** — a built-in character n-gram *hashed* embedder (zero downloads,
   zero dependencies, ships in this repo). For short scheme documents with
   strong keyword signals it is surprisingly competitive, and it makes every
   install — including offline machines — AI-capable.

Selection: env ``FEEFIX_AI_BACKEND = auto|neural|ngram`` (default ``auto``).
"""

from __future__ import annotations

import hashlib
import math
import os
import re
from dataclasses import dataclass
from typing import Protocol

_TOKEN_RE = re.compile(r"[a-z0-9.]+")


class EmbeddingBackend(Protocol):
    name: str

    def embed(self, texts: list[str]) -> list[list[float]]: ...


# --------------------------------------------------------------------------- #
# 1) Neural backend — fastembed / MiniLM (free, open, local)
# --------------------------------------------------------------------------- #
class NeuralEmbedder:
    name = "neural"

    MODEL = "sentence-transformers/all-MiniLM-L6-v2"

    def __init__(self, timeout_s: float = 30.0):
        from fastembed import TextEmbedding  # lazy import: optional dependency

        self._model = TextEmbedding(model_name=self.MODEL)

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [list(map(float, v)) for v in self._model.embed(texts)]


# --------------------------------------------------------------------------- #
# 2) Built-in n-gram embedder — zero downloads, zero deps
# --------------------------------------------------------------------------- #
def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


class NGramHashEmbedder:
    """Character n-gram hashing embedder.

    Every token contributes its char n-grams (salted per n), hashed into a
    fixed vector. Related spellings ("scholarship"/"scholarships",
    "engineering"/"engineer") share most n-grams, so meaning clusters without
    any pretrained weights. Deterministic — identical across machines.
    """

    name = "ngram"

    def __init__(self, dim: int = 1024, ngrams: tuple[int, ...] = (3, 4)):
        self.dim = dim
        self.ngrams = ngrams

    # -- internals ----------------------------------------------------------
    WORD_WEIGHT = 3.0    # exact-token channel beats fuzzy n-grams
    NGRAM_WEIGHT = 1.0

    def _vector(self, text: str) -> dict[int, float]:
        v: dict[int, float] = {}
        tokens = _tokenize(text)
        for tok in tokens:
            # word-level feature (exact-token channel)
            idx = int.from_bytes(
                hashlib.blake2b(f"w:{tok}".encode(), digest_size=4).digest(), "little"
            ) % self.dim
            v[idx] = v.get(idx, 0.0) + self.WORD_WEIGHT
            padded = f"<{tok}>"
            for n in self.ngrams:
                for i in range(len(padded) - n + 1):
                    ng = padded[i : i + n]
                    idx = int.from_bytes(
                        hashlib.blake2b(f"n{n}:{ng}".encode(), digest_size=4).digest(),
                        "little",
                    ) % self.dim
                    v[idx] = v.get(idx, 0.0) + self.NGRAM_WEIGHT
        # sublinear TF: repeated words ("scholarship… scholarship") stop dominating
        for k in v:
            v[k] = 1.0 + math.log(v[k])
        return v

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for text in texts:
            sparse = self._vector(text)
            norm = math.sqrt(sum(x * x for x in sparse.values())) or 1.0
            dense = [0.0] * self.dim
            for idx, val in sparse.items():
                dense[idx] = val / norm
            vectors.append(dense)
        return vectors


# --------------------------------------------------------------------------- #
# Selection
# --------------------------------------------------------------------------- #
_ORDER = {"auto": ("neural", "ngram"), "neural": ("neural", "ngram"), "ngram": ("ngram",)}


def get_embedder(prefer: str | None = None, quiet: bool = True) -> EmbeddingBackend:
    """Pick the best available free backend. Never raises."""
    prefer = (prefer or os.environ.get("FEEFIX_AI_BACKEND", "auto")).lower()
    for name in _ORDER.get(prefer, _ORDER["auto"]):
        try:
            if name == "neural":
                return NeuralEmbedder()
            return NGramHashEmbedder()
        except Exception as exc:  # offline / weights missing / dependency absent
            if not quiet:
                print(f"[feefix-ai] neural backend unavailable ({exc.__class__.__name__})")
    return NGramHashEmbedder()  # unreachable, but never fail


def cosine(a: list[float], b: list[float]) -> float:
    """Vectors are normalised, so dot product = cosine."""
    return sum(x * y for x, y in zip(a, b))
