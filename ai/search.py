"""Semantic search over the scheme catalogue.

Each scheme becomes a retrieval document built from its *structured fields* —
never scraped prose — so match quality mirrors data quality. Scores are
cosine similarities over the active free embedding backend (MiniLM when
weights are present locally, else the built-in n-gram embedder).
"""

from __future__ import annotations

from dataclasses import dataclass

from ai.embeddings import EmbeddingBackend, cosine, get_embedder
from ai.lexicon import expand_query
from backend.models.scheme import Scheme


def scheme_document(s: Scheme) -> str:
    e = s.eligibility
    bits = [
        s.name,
        s.provider,
        s.summary,
        s.benefit.type.replace("_", " "),
        s.benefit.amount_display,
        " ".join(s.tags),
        " ".join(s.documents),
        " ".join(e.special_conditions),
        f"income limit {e.max_family_income} rupees" if e.max_family_income else "",
        f"marks {e.min_marks_percent} percent merit" if e.min_marks_percent else "",
        f"girls female" if e.genders and len(e.genders) == 1 and e.genders[0].value == "female" else "",
        "minority communities" if e.minority_only else "",
        "disability divyang" if e.disability_required else "",
        " ".join(c.replace("_", " ") for c in [c.value for c in e.course_levels] or []),
        " ".join(e.domicile_states or ["all india"]),
        s.application.mode,
    ]
    return " | ".join(b for b in bits if b)


@dataclass
class SearchHit:
    scheme: Scheme
    score: float


class SemanticSearch:
    def __init__(self, schemes: list[Scheme], embedder: EmbeddingBackend | None = None):
        self.schemes = schemes
        self.embedder = embedder or get_embedder()
        self.backend_name = getattr(self.embedder, "name", "unknown")
        # Expand documents with the same lexicon as queries for token symmetry
        # ("technical" in a doc must meet "engineering" in a query).
        documents = [expand_query(scheme_document(s)) for s in schemes]
        self._vectors = self.embedder.embed(documents) if documents else []
        self._by_id = {s.id: i for i, s in enumerate(schemes)}

    def search(self, query: str, k: int = 5, expand: bool = True) -> list[SearchHit]:
        q = expand_query(query) if expand else query
        (qv,) = self.embedder.embed([q])
        hits = [SearchHit(s, cosine(qv, v)) for s, v in zip(self.schemes, self._vectors)]
        hits.sort(key=lambda h: (-h.score, h.scheme.name))
        return hits[:k]

    def scores_for(self, query: str, scheme_ids: list[str] | set[str]) -> dict[str, float]:
        """Semantic scores for a subset of schemes (used to re-rank matches)."""
        q = expand_query(query)
        (qv,) = self.embedder.embed([q])
        out: dict[str, float] = {}
        for sid in scheme_ids:
            idx = self._by_id.get(sid)
            if idx is not None:
                out[sid] = cosine(qv, self._vectors[idx])
        return out
