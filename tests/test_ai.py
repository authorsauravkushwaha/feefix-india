"""Free-AI layer tests: embeddings, semantic search, grounded Q&A, chat."""

from __future__ import annotations

import re

from ai.embeddings import NGramHashEmbedder, cosine, get_embedder
from ai.qa import QaEngine
from ai.search import SemanticSearch


class TestEmbeddings:
    def test_backend_selected(self):
        backend = get_embedder()
        assert backend.name in ("neural", "ngram")

    def test_ngram_deterministic(self):
        e = NGramHashEmbedder(dim=256)
        a = e.embed(["scholarship for girls"])
        b = e.embed(["scholarship for girls"])
        assert a == b

    def test_related_texts_cluster(self):
        e = NGramHashEmbedder(dim=512)
        q, girls, loan = e.embed(
            ["scholarship for girls", "scholarships girl students", "credit card education loan"]
        )
        assert cosine(q, girls) > cosine(q, loan)

    def test_normalised_vectors(self):
        e = NGramHashEmbedder(dim=256)
        (v,) = e.embed(["west bengal scholarship"])
        norm = sum(x * x for x in v) ** 0.5
        assert abs(norm - 1.0) < 1e-6


class TestSemanticSearch:
    def test_girls_engineering_finds_pragati(self, dataset):
        search = SemanticSearch(dataset.schemes)
        hits = search.search("engineering scholarship for girls", k=5)
        ids = [h.scheme.id for h in hits]
        assert "aicte-pragati" in ids

    def test_disability_finds_disability_schemes(self, dataset):
        search = SemanticSearch(dataset.schemes)
        ids = [h.scheme.id for h in search.search("disability student support", k=6)]
        assert "nsp-post-matric-disabilities" in ids or "aicte-saksham" in ids

    def test_scores_for_subset(self, dataset):
        search = SemanticSearch(dataset.schemes)
        scores = search.scores_for("muslim scholarship", ["aikyashree-wb", "sv-mcm-wb"])
        assert scores["aikyashree-wb"] > scores["sv-mcm-wb"]


class TestGroundedQa:
    def _qa(self, dataset) -> QaEngine:
        return QaEngine(dataset)

    def test_search_mode_when_no_hints(self, dataset):
        r = self._qa(dataset).answer("what documents are usually needed?")
        assert r.mode == "search"
        assert r.citations, "grounded answers must cite schemes"

    def test_grounding_rule(self, dataset):
        """Every bold scheme name in an answer must be an actual cited scheme."""
        r = self._qa(dataset).answer("engineering support for girls")
        bold_names = re.findall(r"\*\*([^*]+)\*\*", r.answer)
        cited = {c["name"] for c in r.citations}
        for name in bold_names:
            assert name in cited, f"Ungrounded mention: {name}"

    def test_profile_hints_detected(self, dataset):
        r = self._qa(dataset).answer(
            "I am a Muslim girl from West Bengal studying B.Tech with family income 2 lakh"
        )
        assert r.mode == "profile"
        d = r.detected_profile
        assert d["domicile_state"] == "West Bengal"
        assert d["gender"] == "female"
        assert d["is_minority"] is True
        assert d["minority_community"] == "muslim"
        assert d["course_level"] == "ug"
        assert d["annual_family_income"] == 200000

    def test_pragati_surfaces_for_engineering_girl(self, dataset):
        r = self._qa(dataset).answer("engineering scholarship for girls")
        top_ids = [c["id"] for c in r.citations[:3]]
        assert "aicte-pragati" in top_ids

    def test_minority_question_surfaces_minority_schemes(self, dataset):
        r = self._qa(dataset).answer("scholarship for muslim students")
        top_ids = [c["id"] for c in r.citations[:4]]
        assert any(i in top_ids for i in ("aikyashree-wb", "nsp-post-matric-minority",
                                          "nsp-merit-cum-means", "begum-hazrat-mahal"))

    def test_no_income_false_positive(self, dataset):
        r = self._qa(dataset).answer("I scored 5000 rank in NEET, any schemes?")
        assert "annual_family_income" not in r.detected_profile

    def test_percentage_detected(self, dataset):
        r = self._qa(dataset).answer("I got 82% in class 12 from West Bengal, girl")
        assert r.detected_profile.get("last_exam_percentage") == 82.0


class TestAiEndpoints:
    def test_semantic_endpoint(self, client):
        r = client.get("/api/search/semantic", params={"q": "minority girls school scholarship"})
        assert r.status_code == 200
        data = r.json()
        assert data["backend"] in ("neural", "ngram")
        assert data["count"] >= 1
        assert data["hits"][0]["semantic_score"] >= data["hits"][-1]["semantic_score"]

    def test_ask_endpoint(self, client):
        r = client.post("/api/ask", json={"question": "scholarship for SC students in west bengal"})
        assert r.status_code == 200
        data = r.json()
        assert data["mode"] in ("search", "profile")
        assert data["citations"]
        names = [c["name"] for c in data["citations"]]
        assert any("OASIS" in n or "Top Class" in n for n in names)

    def test_ask_with_session_profile(self, client):
        sid = "sess-ai-flow"
        client.put(f"/api/students/{sid}/profile", json={"profile": {
            "domicile_state": "West Bengal", "category": "sc",
            "annual_family_income": 90000, "course_level": "ug",
            "gender": "male", "last_exam_percentage": 68,
        }})
        r = client.post("/api/ask", json={"question": "what is my best option?", "session_id": sid})
        data = r.json()
        assert data["mode"] == "profile"

    def test_health_reports_ai_backend(self, client):
        r = client.get("/api/health").json()
        assert r["ai_backend"] in ("neural", "ngram", "offline")

    def test_chat_free_text_after_matching(self, client):
        cid = "chatai1"
        client.post("/api/chat", json={"message": "start", "chat_id": cid})
        client.post("/api/chat", json={"message": "West Bengal", "chat_id": cid})
        client.post("/api/chat", json={"message": "B.Tech", "chat_id": cid})
        client.post("/api/chat", json={"message": "2 lakh", "chat_id": cid})
        r = client.post("/api/chat", json={
            "message": "what documents do these need?", "chat_id": cid})
        data = r.json()
        assert data["step"] == "done"
        assert "citations" in data and data["citations"]
        assert len(data["reply"]) > 40
