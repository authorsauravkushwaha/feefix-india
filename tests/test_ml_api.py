"""Phase 3 — outcome events + V2 rank comparison endpoint."""

from __future__ import annotations

PROFILE = {
    "domicile_state": "West Bengal",
    "category": "general",
    "annual_family_income": 200000,
    "course_level": "ug",
    "gender": "female",
    "is_minority": True,
    "minority_community": "muslim",
    "last_exam_percentage": 82,
}


def _setup(client, sid):
    client.put(f"/api/students/{sid}/profile", json={"profile": PROFILE})
    return sid


def test_event_records_with_context(client):
    sid = _setup(client, "sess-ml1")
    r = client.post("/api/events", json={
        "session_id": sid, "scheme_id": "aicte-pragati", "type": "applied"})
    assert r.status_code == 200
    ctx = r.json()["event"]["context"]
    assert "clarity" in ctx and "benefit_norm" in ctx and "urgency" in ctx


def test_event_validations(client):
    assert client.post("/api/events", json={
        "session_id": "x", "scheme_id": "nope", "type": "applied"}).status_code == 404
    assert client.post("/api/events", json={
        "session_id": "x", "scheme_id": "sv-mcm-wb", "type": "yay"}).status_code == 422


def test_ml_rank_compare_shape(client):
    sid = _setup(client, "sess-ml2")
    match = client.get(f"/api/match/{sid}").json()
    r = client.get(f"/api/ml/rank/{sid}")
    assert r.status_code == 200
    data = r.json()
    assert data["trained_on"] > 0
    assert isinstance(data["bootstrap"], bool)
    assert data["items"], "must rank the session's open matches"

    # Every open match is reranked, with V1 & V2 positions.
    match_ids = {m["id"] for m in match["matches"] if not m["deadline"]["expired"]}
    item_ids = {it["scheme_id"] for it in data["items"]}
    assert item_ids == match_ids
    for it in data["items"]:
        assert 0.0 <= it["model_probability"] <= 1.0
        assert "clarity" in it["features"]
    ranks = sorted(it["v2_rank"] for it in data["items"])
    assert ranks == list(range(1, len(data["items"]) + 1))


def test_ml_rank_deterministic(client):
    sid = _setup(client, "sess-ml3")
    a = client.get(f"/api/ml/rank/{sid}").json()["items"]
    b = client.get(f"/api/ml/rank/{sid}").json()["items"]
    assert a == b


def test_v2_reweights_same_signals_not_inventing(client):
    sid = _setup(client, "sess-ml4")
    data = client.get(f"/api/ml/rank/{sid}").json()
    for it in data["items"]:
        f = it["features"]
        assert set(f) == {"clarity", "urgency", "benefit_norm", "verified"}
