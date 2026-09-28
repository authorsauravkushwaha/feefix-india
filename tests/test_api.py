"""API contract tests — the same surface the web app and app consume."""

from __future__ import annotations

PROFILE = {
    "domicile_state": "West Bengal",
    "category": "general",
    "annual_family_income": 200000,
    "course_level": "ug",
    "gender": "female",
    "is_minority": True,
    "minority_community": "muslim",
    "has_disability": False,
    "last_exam_percentage": 82,
    "is_single_girl_child": False,
}


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["schemes_loaded"] >= 15


def test_meta(client):
    r = client.get("/api/meta")
    data = r.json()
    assert "West Bengal" in data["states"]
    assert "ug" in data["course_levels"]
    assert "saved" in data["track_statuses"]


def test_schemes_listing(client):
    r = client.get("/api/schemes")
    data = r.json()
    assert data["count"] >= 15
    first = data["schemes"][0]
    for key in ("id", "name", "benefit", "deadline", "eligibility", "documents",
                "application", "official_url", "verification_status"):
        assert key in first


def test_schemes_search_and_filter(client):
    q = client.get("/api/schemes", params={"q": "kanyashree"}).json()
    assert q["count"] == 1
    fee = client.get("/api/schemes", params={"fee_waiver": "true"}).json()
    assert all(s["benefit"]["type"] == "fee_waiver" for s in fee["schemes"])
    state = client.get("/api/schemes", params={"level": "state"}).json()
    assert all(s["level"] == "state" for s in state["schemes"])


def test_scheme_detail_and_404(client):
    r = client.get("/api/schemes/sv-mcm-wb")
    assert r.status_code == 200
    assert r.json()["id"] == "sv-mcm-wb"
    assert client.get("/api/schemes/nope").status_code == 404


def test_match_pipeline(client):
    r = client.post("/api/match", json={"profile": PROFILE})
    assert r.status_code == 200
    data = r.json()
    assert data["match_count"] > 0
    ids = [m["id"] for m in data["matches"]]
    assert "aikyashree-wb" in ids
    match = next(m for m in data["matches"] if m["id"] == "aikyashree-wb")
    assert match["why_matched"], "match must be explained"
    assert match["score"] > 0
    assert data["near_misses"] or data["matches"]


def test_match_is_ranked_descending(client):
    data = client.post("/api/match", json={"profile": PROFILE}).json()
    open_scores = [m["score"] for m in data["matches"] if not m["deadline"]["expired"]]
    assert open_scores == sorted(open_scores, reverse=True)


def test_profile_roundtrip_and_session_match(client):
    sid = "sess-profile-flow"
    r = client.put(f"/api/students/{sid}/profile", json={"profile": PROFILE})
    assert r.status_code == 200 and r.json()["saved"]
    got = client.get(f"/api/students/{sid}/profile").json()
    assert got["profile"]["domicile_state"] == "West Bengal"
    session_match = client.get(f"/api/match/{sid}").json()
    assert session_match["match_count"] > 0


def test_tracker_flow(client):
    sid = "sess-tracker-flow"
    r = client.put(f"/api/tracker/{sid}/sv-mcm-wb", json={"status": "saved"})
    assert r.status_code == 200
    r = client.put(f"/api/tracker/{sid}/sv-mcm-wb", json={"status": "applied"})
    assert r.json()["board"]["sv-mcm-wb"]["status"] == "applied"
    bad = client.put(f"/api/tracker/{sid}/sv-mcm-wb", json={"status": "nonsense"})
    assert bad.status_code == 422
    board = client.get(f"/api/tracker/{sid}").json()
    assert board["count"] == 1
    assert board["items"][0]["id"] == "sv-mcm-wb"
    # clearing
    client.put(f"/api/tracker/{sid}/sv-mcm-wb", json={"status": None})
    assert client.get(f"/api/tracker/{sid}").json()["count"] == 0


def test_reminders(client):
    sid = "sess-reminders-flow"
    client.put(f"/api/students/{sid}/profile", json={"profile": PROFILE})
    client.put(f"/api/tracker/{sid}/nsp-post-matric-minority", json={"status": "saved"})
    r = client.get(f"/api/students/{sid}/reminders")
    assert r.status_code == 200
    data = r.json()
    assert data["count"] > 0
    assert all("message" in x and "severity" in x for x in data["reminders"])


def test_reminders_dispatch(client):
    sid = "sess-dispatch-flow"
    client.put(f"/api/students/{sid}/profile", json={"profile": PROFILE})
    r = client.post(f"/api/students/{sid}/reminders/dispatch", json={"limit": 3})
    assert r.status_code == 200
    assert r.json()["dispatched"] >= 1
    assert all(x["delivered"] for x in r.json()["receipts"])


def test_chat_full_conversation(client):
    r = client.post("/api/chat", json={"message": "start"})
    chat_id = r.json()["chat_id"]
    assert "Question 1" in r.json()["reply"]
    r = client.post("/api/chat", json={"message": "West Bengal", "chat_id": chat_id})
    assert "Question 2" in r.json()["reply"]
    r = client.post("/api/chat", json={"message": "B.Tech", "chat_id": chat_id})
    assert "Question 3" in r.json()["reply"]
    r = client.post("/api/chat", json={"message": "₹2,00,000", "chat_id": chat_id})
    data = r.json()
    assert "match" in data["reply"].lower()
    assert len(data["matches"]) >= 3
    assert data["step"] == "done"


def test_i18n(client):
    en = client.get("/api/i18n/en").json()
    bn = client.get("/api/i18n/bn").json()
    assert en["brand.tagline"] != bn["brand.tagline"]
    assert client.get("/api/i18n/xx").status_code == 404


def test_spa_index_served(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"FeeFix" in r.content
