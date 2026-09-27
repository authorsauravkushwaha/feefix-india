"""FeeFix India REST API — matches, schemes, tracker, reminders, reach, i18n."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

from backend.api.schemas import (
    AskRequest,
    ChatRequest,
    DispatchRequest,
    ProfileUpsertRequest,
    TrackRequest,
)
from backend.models.student import StudentProfile
from backend.services.chat import handle_message
from backend.services.matching import (
    match_profile,
    scheme_to_public,
    strip_internal,
)
from backend.services.reminders import build_reminders

router = APIRouter(prefix="/api")

LANG_DIR = Path(__file__).resolve().parents[2] / "language" / "regional_support"
SUPPORTED_LANGS = {"en", "bn", "hi"}
DEFAULT_STATUS_ERROR = "Invalid status. Use one of saved|planning|applied|under_review|approved|rejected."


# -- helpers ------------------------------------------------------------------
def _dataset(request: Request):
    return request.app.state.dataset


def _tracker(request: Request):
    return request.app.state.tracker


# -- meta -----------------------------------------------------------------------
@router.get("/health")
def health(request: Request) -> dict:
    qa = getattr(request.app.state, "qa", None)
    return {
        "status": "ok",
        "service": "feefix-india",
        "schemes_loaded": len(_dataset(request).schemes),
        "ai_backend": qa.backend if qa else "offline",
    }


@router.get("/meta")
def meta() -> dict:
    from backend.models.student import (
        Category,
        CourseLevel,
        Gender,
        INDIAN_STATES,
        MINORITY_COMMUNITIES,
    )
    from backend.services.tracker import STATUSES

    return {
        "states": INDIAN_STATES,
        "categories": [c.value for c in Category],
        "course_levels": [c.value for c in CourseLevel],
        "genders": [g.value for g in Gender],
        "minority_communities": MINORITY_COMMUNITIES,
        "track_statuses": STATUSES,
    }


@router.get("/stats")
def stats(request: Request) -> dict:
    return _dataset(request).summary()


# -- schemes ----------------------------------------------------------------------
@router.get("/schemes")
def list_schemes(
    request: Request,
    q: str | None = None,
    level: str | None = None,
    status: str | None = None,
    fee_waiver: bool = False,
) -> dict:
    schemes = _dataset(request).search(
        query=q, level=level, status=status, fee_waiver_only=fee_waiver
    )
    return {
        "count": len(schemes),
        "schemes": [scheme_to_public(s) for s in schemes],
    }


@router.get("/schemes/{scheme_id}")
def scheme_detail(scheme_id: str, request: Request) -> dict:
    scheme = _dataset(request).get(scheme_id)
    if not scheme:
        raise HTTPException(status_code=404, detail="Scheme not found")
    return scheme_to_public(scheme)


# -- matching ----------------------------------------------------------------------
@router.post("/match")
def match_route(body: ProfileUpsertRequest, request: Request) -> dict:
    result = match_profile(body.profile, _dataset(request))
    return strip_internal(result)


@router.get("/match/{session_id}")
def match_for_session(session_id: str, request: Request) -> dict:
    profile_dict = _tracker(request).load_profile(session_id)
    result = match_profile(
        StudentProfile(**(profile_dict or {})), _dataset(request)
    )
    return strip_internal(result)


# -- profile persistence ------------------------------------------------------------
@router.put("/students/{session_id}/profile")
def save_profile(session_id: str, body: ProfileUpsertRequest, request: Request) -> dict:
    _tracker(request).save_profile(session_id, body.profile.model_dump(mode="json"))
    result = match_profile(body.profile, _dataset(request))
    return {"saved": True, "session_id": session_id, **strip_internal(result)}


@router.get("/students/{session_id}/profile")
def get_profile(session_id: str, request: Request) -> dict:
    profile = _tracker(request).load_profile(session_id)
    return {"session_id": session_id, "profile": profile}


# -- tracker --------------------------------------------------------------------------
@router.put("/tracker/{session_id}/{scheme_id}")
def set_track_status(
    session_id: str, scheme_id: str, body: TrackRequest, request: Request
) -> dict:
    scheme = _dataset(request).get(scheme_id)
    if not scheme:
        raise HTTPException(status_code=404, detail="Scheme not found")
    try:
        board = _tracker(request).set_status(session_id, scheme_id, body.status)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    from backend.services.tracker import TrackerStore

    return {
        "session_id": session_id,
        "board": TrackerStore.scheme_entries(board),
    }


@router.get("/tracker/{session_id}")
def get_board(session_id: str, request: Request) -> dict:
    from backend.services.tracker import TrackerStore

    board = TrackerStore.scheme_entries(_tracker(request).board(session_id))
    schemes = []
    for scheme_id, entry in board.items():
        scheme = _dataset(request).get(scheme_id)
        if scheme:
            payload = scheme_to_public(scheme)
            payload["track"] = entry
            schemes.append(payload)
    return {"session_id": session_id, "count": len(schemes), "items": schemes}


# -- reminders --------------------------------------------------------------------------
@router.get("/students/{session_id}/reminders")
def reminders(session_id: str, request: Request) -> dict:
    tracker = _tracker(request)
    profile_dict = tracker.load_profile(session_id)
    result = match_profile(StudentProfile(**(profile_dict or {})), _dataset(request))
    from backend.services.tracker import TrackerStore

    board = TrackerStore.scheme_entries(tracker.board(session_id))
    items = build_reminders(result["ranked_matches"], board)
    return {
        "session_id": session_id,
        "count": len(items),
        "high": sum(1 for r in items if r["severity"] == "high"),
        "reminders": items,
    }


@router.post("/students/{session_id}/reminders/dispatch")
def dispatch_reminders(
    session_id: str, body: DispatchRequest, request: Request
) -> dict:
    """Push due reminders to the notification outbox (reach-layer demo)."""
    tracker = _tracker(request)
    profile_dict = tracker.load_profile(session_id)
    result = match_profile(StudentProfile(**(profile_dict or {})), _dataset(request))
    from backend.services.tracker import TrackerStore

    board = TrackerStore.scheme_entries(tracker.board(session_id))
    items = build_reminders(result["ranked_matches"], board)[: body.limit]
    receipts = request.app.state.notifier.dispatch_reminders(session_id, items)
    return {
        "session_id": session_id,
        "dispatched": len(items),
        "receipts": receipts,
    }


# -- AI: semantic search & grounded Q&A ------------------------------------------------------
@router.get("/search/semantic")
def semantic_search(request: Request, q: str, k: int = 5) -> dict:
    qa = getattr(request.app.state, "qa", None)
    if qa is None:
        raise HTTPException(status_code=503, detail="AI layer not initialised")
    k = max(1, min(k, 15))
    hits = qa.search.search(q, k=k)
    return {
        "query": q,
        "backend": qa.backend,
        "count": len(hits),
        "hits": [
            {**scheme_to_public(h.scheme), "semantic_score": round(h.score, 4)}
            for h in hits
        ],
    }


@router.post("/ask")
def ask(body: AskRequest, request: Request) -> dict:
    qa = getattr(request.app.state, "qa", None)
    if qa is None:
        raise HTTPException(status_code=503, detail="AI layer not initialised")
    session_profile = None
    if body.session_id:
        saved = _tracker(request).load_profile(body.session_id)
        if saved:
            session_profile = StudentProfile(**saved)
    result = qa.answer(body.question, session_profile=session_profile)
    return {
        "question": result.question,
        "answer": result.answer,
        "mode": result.mode,
        "backend": result.backend,
        "citations": result.citations,
        "detected_profile": result.detected_profile,
    }


# -- reach layer: conversational matcher --------------------------------------------------
@router.post("/chat")
def chat(body: ChatRequest, request: Request) -> dict:
    if not body.message.strip():
        raise HTTPException(status_code=422, detail="Message must not be empty")
    qa = getattr(request.app.state, "qa", None)
    return handle_message(body.message, _dataset(request), body.chat_id, qa=qa)


# -- language layer ---------------------------------------------------------------------------
@router.get("/i18n/{lang}")
def i18n(lang: str) -> dict:
    if lang not in SUPPORTED_LANGS:
        raise HTTPException(status_code=404, detail="Unsupported language")
    path = LANG_DIR / f"{lang}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Dictionary missing")
    return json.loads(path.read_text(encoding="utf-8"))
