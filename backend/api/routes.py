"""FeeFix India REST API — matches, schemes, tracker, reminders, reach, i18n."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse

from backend.api.schemas import (
    AskRequest,
    BulkTrackRequest,
    ChatRequest,
    DispatchRequest,
    EventRequest,
    LinkSessionRequest,
    LoginRequest,
    NotesRequest,
    OtpRequestBody,
    OtpVerifyBody,
    ProfileUpsertRequest,
    RegisterRequest,
    TrackRequest,
)
from backend.models.student import StudentProfile
from backend.services.chat import handle_message
from backend.services.limits import MAX_SEARCH_LEN, MAX_UPLOAD_BYTES
from backend.services.matching import (
    match_profile,
    scheme_to_public,
    strip_internal,
)
from backend.services.reminders import build_reminders

router = APIRouter(prefix="/api")

LANG_DIR = Path(__file__).resolve().parents[2] / "language" / "regional_support"
SUPPORTED_LANGS = {"en", "bn", "hi", "ta"}
DEFAULT_STATUS_ERROR = "Invalid status. Use one of saved|planning|applied|under_review|approved|rejected."


# -- helpers ------------------------------------------------------------------
def _dataset(request: Request):
    return request.app.state.dataset


def _tracker(request: Request):
    return request.app.state.tracker


# -- auth & session ownership --------------------------------------------------
def _bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    return header[7:].strip() if header.lower().startswith("bearer ") else None


def _current_user(request: Request) -> dict | None:
    # Populated by the session middleware (one resolve + one rotation per
    # request). Fall back to a direct resolve for call sites outside it.
    cached = getattr(request.state, "user", None)
    if cached is not None:
        return cached
    from backend.services import auth as auth_svc

    return auth_svc.resolve_token(_bearer_token(request))


def _require_user(request: Request) -> dict:
    user = _current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Sign in required.")
    return user


def _authorize_session(request: Request, session_id: str) -> None:
    """Anonymous sessions stay open; account-owned ones require their owner."""
    tracker = _tracker(request)
    owner_of = getattr(tracker, "owner_of", None)
    owner = owner_of(session_id) if owner_of else None
    if owner:
        user = _current_user(request)
        if not user or user["id"] != owner:
            raise HTTPException(status_code=403, detail="This data belongs to an account — sign in.")


# -- authentication -------------------------------------------------------------
def _enforce_auth_limit(request: Request, identifier: str) -> None:
    """Auth rate limit with a Retry-After hint (blunts credential brute-force)."""
    from backend.services import ratelimit

    client = ratelimit.client_ip(request)
    if not ratelimit.check_auth(client, identifier):
        raise HTTPException(
            status_code=429,
            detail="Too many attempts — try again later.",
            headers={"Retry-After": str(ratelimit.retry_after(client, f"auth:{identifier}"))},
        )


@router.post("/auth/register")
def register(body: RegisterRequest, request: Request) -> dict:
    from backend.services import auth as auth_svc
    from backend.services import ratelimit

    _enforce_auth_limit(request, body.email.strip().lower())
    try:
        user = auth_svc.register(body.email, body.password, body.name)
    except auth_svc.AuthError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    token, expires = auth_svc.create_session(
        user["id"], auth_svc.client_fingerprint(request)
    )
    return {"token": token, "expires_at": expires.isoformat(timespec="seconds"), "user": user,
            "session_id": None}


@router.post("/auth/login")
def login(body: LoginRequest, request: Request) -> dict:
    from backend.services import auth as auth_svc
    from backend.services import ratelimit

    _enforce_auth_limit(request, body.email.strip().lower())
    try:
        user = auth_svc.login(body.email, body.password)
    except auth_svc.AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    token, expires = auth_svc.create_session(
        user["id"], auth_svc.client_fingerprint(request)
    )
    tracker = _tracker(request)
    session_for_user = getattr(tracker, "session_for_user", None)
    return {"token": token, "expires_at": expires.isoformat(timespec="seconds"), "user": user,
            "session_id": session_for_user(user["id"]) if session_for_user else None}


@router.post("/auth/logout")
def logout(request: Request) -> dict:
    from backend.services import auth as auth_svc

    token = _bearer_token(request)
    revoked = auth_svc.revoke_token(token) if token else False
    return {"revoked": revoked}


@router.get("/auth/me")
def me(request: Request) -> dict:
    return {"user": _require_user(request)}


@router.post("/auth/link-session")
def link_session(body: LinkSessionRequest, request: Request) -> dict:
    """Bind the anonymous wizard session to the signed-in account — after this,
    the user's data follows their login on any device."""
    user = _require_user(request)
    tracker = _tracker(request)
    bind_owner = getattr(tracker, "bind_owner", None)
    if not bind_owner:
        raise HTTPException(status_code=501, detail="Account linking requires the database store.")
    bind_owner(body.session_id, user["id"])
    return {"linked": True, "session_id": body.session_id, "user": user}


@router.get("/auth/export")
def export_data(request: Request) -> dict:
    """Data portability: everything the account holds, downloadable in one JSON."""
    user = _require_user(request)
    tracker = _tracker(request)
    exporter = getattr(tracker, "export_user_data", None)
    if not exporter:
        return {"user": user, "sessions": {}, "outcome_events": []}
    return {"user": user, **exporter(user["id"])}


@router.delete("/auth/account")
def delete_account(request: Request) -> dict:
    """Right to erasure: account, tokens and all owned data — gone."""
    from backend.services import auth as auth_svc

    user = _require_user(request)
    auth_svc.delete_account(user["id"])
    return {"deleted": True}


# -- OTP sign-in (email & international phone) ---------------------------------
def _auth_payload(user: dict, request: Request) -> dict:
    """Uniform {token, expires_at, user, session_id} for every sign-in door."""
    from backend.services import auth as auth_svc

    token, expires = auth_svc.create_session(
        user["id"], auth_svc.client_fingerprint(request)
    )
    tracker = _tracker(request)
    session_for_user = getattr(tracker, "session_for_user", None)
    return {
        "token": token,
        "expires_at": expires.isoformat(timespec="seconds"),
        "user": user,
        "session_id": session_for_user(user["id"]) if session_for_user else None,
    }


@router.post("/auth/otp/request")
def otp_request(body: OtpRequestBody, request: Request) -> dict:
    """Send a 6-digit code (5-min expiry, 40s resend cooldown, ≤5 codes/hour)."""
    from backend.services import otp as otp_svc
    from backend.services import ratelimit

    from backend.services import ratelimit as _rl
    client = _rl.client_ip(request)
    _enforce_auth_limit(request, "otp-req")
    try:
        return otp_svc.request_code(body.channel, body.address, client)
    except otp_svc.auth_svc.AuthError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/auth/otp/verify")
def otp_verify(body: OtpVerifyBody, request: Request) -> dict:
    """Burn the code → mint a session. Wrong code and unknown account both
    answer 401 identically (no user-enumeration)."""
    from backend.services import otp as otp_svc
    from backend.services import ratelimit

    from backend.services import ratelimit as _rl
    client = _rl.client_ip(request)
    _enforce_auth_limit(request, f"otp-verify:{body.address.strip().lower()}")
    try:
        user = otp_svc.verify_code(body.channel, body.address, body.code, body.name)
    except otp_svc.auth_svc.AuthError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired code — request a new one.")
    return _auth_payload(user, request)


# -- GitHub OAuth ---------------------------------------------------------------
@router.get("/auth/methods")
def auth_methods() -> dict:
    """Which sign-in doors are live on this deployment (UI dims unavailable)."""
    from backend.services import otp as otp_svc

    return otp_svc.methods()


@router.get("/auth/github")
def github_start(request: Request) -> RedirectResponse:
    from backend.services import otp as otp_svc

    try:
        url = otp_svc.github_start()
    except otp_svc.auth_svc.AuthError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc
    return RedirectResponse(url, status_code=302)


@router.get("/auth/github/callback")
def github_callback(request: Request, code: str | None = None, state: str | None = None):
    from backend.services import otp as otp_svc

    if not code or not state:
        return RedirectResponse("/#auth=failed", status_code=302)
    try:
        user = otp_svc.github_finish(code, state)
    except otp_svc.auth_svc.AuthError:
        return RedirectResponse("/#auth=failed", status_code=302)
    from backend.services import auth as auth_svc

    tracker = _tracker(request)
    token, _expires = auth_svc.create_session(
        user["id"], auth_svc.client_fingerprint(request)
    )
    session_for_user = getattr(tracker, "session_for_user", None)
    sid = session_for_user(user["id"]) if session_for_user else None
    # The token lands in a <script type="application/json"> data block that a
    # same-origin static file reads. A hostile GitHub profile name must never be
    # able to break out of that block, so neutralise every HTML-significant
    # character (</script>, attribute quotes, entity parsing) before splicing.
    payload_js = _json_html_safe({"token": token, "user": user, "session_id": sid})
    return HTMLResponse(_HANDOFF_HTML.replace("__PAYLOAD__", payload_js))


def _json_html_safe(obj) -> str:
    """JSON-encode, then make it safe to splice into an HTML <script> data block.

    Defence-in-depth against HTML/script injection via any string field (e.g. a
    crafted display name). ``<``/``>`` block ``</script>`` breakouts; ``&`` blocks
    HTML-entity reinterpretation; U+2028/U+2029 are escaped because they are
    line terminators in JS even though they are legal in JSON strings.
    """
    encoded = json.dumps(obj, ensure_ascii=False)
    return (
        encoded.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


# Handoff page: CSP (script-src 'self') never allows inline JS, so the token
# lives in a non-executable JSON data block and /gh-handoff.js (same-origin,
# static) moves it to localStorage. The token never touches a URL or a log.
_HANDOFF_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8" />
<title>Signed in — FeeFix</title></head>
<body style="font-family:system-ui;background:#0b0f19;color:#dbe6ff;display:grid;place-items:center;height:100vh;margin:0">
<div style="text-align:center">
  <div style="font-size:2rem">🔐</div>
  <p>Signed in — returning you to FeeFix…</p>
</div>
<script type="application/json" id="p">__PAYLOAD__</script>
<script src="/gh-handoff.js"></script>
</body></html>"""


# -- meta -----------------------------------------------------------------------
@router.get("/health")
def health(request: Request) -> dict:
    """Liveness plus the operational facts an operator actually needs to see.

    Notably: whether rate-limit counters are shared (``distributed``) or
    per-process — the failure mode that used to be invisible until an attacker
    exploited it.
    """
    from backend.services import ratelimit

    qa = getattr(request.app.state, "qa", None)
    boot = getattr(request.app.state, "boot", {}) or {}
    return {
        "status": "ok",
        "service": "feefix-india",
        "schemes_loaded": len(_dataset(request).schemes),
        "ai_backend": qa.backend if qa else "offline",
        "password_hashing": boot.get("password_hashing", {}).get("algorithm", "unknown"),
        "rate_limit": ratelimit.status(),
        "rate_limit_warning": boot.get("rate_limit_warning"),
        "docs_enabled": getattr(request.app.state, "docs_enabled", True),
    }


@router.get("/meta")
def meta() -> dict:
    """Public, non-secret description of the API's policy surface.

    Limit tables and security policy are documented *by the service itself*, so
    clients and auditors do not have to reverse-engineer them.
    """
    from backend.models.student import (
        Category,
        CourseLevel,
        Gender,
        INDIAN_STATES,
        MINORITY_COMMUNITIES,
    )
    from backend.services import passwords
    from backend.services import uploads as uploads_svc
    from backend.services.auth import policy_summary as session_policy
    from backend.services.limits import describe_limits
    from backend.services.tracker import STATUSES

    uploads_policy = uploads_svc.describe_policy
    password_policy = passwords.describe

    return {
        "states": INDIAN_STATES,
        "categories": [c.value for c in Category],
        "course_levels": [c.value for c in CourseLevel],
        "genders": [g.value for g in Gender],
        "minority_communities": MINORITY_COMMUNITIES,
        "track_statuses": STATUSES,
        "limits": describe_limits(),
        "uploads": uploads_policy(),
        "sessions": session_policy(),
        "password_hashing": password_policy(),
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
    result = match_profile(body.profile, _dataset(request), lang=body.lang)
    return strip_internal(result)


@router.get("/match/{session_id}")
def match_for_session(session_id: str, request: Request, lang: str = "en") -> dict:
    _authorize_session(request, session_id)
    profile_dict = _tracker(request).load_profile(session_id)
    result = match_profile(
        StudentProfile(**(profile_dict or {})), _dataset(request), lang=lang
    )
    return strip_internal(result)


# -- profile persistence ------------------------------------------------------------
@router.put("/students/{session_id}/profile")
def save_profile(session_id: str, body: ProfileUpsertRequest, request: Request) -> dict:
    _authorize_session(request, session_id)
    _tracker(request).save_profile(session_id, body.profile.model_dump(mode="json"))
    result = match_profile(body.profile, _dataset(request), lang=body.lang)
    return {"saved": True, "session_id": session_id, **strip_internal(result)}


@router.get("/students/{session_id}/profile")
def get_profile(session_id: str, request: Request) -> dict:
    _authorize_session(request, session_id)
    profile = _tracker(request).load_profile(session_id)
    return {"session_id": session_id, "profile": profile}


# -- tracker --------------------------------------------------------------------------
@router.put("/tracker/{session_id}/{scheme_id}")
def set_track_status(
    session_id: str, scheme_id: str, body: TrackRequest, request: Request
) -> dict:
    _authorize_session(request, session_id)
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


@router.post("/tracker/{session_id}/bulk")
def bulk_track_status(session_id: str, body: BulkTrackRequest, request: Request) -> dict:
    """Apply many tracker updates in one request.

    Validated entirely before any write, so a bad id does not leave a partial
    board. The body cap is the ``bulk`` policy (512 KB), not the 16 KB
    single-status cap and not the 1 MB catch-all.
    """
    _authorize_session(request, session_id)
    dataset = _dataset(request)
    unknown = [item.scheme_id for item in body.updates if dataset.get(item.scheme_id) is None]
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown scheme(s): {', '.join(unknown[:8])}")
    tracker = _tracker(request)
    try:
        for item in body.updates:
            tracker.set_status(session_id, item.scheme_id, item.status)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    from backend.services.tracker import TrackerStore

    board = TrackerStore.scheme_entries(tracker.board(session_id))
    return {"session_id": session_id, "applied": len(body.updates), "board": board}


@router.get("/tracker/{session_id}")
def get_board(session_id: str, request: Request) -> dict:
    _authorize_session(request, session_id)
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
    _authorize_session(request, session_id)
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
    _authorize_session(request, session_id)
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


# -- long-form notes (its own, larger body policy) -------------------------------------------
@router.put("/students/{session_id}/notes")
def save_notes(session_id: str, body: NotesRequest, request: Request) -> dict:
    """Store long application notes.

    Bounded by ``MAX_NOTES_LEN`` (20 KB by default) *and* by the endpoint's own
    body policy — a legitimately long note is accepted instead of being killed
    by a global one-size-fits-all cap.
    """
    _authorize_session(request, session_id)
    return {"saved": True, **_tracker(request).set_notes(session_id, body.notes)}


@router.get("/students/{session_id}/notes")
def read_notes(session_id: str, request: Request) -> dict:
    _authorize_session(request, session_id)
    return _tracker(request).get_notes(session_id)


# -- uploads (the hardened gate, finally wired in) --------------------------------------------
def _upload_rejection(exc: "uploads_svc.UploadRejected") -> HTTPException:
    return HTTPException(status_code=exc.status, detail=exc.reason)


@router.post("/uploads/{session_id}")
async def upload_document(
    session_id: str,
    request: Request,
    file: UploadFile = File(..., description="PDF/PNG/JPEG, max MAX_UPLOAD_BYTES"),
) -> dict:
    """Accept a document (income certificate, marksheet …) for a session.

    The bytes pass through ``services/uploads.py`` → ``services/upload.py``:
    extension allowlist, magic-byte sniffing, size cap, sanitised name, random
    storage name under a directory that is **not** web-served. Ownership is
    enforced before a single byte is written.
    """
    from backend.services import uploads as uploads_svc

    _authorize_session(request, session_id)
    user = _current_user(request)
    # Read one byte past the cap so an oversized file is detected, not buffered.
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    try:
        record = uploads_svc.store_upload(
            session_id,
            file.filename or "upload",
            content,
            content_type=file.content_type,
            user_id=user["id"] if user else None,
        )
    except uploads_svc.UploadRejected as exc:
        raise _upload_rejection(exc) from exc
    return {
        "stored": True,
        "upload": {
            **record,
            "url": f"/api/uploads/{session_id}/{record['id']}/content",
        },
    }


@router.get("/uploads/{session_id}")
def list_documents(session_id: str, request: Request) -> dict:
    from backend.services import uploads as uploads_svc

    _authorize_session(request, session_id)
    try:
        items = uploads_svc.list_uploads(session_id)
    except uploads_svc.UploadRejected as exc:
        raise _upload_rejection(exc) from exc
    return {
        "session_id": session_id,
        "count": len(items),
        "items": [
            {**item, "url": f"/api/uploads/{session_id}/{item['id']}/content"}
            for item in items
        ],
        "policy": uploads_svc.describe_policy(),
    }


@router.get("/uploads/{session_id}/{upload_id}/content")
def download_document(session_id: str, upload_id: str, request: Request) -> FileResponse:
    """Serve a stored document as a download — never as sniffable content."""
    from backend.services import uploads as uploads_svc

    _authorize_session(request, session_id)
    try:
        record, path = uploads_svc.load_upload(session_id, upload_id)
    except uploads_svc.UploadRejected as exc:
        raise _upload_rejection(exc) from exc
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=record["original_name"],
        headers={"X-Content-Type-Options": "nosniff"},
    )


@router.delete("/uploads/{session_id}/{upload_id}")
def delete_document(session_id: str, upload_id: str, request: Request) -> dict:
    from backend.services import uploads as uploads_svc

    _authorize_session(request, session_id)
    user = _current_user(request)
    try:
        uploads_svc.delete_upload(session_id, upload_id, user_id=user["id"] if user else None)
    except uploads_svc.UploadRejected as exc:
        raise _upload_rejection(exc) from exc
    return {"deleted": True, "upload_id": upload_id}


# -- AI: semantic search & grounded Q&A ------------------------------------------------------
@router.get("/search/semantic")
def semantic_search(request: Request, q: str = Query(max_length=MAX_SEARCH_LEN), k: int = 5) -> dict:
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
        _authorize_session(request, body.session_id)
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


# -- outcome events & V2 rank preview (Phase 3) -------------------------------------------
@router.post("/events")
def record_event(body: EventRequest, request: Request) -> dict:
    """Record an application-outcome signal — V2's future training data."""
    from backend.matching_engine.engine import EligibilityEngine
    from backend.matching_engine.ranker import RankingEngine
    from backend.services import events as events_svc

    _authorize_session(request, body.session_id)
    dataset = _dataset(request)
    scheme = dataset.get(body.scheme_id)
    if not scheme:
        raise HTTPException(status_code=404, detail="Scheme not found")

    # Snapshot V1 signal context so V2 trains on exactly what V1 showed.
    context: dict = {}
    profile_dict = _tracker(request).load_profile(body.session_id)
    if profile_dict:
        profile = StudentProfile(**profile_dict)
        engine = EligibilityEngine(dataset.schemes)
        ranked = [r for r in RankingEngine().rank(engine.match(profile).matches)
                  if r.scheme.id == body.scheme_id]
        if ranked:
            r = ranked[0]
            amounts = [x.scheme.benefit.amount_annual_inr
                       for x in engine.match(profile).matches] or [1]
            context = {
                "clarity": r.evaluation.clarity,
                "urgency": round(RankingEngine()._urgency(r.days_left) / 25, 4),
                "benefit_norm": round(r.scheme.benefit.amount_annual_inr / max(amounts), 4),
                "verified": 1.0 if r.scheme.verification_status == "verified" else 0.0,
            }
    try:
        event = events_svc.record(body.session_id, body.scheme_id, body.type, context)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"recorded": True, "event": event}


@router.get("/ml/rank/{session_id}")
def ml_rank_preview(session_id: str, request: Request) -> dict:
    """V1 vs V2: the outcome-model reranks this session's matches (Phase 3 preview)."""
    _authorize_session(request, session_id)
    from backend.services import events as events_svc
    from ml.ranking.service import compare

    profile_dict = _tracker(request).load_profile(session_id)
    profile = StudentProfile(**(profile_dict or {}))
    return compare(profile, _dataset(request), events_svc.load())


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
