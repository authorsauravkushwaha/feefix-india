"""FeeFix India REST API — matches, schemes, tracker, reminders, reach, i18n.

AUTHORISATION CONTRACT
======================
Every route that names a ``session_id`` passes it through
:func:`backend.services.authz.authorize_session` **before** touching storage,
and uses the validated value it returns rather than the raw path parameter.
This is a rule, not a convention: the four endpoints that skipped it
(``/reminders``, ``/reminders/dispatch``, ``/events``, ``/ask``) were readable
and writable by anyone who knew or guessed a session id — a textbook IDOR.

Every route that takes a password passes through
:func:`backend.services.ratelimit.guard_kdf` before the KDF runs, so the
expensive operation has its own budget independent of the request budget.

No route returns an internal exception, a stack trace, a class name or a
configuration value. Handlers raise :class:`fastapi.HTTPException` with fixed,
client-safe text; unexpected errors are handled once in ``backend.main``.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from backend.api.schemas import (
    AskRequest,
    ChangePasswordRequest,
    ChatRequest,
    DispatchRequest,
    EventRequest,
    LinkSessionRequest,
    LoginRequest,
    OtpRequestBody,
    OtpVerifyBody,
    ProfileUpsertRequest,
    RegisterRequest,
    TrackRequest,
)
from backend.models.student import StudentProfile
from backend.services import authz
from backend.services import input_guard
from backend.services import ratelimit
from backend.services import security
from backend.services.authz import Principal
from backend.services.chat import handle_message
from backend.services.matching import (
    match_profile,
    scheme_to_public,
    strip_internal,
)
from backend.services.reminders import build_reminders
from backend.services.security import LIMITS

router = APIRouter(prefix="/api")

LANG_DIR = Path(__file__).resolve().parents[2] / "language" / "regional_support"
SUPPORTED_LANGS = frozenset({"en", "bn", "hi", "ta"})
DEFAULT_STATUS_ERROR = "Invalid status. Use one of saved|planning|applied|under_review|approved|rejected."

# Fixed, non-diagnostic client-facing text. Reusing one string across failure
# modes is deliberate: differing messages become an enumeration oracle.
MSG_SIGN_IN_REQUIRED = "Sign in required."
MSG_FORBIDDEN = authz.AuthorisationError.MESSAGE
MSG_NOT_FOUND = "Scheme not found"
MSG_RATE_LIMITED = "Too many attempts — please wait a moment and try again."


# -- helpers ------------------------------------------------------------------
def _dataset(request: Request):
    return request.app.state.dataset


def _tracker(request: Request):
    return request.app.state.tracker


def _client_ip(request: Request) -> str:
    """The accountability IP, resolved once by the shield and reused here."""
    cached = getattr(request.state, "client_ip", None)
    if cached:
        return cached
    peer = request.client.host if request.client else None
    return security.client_ip(peer, dict(request.headers))


def _user_agent(request: Request) -> str:
    # Bounded: a user agent is attacker-controlled and is only ever hashed.
    return (request.headers.get("user-agent") or "")[:LIMITS.MAX_FREE_TEXT_LEN]


# -- auth & session ownership --------------------------------------------------
def _bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        return None
    return input_guard.valid_bearer_token(header[7:].strip())


def _current_user(request: Request) -> dict | None:
    from backend.services import auth as auth_svc

    return auth_svc.resolve_token(_bearer_token(request), user_agent=_user_agent(request))


def _principal(request: Request) -> Principal:
    """The caller, authenticated or not — never ``None``.

    Returning an explicit anonymous principal instead of ``None`` is what stops
    the ``if user: check(...)`` bug where a handler skips authorisation for
    logged-out callers.

    Memoised on ``request.state``: resolving a token does a database read and a
    rolling-expiry write, and a single request may authorise more than once
    (gate, then ownership stamp). Doing that twice per request would double the
    write load on the session table for no benefit.
    """
    cached = getattr(request.state, "principal", None)
    if cached is not None:
        return cached
    principal = Principal.of(
        _current_user(request),
        client_ip=_client_ip(request),
        user_agent=_user_agent(request),
    )
    request.state.principal = principal
    return principal


def _require_user(request: Request) -> dict:
    user = _current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail=MSG_SIGN_IN_REQUIRED)
    return user


def _guard(request: Request, session_id: str, *, write: bool = False, route: str = "") -> str:
    """Authorise + validate a session id. Returns the safe value to use."""
    try:
        return authz.authorize_session(
            _principal(request), _tracker(request), session_id, write=write, route=route
        )
    except authz.AuthorisationError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message) from exc


def _deny(exc: authz.AuthorisationError) -> HTTPException:
    return HTTPException(status_code=exc.status, detail=exc.message)


def _charge_kdf(request: Request) -> None:
    """Budget one password-hashing operation before it happens."""
    try:
        ratelimit.guard_kdf(_client_ip(request))
    except ratelimit.RateLimited as exc:
        raise HTTPException(
            status_code=429, detail=MSG_RATE_LIMITED,
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc


def _guard_auth(request: Request, identifier: str, *, route: str = "auth") -> None:
    try:
        ratelimit.guard_auth(_client_ip(request), identifier, route=route)
    except ratelimit.RateLimited as exc:
        raise HTTPException(
            status_code=429, detail=MSG_RATE_LIMITED,
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc


# -- authentication -------------------------------------------------------------
@router.post("/auth/register")
def register(body: RegisterRequest, request: Request) -> dict:
    from backend.services import auth as auth_svc

    _guard_auth(request, body.email.strip().lower(), route="register")
    # The KDF budget is charged before hashing: registration is the cheapest
    # way for an attacker to buy 600,000 rounds of SHA-256 per request.
    _charge_kdf(request)
    try:
        user = auth_svc.register(body.email, body.password, body.name)
    except auth_svc.AuthError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    token, expires = auth_svc.create_session(user["id"], user_agent=_user_agent(request))
    security.audit_security_event("auth.register_ok", security.redact_email(user["email"]),
                                  user["id"])
    return {"token": token, "expires_at": expires.isoformat(timespec="seconds"), "user": user,
            "session_id": None}


@router.post("/auth/login")
def login(body: LoginRequest, request: Request) -> dict:
    from backend.services import auth as auth_svc

    _guard_auth(request, body.email.strip().lower(), route="login")
    _charge_kdf(request)
    try:
        user = auth_svc.login(body.email, body.password,
                              client_ip=_client_ip(request), user_agent=_user_agent(request))
    except auth_svc.AuthError as exc:
        # 401 with the same text for every failure reason.
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    token, expires = auth_svc.create_session(user["id"], user_agent=_user_agent(request))
    tracker = _tracker(request)
    session_for_user = getattr(tracker, "session_for_user", None)
    return {"token": token, "expires_at": expires.isoformat(timespec="seconds"), "user": user,
            "session_id": session_for_user(user["id"]) if session_for_user else None}


@router.put("/auth/password")
def change_password(body: ChangePasswordRequest, request: Request) -> dict:
    """Rotate the password and revoke every other session.

    Exists because "I think my password leaked" needs an action that actually
    works. Revoking all sessions on change is the part that matters.
    """
    from backend.services import auth as auth_svc

    user = _require_user(request)
    _charge_kdf(request)
    try:
        auth_svc.change_password(user["id"], body.current_password, body.new_password)
    except auth_svc.AuthError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    # The caller's own token was revoked too — that is the point. Tell them so
    # the SPA signs out instead of silently failing on the next request.
    return {"changed": True, "sessions_revoked": True}


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
    """Bind the anonymous wizard session to the signed-in account.

    This used to call ``bind_owner`` directly, whose SQL overwrote any existing
    owner. That made account takeover a two-request operation: register, then
    link a session id belonging to someone else — after which the victim's own
    valid token returned 403 on their own data. Ownership is now write-once and
    a re-bind attempt is refused *and* audited.
    """
    user = _require_user(request)
    tracker = _tracker(request)
    try:
        sid = authz.authorize_bind(
            Principal.of(user, client_ip=_client_ip(request), user_agent=_user_agent(request)),
            tracker, body.session_id,
        )
    except authz.AuthorisationError as exc:
        raise _deny(exc) from exc
    tracker.bind_owner(sid, user["id"])
    return {"linked": True, "session_id": sid, "user": user}


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

    token, expires = auth_svc.create_session(user["id"], user_agent=_user_agent(request))
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
    """Send a 6-digit code (5-min expiry, 40s resend cooldown, ≤5 codes/hour).

    The code itself is never in this response on a production deployment — see
    :func:`backend.services.otp.request_code` for why that mattered.
    """
    from backend.services import otp as otp_svc

    _guard_auth(request, f"otp-req:{body.address.strip().lower()[:64]}", route="otp-request")
    try:
        return otp_svc.request_code(body.channel, body.address, _client_ip(request))
    except otp_svc.auth_svc.AuthError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/auth/otp/verify")
def otp_verify(body: OtpVerifyBody, request: Request) -> dict:
    """Burn the code → mint a session. Wrong code and unknown account both
    answer 401 identically (no user-enumeration)."""
    from backend.services import otp as otp_svc

    _guard_auth(request, f"otp-verify:{body.address.strip().lower()[:64]}", route="otp-verify")
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
    """OAuth callback. ``state`` is a one-time server-side row (CSRF defence).

    The token is handed to the browser through a non-executable JSON data block,
    never through a URL fragment. A token in a URL lands in the referer header,
    in proxy logs and in browser history; a data block does not. The block is
    escaped for ``<``, ``>`` and ``&`` so a hostile GitHub display name cannot
    break out of it into script context.
    """
    from backend.services import otp as otp_svc

    if not code or not state:
        return RedirectResponse("/#auth=failed", status_code=302)
    # Bound the query values before they reach any HTTP call or SQL parameter.
    if input_guard.reject_if_overlong(code, 256) or input_guard.reject_if_overlong(state, 256):
        security.audit_security_event("oauth.oversized_callback_param", None)
        return RedirectResponse("/#auth=failed", status_code=302)
    try:
        user = otp_svc.github_finish(code, state)
    except otp_svc.auth_svc.AuthError:
        return RedirectResponse("/#auth=failed", status_code=302)
    except Exception:
        # Anything unexpected (network, JSON shape) is logged server-side and
        # presented as the same generic failure. Never a stack trace.
        security.audit_security_event("oauth.callback_error", None)
        return RedirectResponse("/#auth=failed", status_code=302)
    from backend.services import auth as auth_svc

    tracker = _tracker(request)
    token, _expires = auth_svc.create_session(user["id"], user_agent=_user_agent(request))
    session_for_user = getattr(tracker, "session_for_user", None)
    sid = session_for_user(user["id"]) if session_for_user else None
    payload_js = json.dumps({"token": token, "user": user, "session_id": sid})
    payload_js = (payload_js.replace("<", "\\u003c")
                            .replace(">", "\\u003e")
                            .replace("&", "\\u0026")
                            .replace("\u2028", "\\u2028")
                            .replace("\u2029", "\\u2029"))
    response = HTMLResponse(_HANDOFF_HTML.replace("__PAYLOAD__", payload_js))
    # A token-bearing page must never be cached by a browser, a proxy or a
    # back/forward store. /api/* already sets no-store; this asserts it here so
    # the guarantee survives a route move.
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    return response


# Handoff page: CSP (script-src 'self') never allows inline JS, so the token
# lives in a non-executable JSON data block and /gh-handoff.js (same-origin,
# static) moves it to sessionStorage. The token never touches a URL or a log.
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
    """Liveness plus aggregate security posture.

    Counts only — no IPs, no nonces, no keys, no versions. An unauthenticated
    health endpoint is a fingerprinting gift if it reports anything else.
    """
    from backend.services import anti_replay

    qa = getattr(request.app.state, "qa", None)
    return {
        "status": "ok",
        "service": "feefix-india",
        "schemes_loaded": len(_dataset(request).schemes),
        "ai_backend": qa.backend if qa else "offline",
        "security": {
            "environment": security.environment(),
            "anti_replay": anti_replay.stats(),
            "rate_limit": ratelimit.snapshot(),
        },
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
        "limits": {
            "max_password_len": LIMITS.MAX_PASSWORD_LEN,
            "min_password_len": LIMITS.MIN_PASSWORD_LEN,
            "max_chat_message_len": LIMITS.MAX_CHAT_MESSAGE_LEN,
            "max_body_bytes": LIMITS.MAX_BODY_BYTES,
        },
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
    """Search the catalogue.

    ``q`` is length-capped before it reaches any substring scan; ``level`` and
    ``status`` are whitelisted against known members rather than passed through,
    so an unexpected value can never be interpreted as a filter operator.
    """
    query = None
    if q is not None:
        query = input_guard.bounded(q, LIMITS.MAX_SEARCH_QUERY_LEN) or None
    level = input_guard.valid_enum(level, {"state", "central"})
    status = input_guard.valid_enum(status, {"verified", "pending_review", "stale"})

    schemes = _dataset(request).search(
        query=query, level=level, status=status, fee_waiver_only=fee_waiver
    )
    return {
        "count": len(schemes),
        "schemes": [scheme_to_public(s) for s in schemes],
    }


@router.get("/schemes/{scheme_id}")
def scheme_detail(scheme_id: str, request: Request) -> dict:
    try:
        sid = authz.authorize_scheme(scheme_id)
    except authz.AuthorisationError:
        # A malformed id is indistinguishable from a missing one to the client.
        raise HTTPException(status_code=404, detail=MSG_NOT_FOUND)
    scheme = _dataset(request).get(sid)
    if not scheme:
        raise HTTPException(status_code=404, detail=MSG_NOT_FOUND)
    return scheme_to_public(scheme)


# -- matching ----------------------------------------------------------------------
@router.post("/match")
def match_route(body: ProfileUpsertRequest, request: Request) -> dict:
    lang = input_guard.valid_lang(body.lang, SUPPORTED_LANGS) or "en"
    result = match_profile(body.profile, _dataset(request), lang=lang)
    return strip_internal(result)


@router.get("/match/{session_id}")
def match_for_session(session_id: str, request: Request, lang: str = "en") -> dict:
    sid = _guard(request, session_id, route="match")
    safe_lang = input_guard.valid_lang(lang, SUPPORTED_LANGS) or "en"
    profile_dict = _tracker(request).load_profile(sid)
    result = match_profile(
        StudentProfile(**(profile_dict or {})), _dataset(request), lang=safe_lang
    )
    return strip_internal(result)


# -- profile persistence ------------------------------------------------------------
@router.put("/students/{session_id}/profile")
def save_profile(session_id: str, body: ProfileUpsertRequest, request: Request) -> dict:
    sid = _guard(request, session_id, write=True, route="save_profile")
    lang = input_guard.valid_lang(body.lang, SUPPORTED_LANGS) or "en"
    # Ownership is stamped at write time. Without this, a signed-in student's
    # profile was stored as anonymous and any other account could claim it via
    # link-session — see SQLiteStore.save_profile for the full write-up.
    principal = _principal(request)
    _tracker(request).save_profile(sid, body.profile.model_dump(mode="json"),
                                   owner_id=principal.id)
    result = match_profile(body.profile, _dataset(request), lang=lang)
    return {"saved": True, "session_id": sid, **strip_internal(result)}


@router.get("/students/{session_id}/profile")
def get_profile(session_id: str, request: Request) -> dict:
    sid = _guard(request, session_id, route="get_profile")
    profile = _tracker(request).load_profile(sid)
    return {"session_id": sid, "profile": profile}


# -- tracker --------------------------------------------------------------------------
@router.put("/tracker/{session_id}/{scheme_id}")
def set_track_status(
    session_id: str, scheme_id: str, body: TrackRequest, request: Request
) -> dict:
    sid = _guard(request, session_id, write=True, route="track")
    try:
        scheme = authz.authorize_scheme(scheme_id)
    except authz.AuthorisationError:
        raise HTTPException(status_code=404, detail=MSG_NOT_FOUND)
    if not _dataset(request).get(scheme):
        raise HTTPException(status_code=404, detail=MSG_NOT_FOUND)
    tracker = _tracker(request)
    # A signed-in student who tracks a scheme before ever saving a profile has
    # tracker rows but no profile row; claim ownership so the session is not
    # left looking anonymous (and therefore claimable by anyone else).
    claim = getattr(tracker, "claim_owner", None)
    if claim is not None:
        claim(sid, _principal(request).id)
    try:
        board = tracker.set_status(sid, scheme, body.status)
    except ValueError as exc:
        # The message comes from our own whitelist, so it is safe to surface —
        # it tells the client which statuses exist and nothing else.
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    from backend.services.tracker import TrackerStore

    return {
        "session_id": sid,
        "board": TrackerStore.scheme_entries(board),
    }


@router.get("/tracker/{session_id}")
def get_board(session_id: str, request: Request) -> dict:
    sid = _guard(request, session_id, route="board")
    from backend.services.tracker import TrackerStore

    board = TrackerStore.scheme_entries(_tracker(request).board(sid))
    schemes = []
    for scheme_id, entry in board.items():
        scheme = _dataset(request).get(scheme_id)
        if scheme:
            payload = scheme_to_public(scheme)
            payload["track"] = entry
            schemes.append(payload)
    return {"session_id": sid, "count": len(schemes), "items": schemes}


# -- reminders --------------------------------------------------------------------------
@router.get("/students/{session_id}/reminders")
def reminders(session_id: str, request: Request) -> dict:
    # Was unguarded: any caller who named a session id received that student's
    # deadline set, derived from their income, category and domicile.
    sid = _guard(request, session_id, route="reminders")
    tracker = _tracker(request)
    profile_dict = tracker.load_profile(sid)
    result = match_profile(StudentProfile(**(profile_dict or {})), _dataset(request))
    from backend.services.tracker import TrackerStore

    board = TrackerStore.scheme_entries(tracker.board(sid))
    items = build_reminders(result["ranked_matches"], board)
    return {
        "session_id": sid,
        "count": len(items),
        "high": sum(1 for r in items if r["severity"] == "high"),
        "reminders": items,
    }


@router.post("/students/{session_id}/reminders/dispatch")
def dispatch_reminders(
    session_id: str, body: DispatchRequest, request: Request
) -> dict:
    """Push due reminders to the notification outbox (reach-layer demo).

    Guarded as a *write*: this sends messages on a student's behalf, so an
    unauthorised call is not just a read — it is an action attributed to
    someone who did not take it.
    """
    sid = _guard(request, session_id, write=True, route="reminders_dispatch")
    tracker = _tracker(request)
    profile_dict = tracker.load_profile(sid)
    result = match_profile(StudentProfile(**(profile_dict or {})), _dataset(request))
    from backend.services.tracker import TrackerStore

    board = TrackerStore.scheme_entries(tracker.board(sid))
    items = build_reminders(result["ranked_matches"], board)[: body.limit]
    receipts = request.app.state.notifier.dispatch_reminders(sid, items)
    return {
        "session_id": sid,
        "dispatched": len(items),
        "receipts": receipts,
    }


# -- AI: semantic search & grounded Q&A ------------------------------------------------------
@router.get("/search/semantic")
def semantic_search(request: Request, q: str, k: int = 5) -> dict:
    qa = getattr(request.app.state, "qa", None)
    if qa is None:
        raise HTTPException(status_code=503, detail="AI layer not initialised")
    # Clamped, not trusted: k feeds an embedding sweep over the whole catalogue.
    k = input_guard.valid_int(k, minimum=1, maximum=15, default=5)
    query = input_guard.bounded(q, LIMITS.MAX_SEARCH_QUERY_LEN)
    if not query:
        raise HTTPException(status_code=422, detail="Search text must not be empty.")
    hits = qa.search.search(query, k=k)
    return {
        "query": query,
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
        # Guarded: an unguarded session_id here let a caller feed someone
        # else's saved profile into the answer engine and read the result back.
        sid = _guard(request, body.session_id, route="ask")
        saved = _tracker(request).load_profile(sid)
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
    """Record an application-outcome signal — V2's future training data.

    Guarded as a write. Unguarded, this let anyone poison another student's
    outcome history — and because those events are the *training data* for the
    ranking model, poisoning them is a way to attack the product's decisions
    rather than one user's record.
    """
    from backend.matching_engine.engine import EligibilityEngine
    from backend.matching_engine.ranker import RankingEngine
    from backend.services import events as events_svc

    sid = _guard(request, body.session_id, write=True, route="events")
    try:
        scheme_id = authz.authorize_scheme(body.scheme_id)
    except authz.AuthorisationError:
        raise HTTPException(status_code=404, detail=MSG_NOT_FOUND)

    dataset = _dataset(request)
    scheme = dataset.get(scheme_id)
    if not scheme:
        raise HTTPException(status_code=404, detail=MSG_NOT_FOUND)

    # Snapshot V1 signal context so V2 trains on exactly what V1 showed.
    context: dict = {}
    profile_dict = _tracker(request).load_profile(sid)
    if profile_dict:
        profile = StudentProfile(**profile_dict)
        engine = EligibilityEngine(dataset.schemes)
        matches = engine.match(profile).matches
        ranked = [r for r in RankingEngine().rank(matches) if r.scheme.id == scheme_id]
        if ranked:
            r = ranked[0]
            amounts = [x.scheme.benefit.amount_annual_inr for x in matches] or [1]
            context = {
                "clarity": r.evaluation.clarity,
                "urgency": round(RankingEngine()._urgency(r.days_left) / 25, 4),
                "benefit_norm": round(r.scheme.benefit.amount_annual_inr / max(amounts), 4),
                "verified": 1.0 if r.scheme.verification_status == "verified" else 0.0,
            }
    try:
        event = events_svc.record(sid, scheme_id, body.type, context)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"recorded": True, "event": event}


@router.get("/ml/rank/{session_id}")
def ml_rank_preview(session_id: str, request: Request) -> dict:
    """V1 vs V2: the outcome-model reranks this session's matches (Phase 3 preview)."""
    sid = _guard(request, session_id, route="ml_rank")
    from backend.services import events as events_svc
    from ml.ranking.service import compare

    profile_dict = _tracker(request).load_profile(sid)
    profile = StudentProfile(**(profile_dict or {}))
    return compare(profile, _dataset(request), events_svc.load())


# -- reach layer: conversational matcher --------------------------------------------------
@router.post("/chat")
def chat(body: ChatRequest, request: Request) -> dict:
    """Conversational matcher.

    ``chat_id`` is client-supplied and keys an in-memory conversation store, so
    it carries the same IDOR shape as ``session_id`` one level up: without a
    guard, anyone could resume anyone else's conversation by naming its id.
    The store now binds a conversation to the principal that started it and
    issues a fresh id to anyone else.
    """
    from backend.services import chat as chat_svc

    message = input_guard.bounded(body.message, LIMITS.MAX_CHAT_MESSAGE_LEN)
    if not message.strip():
        raise HTTPException(status_code=422, detail="Message must not be empty")

    principal = _principal(request)
    requested = input_guard.valid_session_id(body.chat_id)
    chat_id = chat_svc.resolve_chat_id(requested, owner_id=principal.id,
                                       owner_fp=chat_svc.owner_fingerprint(principal))

    qa = getattr(request.app.state, "qa", None)
    return handle_message(message, _dataset(request), chat_id, qa=qa,
                          owner_id=principal.id,
                          owner_fp=chat_svc.owner_fingerprint(principal))


# -- language layer ---------------------------------------------------------------------------
@router.get("/i18n/{lang}")
def i18n(lang: str) -> dict:
    """Serve a translation dictionary.

    ``lang`` is checked against an allow-list *before* it is used to build a
    path. That ordering is the entire defence: ``../../../etc/passwd`` is not a
    member of the allow-list, so it never reaches the filesystem. Building the
    path first and checking afterwards is the pattern that causes traversal.
    """
    safe = input_guard.valid_lang(lang, SUPPORTED_LANGS)
    if safe is None:
        raise HTTPException(status_code=404, detail="Unsupported language")
    path = (LANG_DIR / f"{safe}.json").resolve()
    # Belt and braces: even with an allow-list, assert containment.
    try:
        path.relative_to(LANG_DIR.resolve())
    except ValueError:
        raise HTTPException(status_code=404, detail="Unsupported language")
    if not path.exists():
        raise HTTPException(status_code=404, detail="Dictionary missing")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        # A corrupt dictionary is an operator problem, not a client detail.
        security.audit_security_event("i18n.dictionary_unreadable", safe)
        raise HTTPException(status_code=500, detail="Dictionary unavailable")
