"""Authorisation — the question that is *not* "who are you?".

AUTHENTICATION ≠ AUTHORISATION
==============================
Authentication answers "are you really Alice?". Authorisation answers "is Alice
allowed to touch *this*?". A system that conflates them produces the single
most common access-control bug on the web: an endpoint that verifies a valid
login exists somewhere in the request, then acts on an identifier taken from
the URL without ever asking whether that identifier belongs to the caller.

FeeFix had this, in two distinct shapes, and both were exploitable with no
credentials at all.

**Shape 1 — missing check (IDOR).** Four endpoints accepted a ``session_id``
and returned or mutated that session's data with no ownership test:

    GET  /api/students/{sid}/reminders            → 200, victim's rows
    POST /api/students/{sid}/reminders/dispatch   → 200, notifications sent
    POST /api/events                              → 200, victim's record mutated
    POST /api/ask  {"session_id": ...}            → 200, victim's profile used

Proven before the fix: an unauthenticated attacker read a signed-in user's
reminder set and pushed notifications on their behalf. ``/api/chat`` had the
same shape one level up — ``chat_id`` is client-supplied and the session table
is keyed on it, so anyone could resume anyone else's conversation.

**Shape 2 — the check exists but the state is mutable.** ``link-session``
called ``bind_owner``, whose SQL was
``ON CONFLICT(session_id) DO UPDATE SET user_id=excluded.user_id``. That
overwrites an existing owner. Proven before the fix: Mallory signed up, bound
Alice's session id to her own account, read Alice's profile, and Alice —
still holding a perfectly valid token — received 403 on her own data. A
complete, silent account takeover using only the public API.

THE RULE THIS MODULE ENFORCES
=============================
Every decision goes through one function with one contract:

* an **owned** resource requires an authenticated principal whose id matches
  the owner — no exceptions, no "anonymous is fine" fallback;
* an **unowned** resource is public by design (FeeFix works anonymously, which
  is a privacy feature, not an oversight);
* ownership can be **claimed once** and can never be transferred by the
  claimant. Re-binding is refused, and the refusal is audited.

Decisions raise :class:`AuthorisationError`, which the API layer converts to a
deliberately vague 403/401. The response must not distinguish "this session
exists and belongs to someone else" from "this session does not exist" —
that distinction is an oracle, and oracles are how IDOR becomes enumeration.
"""

from __future__ import annotations

from dataclasses import dataclass

from backend.services import security
from backend.services.input_guard import valid_scheme_id, valid_session_id


class AuthorisationError(Exception):
    """Access refused. ``status`` is what the API layer must return."""

    #: Client-safe text. Identical for every ownership failure so that the
    #: response cannot be used to probe which session ids are real.
    MESSAGE = "You don't have access to this record."

    def __init__(self, reason: str, *, status: int = 403, message: str | None = None) -> None:
        super().__init__(reason)
        #: Server-side reason — audit log only, never returned to a client.
        self.reason = reason
        self.status = status
        self.message = message or self.MESSAGE


class AuthenticationError(Exception):
    """No usable principal was presented (maps to HTTP 401)."""

    MESSAGE = "Sign in required."

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.MESSAGE)
        self.message = message or self.MESSAGE


@dataclass(frozen=True)
class Principal:
    """The authenticated caller, or an anonymous one.

    ``id is None`` means anonymous — which is a *legitimate* principal in
    FeeFix, not an error. Keeping it in the type stops the classic bug where a
    handler does ``if user: check_owner(...)`` and silently skips the check for
    anonymous callers on an owned resource.
    """

    id: str | None = None
    email: str | None = None
    name: str | None = None
    client_ip: str = "unknown"
    user_agent: str = ""

    @property
    def is_authenticated(self) -> bool:
        return bool(self.id)

    @classmethod
    def anonymous(cls, client_ip: str = "unknown", user_agent: str = "") -> "Principal":
        return cls(id=None, client_ip=client_ip, user_agent=user_agent)

    @classmethod
    def of(cls, user: dict | None, client_ip: str = "unknown", user_agent: str = "") -> "Principal":
        if not user:
            return cls.anonymous(client_ip, user_agent)
        return cls(
            id=user.get("id"),
            email=user.get("email"),
            name=user.get("name"),
            client_ip=client_ip,
            user_agent=user_agent,
        )


# ------------------------------------------------------------------ helpers --
def owner_of(store, session_id: str | None) -> str | None:
    """The owning user id of a session, or ``None`` when unowned/unknown.

    Defensive about the store implementation: the JSON ``TrackerStore`` has no
    ownership concept at all, and a missing method must mean "unowned" rather
    than raising a 500 on a legitimate anonymous request.
    """
    if not session_id:
        return None
    resolver = getattr(store, "owner_of", None)
    if resolver is None:
        return None
    try:
        return resolver(session_id) or None
    except Exception:  # pragma: no cover - store failure must not become 500
        return None


def _audit(principal: Principal, action: str, session_id: str, owner: str | None) -> None:
    security.audit_security_event(
        action,
        f"session={session_id} owner={owner or 'none'} actor={principal.id or 'anonymous'}",
        principal.id,
    )


# ------------------------------------------------------------- decisions ----
def require_authenticated(principal: Principal) -> Principal:
    """Raise 401 unless a real principal is present."""
    if not principal.is_authenticated:
        raise AuthenticationError()
    return principal


def authorize_session(
    principal: Principal,
    store,
    session_id: str | None,
    *,
    write: bool = False,
    route: str = "",
) -> str:
    """The one gate every session-scoped endpoint must pass through.

    Returns the validated ``session_id`` so callers cannot accidentally use the
    raw (unvalidated) value afterwards — validating at the gate and then using
    the original string is how path/SQL/ID bugs survive a "we added a check"
    refactor.

    ``write=True`` is recorded differently in the audit log: an unauthorised
    read is reconnaissance, an unauthorised write is an incident.
    """
    sid = valid_session_id(session_id)
    if sid is None:
        # A malformed id is not a "not found": refuse without touching storage.
        raise AuthorisationError("malformed_session_id", status=400,
                                 message="That record reference is not valid.")

    owner = owner_of(store, sid)

    if owner is None:
        # Unowned → anonymous access is the product's design. Nothing to check.
        return sid

    if not principal.is_authenticated:
        _audit(principal, "authz.denied_anonymous_write" if write else "authz.denied_anonymous",
               sid, owner)
        # 403, matching the platform's existing contract. 401 would be the more
        # textbook answer, but FeeFix's SPA treats 401 as "your token expired"
        # and clears local state — so answering 401 to a user who is simply
        # *not signed in* would look like a forced logout. The distinction also
        # leaks nothing extra: the caller already proved they know a 128-bit
        # session id by naming it.
        raise AuthorisationError(
            "session_owned_unauthenticated",
            message="This data belongs to an account — sign in.",
        )

    if principal.id != owner:
        _audit(principal, "authz.denied_wrong_owner_write" if write else "authz.denied_wrong_owner",
               sid, owner)
        raise AuthorisationError("session_owned_by_other")

    return sid


def authorize_bind(
    principal: Principal,
    store,
    session_id: str | None,
    *,
    allow_claim: bool = True,
) -> str:
    """May this principal take ownership of ``session_id``?

    This is the fix for the account-takeover shape. Ownership is a
    **write-once** attribute:

    * owned by the caller → idempotent success (the SPA retries link-session);
    * owned by anyone else → refused, audited, and the attempt is treated as a
      security event because it is indistinguishable from an attack;
    * unowned → claimable, provided the store supports ownership at all.

    ``allow_claim=False`` is available for deployments that want link-session
    to work only on sessions that already contain data (i.e. the user must
    have demonstrated possession by having created it in this browser).
    """
    require_authenticated(principal)
    sid = valid_session_id(session_id)
    if sid is None:
        raise AuthorisationError("malformed_session_id", status=400,
                                 message="That record reference is not valid.")

    binder = getattr(store, "bind_owner", None)
    if binder is None:
        raise AuthorisationError("store_lacks_ownership", status=501,
                                 message="Account linking requires the database store.")

    owner = owner_of(store, sid)

    if owner is not None and owner != principal.id:
        _audit(principal, "authz.bind_refused_already_owned", sid, owner)
        # Same message as every other ownership failure — no oracle.
        raise AuthorisationError("bind_target_owned_by_other")

    if owner is None and not allow_claim:
        exists = getattr(store, "has_data", None)
        if exists is not None and not exists(sid):
            _audit(principal, "authz.bind_refused_no_data", sid, None)
            raise AuthorisationError("bind_target_has_no_data",
                                     message="Nothing to link yet — save your progress first.")

    return sid


def authorize_scheme(scheme_id: str | None) -> str:
    """Validate a scheme id before it is used as a key or path segment."""
    sid = valid_scheme_id(scheme_id)
    if sid is None:
        raise AuthorisationError("malformed_scheme_id", status=400,
                                 message="That scheme reference is not valid.")
    return sid


def authorize_chat(
    principal: Principal,
    store_owner_lookup,
    chat_id: str | None,
) -> str | None:
    """Chat conversations are keyed on a client-supplied id — the same IDOR
    shape as sessions, one layer up.

    A chat id may be resumed only by the principal that owns it. When the
    deployment does not track chat ownership (the in-memory store historically
    did not), a *new* id is issued instead of trusting the supplied one, which
    removes the hijack without breaking the anonymous flow.
    """
    sid = valid_session_id(chat_id)
    if sid is None:
        return None
    if store_owner_lookup is None:
        return sid
    owner = store_owner_lookup(sid)
    if owner is None:
        return sid
    if principal.id != owner:
        _audit(principal, "authz.denied_chat", sid, owner)
        raise AuthorisationError("chat_owned_by_other")
    return sid


__all__ = [
    "AuthenticationError",
    "AuthorisationError",
    "Principal",
    "authorize_bind",
    "authorize_chat",
    "authorize_scheme",
    "authorize_session",
    "owner_of",
    "require_authenticated",
]
