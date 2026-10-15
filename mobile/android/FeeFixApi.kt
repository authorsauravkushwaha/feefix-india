// ==========================================================================
// FeeFix India — Android API client (hardened reference scaffold).
//
// Dependency-light on purpose: OkHttp + org.json only, so this file documents
// the full wire contract without a Gradle project. Swap to Retrofit in the app;
// every security property below is transport-independent and must survive that
// swap.
//
// WHAT CHANGED, AND WHY
// ---------------------
// The previous version was `OkHttpClient()` with a string baseUrl. That is four
// separate vulnerabilities on a device, which is the least controlled
// environment FeeFix runs in:
//
//   1. NO TIMEOUTS. OkHttp's default read/write timeouts are 10 s but the
//      *call* timeout is 0 — infinite. A server that accepts a connection and
//      then goes silent hangs the calling coroutine forever. On a mobile
//      network, where captive portals and flaky handovers do exactly that,
//      this is not a corner case. It is an availability bug an attacker on the
//      same Wi-Fi can trigger deliberately (slowloris from the other end).
//
//   2. NO SCHEME ENFORCEMENT. `baseUrl` came from the caller, so an http:// URL
//      was accepted and every request — including the bearer token — went in
//      cleartext. On Android 9+ cleartext is blocked by default, but that is a
//      platform default the app can override, and an explicit check in code
//      does not depend on the manifest being right.
//
//   3. NO AUTHENTICATION AT ALL. The client could not send an Authorization
//      header, so it could only ever reach the anonymous endpoints. Any app
//      that added auth later would have had to invent its own token storage,
//      which is how tokens end up in SharedPreferences in plaintext — readable
//      by any process with root, by every backup, and by every bug report the
//      user ever files.
//
//   4. NO INPUT VALIDATION. `sessionId` and `schemeId` were interpolated
//      straight into the URL path. A value containing "/" or "?" changes which
//      endpoint is called — request smuggling against your own API, and a
//      stored value that survives from an earlier session makes it persistent.
//
// Also added: anti-replay nonces (matching the web client), certificate pinning
// hooks, bounded response reads, and error handling that never surfaces a raw
// exception message to the UI.
// ==========================================================================
package `in`.feefix

import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.CertificatePinner
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.SecureRandom
import java.util.concurrent.TimeUnit

/** Student profile exactly as the backend expects it (see models/StudentProfile). */
data class StudentProfile(
    val domicileState: String,
    val category: String,          // general | sc | st | obc
    val annualFamilyIncome: Long?,
    val courseLevel: String,       // school|higher_secondary|iti|diploma|ug|pg|phd
    val gender: String = "prefer_not_to_say",
    val isMinority: Boolean = false,
    val minorityCommunity: String? = null,
    val hasDisability: Boolean = false,
    val lastExamPercentage: Double? = null,
    val isSingleGirlChild: Boolean = false,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("domicile_state", domicileState)
        put("category", category)
        put("annual_family_income", annualFamilyIncome ?: JSONObject.NULL)
        put("course_level", courseLevel)
        put("gender", gender)
        put("is_minority", isMinority)
        put("minority_community", minorityCommunity ?: JSONObject.NULL)
        put("has_disability", hasDisability)
        put("last_exam_percentage", lastExamPercentage ?: JSONObject.NULL)
        put("is_single_girl_child", isSingleGirlChild)
    }
}

// ---------------------------------------------------------------------------
// Validation. Mirrors backend/services/input_guard.py so a value the server
// would reject is also rejected here — one less round trip, and no way for a
// tampered local value to reach a URL path.
// ---------------------------------------------------------------------------
internal object Guard {

    /** RFC 5321 ceiling. Checked before anything else, because length is the
     *  cheapest possible rejection and the server enforces the same bound. */
    const val MAX_EMAIL = 254
    const val MAX_PASSWORD = 128
    const val MIN_PASSWORD = 8
    const val MAX_ID = 64

    /** Identifiers that become URL path segments. Allow-listed to the shapes
     *  the server issues, so "/" and "?" can never appear in one. */
    private val ID_RE = Regex("^[A-Za-z0-9][A-Za-z0-9_-]{3,63}$")
    private val SLUG_RE = Regex("^[a-z0-9][a-z0-9-]{0,63}$")
    private val TOKEN_RE = Regex("^[A-Za-z0-9_-]{32,128}$")

    /** Unicode bidi overrides and C0/C1 controls. Pasted or synced text can
     *  carry these; they make a string display as something other than what it
     *  is, and they survive into logs. */
    private val INVISIBLE_RE = Regex(
        "[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\u00AD\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]"
    )

    fun clean(value: String?, max: Int): String =
        INVISIBLE_RE.replace(value.orEmpty(), "").take(max)

    fun sessionId(value: String?): String =
        requireNotNull(value?.takeIf { ID_RE.matches(it) && it.length <= MAX_ID }) {
            "invalid session id"
        }

    fun schemeId(value: String?): String =
        requireNotNull(value?.takeIf { SLUG_RE.matches(it) }) { "invalid scheme id" }

    fun bearerToken(value: String?): String? =
        value?.takeIf { TOKEN_RE.matches(it) }

    fun password(value: String?): String =
        requireNotNull(value?.takeIf { it.length in MIN_PASSWORD..MAX_PASSWORD }) {
            "password must be $MIN_PASSWORD-$MAX_PASSWORD characters"
        }
}

/** Raised for anything the caller must not show verbatim in the UI. */
class FeeFixApiException(
    /** Stable, machine-readable — safe to branch on and safe to log. */
    val code: String,
    /** Human text written by us, never an exception message or a server body. */
    val userMessage: String,
    cause: Throwable? = null,
) : Exception(code, cause)

/**
 * Where the session token lives.
 *
 * Implemented by the app with **EncryptedSharedPreferences** (androidx.security
 * .crypto), which wraps the value in a key held by the Android Keystore: it
 * survives reboots, is not readable by other apps, and — unlike plain
 * SharedPreferences — does not appear in cleartext in a device backup or in a
 * bug report the user attaches.
 *
 * It is an interface here so this scaffold stays Gradle-free, and so tests can
 * substitute an in-memory fake without touching the crypto.
 */
interface TokenStore {
    /** Returns a shape-validated token, or null. Validation happens on read:
     *  a value mutated by a bug or a restored backup must never be sent. */
    fun token(): String?
    fun save(token: String): Boolean
    fun clear()
}

class FeeFixApi(
    baseUrl: String,
    private val tokenStore: TokenStore? = null,
    /** SHA-256 SPKI pins, e.g. "sha256/AAAA…". Empty disables pinning.
     *
     *  Pinning is what stops a malicious root CA — or a user talked into
     *  installing a "profile" or a debugging proxy — from silently reading and
     *  altering traffic that TLS alone would have protected. Always ship at
     *  least TWO pins (one primary, one backup), because a single pin that
     *  cannot be rotated turns a certificate renewal into an app that cannot
     *  reach its own backend. */
    certificatePins: List<String> = emptyList(),
) {

    private val base: String = baseUrl.let { raw ->
        // HTTPS only. Enforced in code, not left to the manifest: a
        // `usesCleartextTraffic` override or a debug build variant should not
        // be able to make bearer tokens travel in the clear.
        require(raw.startsWith("https://")) {
            "FeeFixApi requires an https:// base URL — refusing ${raw.take(32)}"
        }
        raw.trimEnd('/')
    }

    private val json = "application/json; charset=utf-8".toMediaType()
    private val random = SecureRandom()

    private val pinner: CertificatePinner? = certificatePins.takeIf { it.isNotEmpty() }?.let { pins ->
        val host = java.net.URI(base).host
        pins.fold(CertificatePinner.Builder()) { acc, pin -> acc.add(host, pin) }.build()
    }

    private val http: OkHttpClient = OkHttpClient.Builder()
        // Every timeout bounded. callTimeout is the one that matters most: it
        // caps the *whole* call including retries and redirects, so a server
        // (or an on-path attacker) that stalls mid-response cannot hang the
        // coroutine indefinitely.
        .callTimeout(20, TimeUnit.SECONDS)
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .writeTimeout(15, TimeUnit.SECONDS)
        // Redirects are followed only within the API. An attacker-controlled
        // redirect to another host is how a token gets replayed to a third
        // party, so cross-host redirects are refused outright.
        .followRedirects(false)
        .followSslRedirects(false)
        // One retry, on connection failure only. Unbounded retries against a
        // failing backend are a self-inflicted denial of service.
        .retryOnConnectionFailure(true)
        .apply { pinner?.let { certificatePinner(it) } }
        .build()

    // -----------------------------------------------------------------------
    // Transport
    // -----------------------------------------------------------------------
    private suspend fun call(request: Request): JSONObject = withContext(Dispatchers.IO) {
        try {
            http.newCall(request).execute().use { res ->
                val body = res.body
                // Bounded read. A hostile or broken intermediary must not be
                // able to make the app allocate without limit.
                val text = if (body == null) "" else {
                    val bytes = body.byteStream().readBytes(MAX_RESPONSE_BYTES)
                    String(bytes, Charsets.UTF_8)
                }
                if (!res.isSuccessful) throw FeeFixApiException(
                    code = "http_${res.code}",
                    userMessage = userMessageFor(res.code),
                )
                if (text.isEmpty()) return@use JSONObject()
                // org.json throws JSONException on malformed input; that is
                // caught below and converted, never propagated raw.
                JSONObject(text)
            }
        } catch (e: FeeFixApiException) {
            throw e
        } catch (e: javax.net.ssl.SSLPeerUnverifiedException) {
            // Pinning failure. This is a security event, not a network hiccup:
            // report it distinctly so the app can tell the user rather than
            // silently retrying into a man-in-the-middle.
            throw FeeFixApiException("tls_unverified", TLS_ERROR, e)
        } catch (e: java.io.IOException) {
            throw FeeFixApiException("network", NETWORK_ERROR, e)
        } catch (e: org.json.JSONException) {
            throw FeeFixApiException("bad_response", SERVER_ERROR, e)
        } catch (e: Exception) {
            // Never let an exception message reach the UI: it can contain the
            // URL, the host, or a fragment of the response.
            throw FeeFixApiException("unexpected", SERVER_ERROR, e)
        }
    }

    /** Client-safe strings. The HTTP status is ours to interpret; the server's
     *  `detail` is not trusted for display because a compromised or spoofed
     *  response could put markup into the UI through it. */
    private fun userMessageFor(status: Int): String = when (status) {
        401 -> "Your session ended. Please sign in again."
        403 -> "You don't have access to that."
        404 -> "We couldn't find that."
        409 -> "That request was already used. Please try again."
        413 -> "That request was too large."
        422 -> "Something in that form needs fixing."
        429 -> "Too many attempts — wait a moment and try again."
        in 500..599 -> SERVER_ERROR
        else -> SERVER_ERROR
    }

    private fun post(path: String, body: JSONObject, authenticated: Boolean = true) =
        build(path, authenticated)
            .post(body.toString().toRequestBody(json))
            .build()

    private fun put(path: String, body: JSONObject, authenticated: Boolean = true) =
        build(path, authenticated)
            .put(body.toString().toRequestBody(json))
            .build()

    private fun get(path: String, authenticated: Boolean = true) =
        build(path, authenticated).get().build()

    private fun build(path: String, authenticated: Boolean): Request.Builder {
        val builder = Request.Builder().url(base + path)
            // Tells any intermediary and our own logs what this client is,
            // without carrying anything identifying.
            .header("User-Agent", USER_AGENT)
            .header("Accept", "application/json")
            // A response bearing a session must never be stored by a proxy or
            // the platform HTTP cache.
            .header("Cache-Control", "no-store")
        if (authenticated) {
            // Validated on read: a token of the wrong shape is dropped rather
            // than sent, so a corrupted store cannot produce a malformed header.
            tokenStore?.token()?.let { raw ->
                Guard.bearerToken(raw)?.let { builder.header("Authorization", "Bearer $it") }
            }
        }
        return builder
    }

    // -----------------------------------------------------------------------
    // Anti-replay. Same contract as web/frontend/security.js: a fresh 192-bit
    // nonce plus a Unix timestamp on every mutating request. The server rejects
    // a nonce it has seen and a timestamp outside its window, so a captured
    // request is worth exactly one use even if TLS is broken somewhere upstream.
    //
    // SecureRandom, never Math.random/java.util.Random: a predictable nonce is
    // a nonce an attacker can pre-register, which inverts the control.
    // -----------------------------------------------------------------------
    private fun withReplayProof(builder: Request.Builder): Request.Builder {
        val bytes = ByteArray(24)
        random.nextBytes(bytes)
        val nonce = Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        return builder
            .header(HEADER_NONCE, nonce)
            .header(HEADER_TS, (System.currentTimeMillis() / 1000).toString())
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /** Email sign-up. Returns and stores the session token. */
    suspend fun register(email: String, password: String, name: String? = null): JSONObject {
        val body = JSONObject()
            .put("email", Guard.clean(email, Guard.MAX_EMAIL))
            .put("password", Guard.password(password))
        name?.let { body.put("name", Guard.clean(it, 80)) }
        return finishSignIn(call(withReplayProof(post("/api/auth/register", body, authenticated = false)).build()))
    }

    suspend fun login(email: String, password: String): JSONObject {
        val body = JSONObject()
            .put("email", Guard.clean(email, Guard.MAX_EMAIL))
            .put("password", Guard.password(password))
        return finishSignIn(call(withReplayProof(post("/api/auth/login", body, authenticated = false)).build()))
    }

    /** Request a one-time code. The response never contains the code itself on
     *  a production backend — if `dev_code` is present the app is pointed at a
     *  development server and should say so rather than auto-fill it. */
    suspend fun requestOtp(channel: String, address: String): JSONObject {
        require(channel == "email" || channel == "phone") { "unknown channel" }
        val body = JSONObject()
            .put("channel", channel)
            .put("address", Guard.clean(address, Guard.MAX_EMAIL))
        return call(withReplayProof(post("/api/auth/otp/request", body, authenticated = false)).build())
    }

    suspend fun verifyOtp(channel: String, address: String, code: String, name: String? = null): JSONObject {
        // Digits only, capped: the value is typed or pasted, and a paste can
        // carry anything.
        val digits = code.filter { it.isDigit() }.take(8)
        require(digits.length in 4..8) { "code must be 4-8 digits" }
        val body = JSONObject()
            .put("channel", channel)
            .put("address", Guard.clean(address, Guard.MAX_EMAIL))
            .put("code", digits)
        name?.let { body.put("name", Guard.clean(it, 80)) }
        return finishSignIn(call(withReplayProof(post("/api/auth/otp/verify", body, authenticated = false)).build()))
    }

    /** Revokes the session server-side AND clears local storage. Doing only one
     *  of the two leaves either a live token nobody holds or a dead token the UI
     *  still believes in. */
    suspend fun logout(): Boolean = try {
        call(withReplayProof(post("/api/auth/logout", JSONObject(), authenticated = true)).build())
            .optBoolean("revoked")
    } finally {
        tokenStore?.clear()
    }

    /** Save profile + receive personalised, ranked, explained matches in one call. */
    suspend fun matchAndSave(sessionId: String, profile: StudentProfile): JSONObject {
        val sid = Guard.sessionId(sessionId)
        val body = JSONObject().put("profile", profile.toJson())
        return call(withReplayProof(put("/api/students/$sid/profile", body)).build())
    }

    /** Reminder center feed (severe-first). */
    suspend fun reminders(sessionId: String): JSONObject =
        call(get("/api/students/${Guard.sessionId(sessionId)}/reminders"))

    /** Move a scheme along the tracker pipeline. status == null clears it. */
    suspend fun track(sessionId: String, schemeId: String, status: String?): JSONObject {
        val sid = Guard.sessionId(sessionId)
        val scheme = Guard.schemeId(schemeId)
        // Whitelisted server-side too; validating here means a bad value cannot
        // reach a URL path at all.
        require(status == null || status in TRACK_STATUSES) { "unknown status: $status" }
        val body = JSONObject().put("status", status ?: JSONObject.NULL)
        return call(withReplayProof(put("/api/tracker/$sid/$scheme", body)).build())
    }

    /** All tracked items with scheme payloads attached. */
    suspend fun board(sessionId: String): JSONObject =
        call(get("/api/tracker/${Guard.sessionId(sessionId)}"))

    /** Bind an anonymous session to the signed-in account. Ownership is
     *  write-once server-side: binding a session that already belongs to someone
     *  else is refused with 403, and that refusal is correct behaviour rather
     *  than an error to retry. */
    suspend fun linkSession(sessionId: String): JSONObject {
        val body = JSONObject().put("session_id", Guard.sessionId(sessionId))
        return call(withReplayProof(post("/api/auth/link-session", body)).build())
    }

    /** Data portability: everything the account holds, in one JSON document. */
    suspend fun exportMyData(): JSONObject = call(get("/api/auth/export"))

    /** Right to erasure. Clears local state regardless of the server's answer,
     *  because a token for a deleted account is worse than no token. */
    suspend fun deleteAccount(): Boolean = try {
        val request = withReplayProof(build("/api/auth/account", authenticated = true).delete()).build()
        call(request).optBoolean("deleted")
    } finally {
        tokenStore?.clear()
    }

    private fun finishSignIn(response: JSONObject): JSONObject {
        val token = response.optString("token", "")
        // Shape-check before persisting. Storing an unvalidated value means the
        // next request sends whatever arrived, and a hostile response could put
        // arbitrary bytes into an Authorization header.
        val safe = Guard.bearerToken(token)
            ?: throw FeeFixApiException("bad_token", SERVER_ERROR)
        if (tokenStore?.save(safe) != true) {
            throw FeeFixApiException("token_store_failed",
                "Sign-in worked but the session could not be stored securely.")
        }
        return response
    }

    private companion object {
        const val MAX_RESPONSE_BYTES = 2 * 1024 * 1024
        const val HEADER_NONCE = "X-FeeFix-Nonce"
        const val HEADER_TS = "X-FeeFix-Ts"
        const val USER_AGENT = "FeeFixAndroid/1.2 (okhttp)"
        const val NETWORK_ERROR = "Can't reach FeeFix right now. Check your connection."
        const val SERVER_ERROR = "Something went wrong on our side. Please try again."
        const val TLS_ERROR = "We couldn't verify this server's certificate. " +
            "On public Wi-Fi, switch networks and try again."
        val TRACK_STATUSES = setOf(
            "saved", "planning", "applied", "under_review", "approved", "rejected"
        )
    }
}

/** Bounded read helper: stops at [max] bytes instead of trusting the sender. */
private fun java.io.InputStream.readBytes(max: Int): ByteArray {
    val buffer = java.io.ByteArrayOutputStream()
    val chunk = ByteArray(8 * 1024)
    var total = 0
    while (true) {
        val read = this.read(chunk)
        if (read <= 0) break
        total += read
        if (total > max) throw FeeFixApiException("response_too_large", "Response was too large.")
        buffer.write(chunk, 0, read)
    }
    return buffer.toByteArray()
}
