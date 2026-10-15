// ==========================================================================
// FeeFix India — Home screen (reference scaffold).
// "You have 7 potential matches." + Urgent · New · Saved · Progress.
// Design rules: one primary action, one clear result, one obvious next step.
//
// WHAT CHANGED, AND WHY
// ---------------------
// The previous version called the API inside LaunchedEffect with no try/catch.
// An exception escaping a LaunchedEffect coroutine is not swallowed — it
// propagates to the composition and crashes the process. On a mobile network
// that means the home screen crashed on every timeout, every captive portal,
// and every moment the backend was briefly unavailable. Three fixes below, in
// order of how much they matter:
//
//   1. EVERY API call is wrapped. A network failure now renders a retry state
//      instead of taking the app down.
//   2. Errors are rendered from a fixed set of strings WE wrote, never from an
//      exception message or a server response body. `Exception.message` on a
//      socket failure contains the host and port; a server `detail` contains
//      whatever the server decided to say. Neither belongs in the UI, and both
//      end up in screenshots and bug reports if they do.
//   3. FLAG_SECURE. This screen shows what a student told us about their family
//      income, community and disability status. Without it, that data appears
//      in the recent-apps carousel — visible to anyone who picks up the phone,
//      and captured in any screenshot the student takes for an unrelated
//      reason. For this data class that is the difference between private and
//      public.
//
// Also: `optInt`/`optString` instead of `getInt`/`getString`, so a backend that
// legitimately omits an optional field degrades instead of throwing.
// ==========================================================================
package `in`.feefix.ui

import android.view.WindowManager
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import `in`.feefix.FeeFixApiException
import `in`.feefix.FeeFixApi
import `in`.feefix.StudentProfile

/**
 * What the home screen is currently showing.
 *
 * `error` is deliberately an enum rather than a String: the set of things that
 * can go wrong is finite and known, and the copy for each is written here
 * rather than inherited from an exception or a response body.
 */
enum class HomeError { NETWORK, SIGNED_OUT, SERVER }

data class HomeState(
    val matchCount: Int = 0,
    val urgentNames: List<String> = emptyList(),
    val reminderMessages: List<String> = emptyList(),
    val loading: Boolean = true,
    val error: HomeError? = null,
)

/** Keep this screen out of the recent-apps carousel and out of screenshots. */
@Composable
private fun FlagSecureOnResume() {
    val activity = LocalContext.current as? android.app.Activity ?: return
    DisposableEffect(activity) {
        activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        onDispose { activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE) }
    }
}

@Composable
fun HomeScreen(
    api: FeeFixApi,
    sessionId: String,
    profile: StudentProfile,
    /** Called when the server says this session no longer exists. The caller
     *  decides how to re-authenticate; this screen must not silently sit in a
     *  loading state that will never resolve. */
    onSignedOut: () -> Unit = {},
) {
    var state by remember { mutableStateOf(HomeState()) }
    // Changing this re-runs the load, which is what the Retry button presses.
    var attempt by remember { mutableIntStateOf(0) }

    FlagSecureOnResume()

    LaunchedEffect(profile, attempt) {
        state = state.copy(loading = true, error = null)
        try {
            val matches = api.matchAndSave(sessionId, profile)
            val reminders = api.reminders(sessionId)

            // optInt / optString: a missing optional field is not a crash. The
            // backend may legitimately omit `open_match_count` for a profile
            // that matches nothing.
            val open = matches.optInt("open_match_count", 0)

            val urgent = mutableListOf<String>()
            val arr = matches.optJSONArray("matches")
            for (i in 0 until (arr?.length() ?: 0)) {
                val m = arr?.optJSONObject(i) ?: continue
                val dl = m.optJSONObject("deadline")
                val daysLeft = dl?.optInt("days_left", Int.MIN_VALUE) ?: Int.MIN_VALUE
                if (daysLeft in 0..30) {
                    // Names come from our own curated dataset, but they still
                    // travel through JSON — cap them so a malformed record
                    // cannot render an unbounded string.
                    urgent += m.optString("name", "").take(200)
                }
            }

            val msgs = mutableListOf<String>()
            val rArr = reminders.optJSONArray("reminders")
            for (i in 0 until (rArr?.length() ?: 0)) {
                val r = rArr?.optJSONObject(i) ?: continue
                msgs += r.optString("message", "").take(300)
            }

            state = HomeState(
                matchCount = open,
                urgentNames = urgent,
                reminderMessages = msgs,
                loading = false,
            )
        } catch (e: FeeFixApiException) {
            // Map a machine-readable code to one of three fixed messages.
            // Never `e.message` — see the header comment.
            state = when (e.code) {
                "http_401" -> HomeState(loading = false, error = HomeError.SIGNED_OUT)
                "network", "tls_unverified" -> HomeState(loading = false, error = HomeError.NETWORK)
                else -> HomeState(loading = false, error = HomeError.SERVER)
            }
            if (e.code == "http_401") onSignedOut()
        } catch (e: Exception) {
            // Last resort: a bug in this screen must not crash the app either.
            state = HomeState(loading = false, error = HomeError.SERVER)
        }
    }

    LazyColumn(Modifier.fillMaxSize().padding(20.dp)) {
        item {
            Text("FeeFix", style = MaterialTheme.typography.headlineMedium)
            Text(
                when {
                    state.loading -> "Checking what you may qualify for…"
                    state.error != null -> ""          // the banner below carries it
                    else -> "You have ${state.matchCount} potential matches."
                },
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.padding(top = 12.dp, bottom = 18.dp),
            )
        }

        if (state.loading) {
            item { LinearProgressIndicator(Modifier.fillMaxWidth()) }
        }

        state.error?.let { err ->
            item {
                ErrorBanner(err) { attempt++ }
            }
        }

        if (state.urgentNames.isNotEmpty()) {
            item { Text("Urgent applications", style = MaterialTheme.typography.titleMedium) }
            items(state.urgentNames) { n ->
                ElevatedCard(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                    Text(n, Modifier.padding(16.dp))
                }
            }
        }

        if (state.reminderMessages.isNotEmpty()) {
            item {
                Spacer(Modifier.height(14.dp))
                Text("Reminders", style = MaterialTheme.typography.titleMedium)
            }
            items(state.reminderMessages.take(4)) { m ->
                OutlinedCard(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                    Text(m, Modifier.padding(16.dp), style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}

@Composable
private fun ErrorBanner(error: HomeError, onRetry: () -> Unit) {
    val (headline, detail) = when (error) {
        HomeError.NETWORK -> "Can't reach FeeFix" to
            "Check your connection and try again. Nothing was lost."
        HomeError.SIGNED_OUT -> "Your session ended" to
            "Sign in again to pick up where you left off."
        HomeError.SERVER -> "Something went wrong" to
            "This is on us. Please try again in a moment."
    }
    ElevatedCard(
        Modifier.fillMaxWidth().padding(vertical = 8.dp),
        colors = CardDefaults.elevatedCardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
        ),
    ) {
        Column(Modifier.padding(16.dp)) {
            Text(headline, style = MaterialTheme.typography.titleSmall)
            Text(detail, style = MaterialTheme.typography.bodyMedium,
                 modifier = Modifier.padding(top = 4.dp))
            if (error != HomeError.SIGNED_OUT) {
                TextButton(onClick = onRetry, modifier = Modifier.padding(top = 4.dp)) {
                    Text("Try again")
                }
            }
        }
    }
}
