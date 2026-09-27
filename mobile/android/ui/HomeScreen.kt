// FeeFix India — Home screen (reference scaffold).
// "You have 7 potential matches." + Urgent · New · Saved · Progress.
// Design rules: one primary action, one clear result, one obvious next step.
package `in`.feefix.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import `in`.feefix.FeeFixApi
import `in`.feefix.StudentProfile

data class HomeState(
    val matchCount: Int = 0,
    val urgentNames: List<String> = emptyList(),
    val reminderMessages: List<String> = emptyList(),
    val loading: Boolean = true,
)

@Composable
fun HomeScreen(api: FeeFixApi, sessionId: String, profile: StudentProfile) {
    var state by remember { mutableStateOf(HomeState()) }

    LaunchedEffect(profile) {
        val matches = api.matchAndSave(sessionId, profile)
        val reminders = api.reminders(sessionId)
        val open = matches.getInt("open_match_count")
        val urgent = mutableListOf<String>()
        val arr = matches.getJSONArray("matches")
        for (i in 0 until arr.length()) {
            val m = arr.getJSONObject(i)
            val dl = m.getJSONObject("deadline")
            if (!dl.isNull("days_left") && dl.getInt("days_left") in 0..30)
                urgent += m.getString("name")
        }
        val msgs = mutableListOf<String>()
        val rArr = reminders.getJSONArray("reminders")
        for (i in 0 until rArr.length()) msgs += rArr.getJSONObject(i).getString("message")
        state = HomeState(open, urgent, msgs, loading = false)
    }

    LazyColumn(Modifier.fillMaxSize().padding(20.dp)) {
        item {
            Text("FeeFix", style = MaterialTheme.typography.headlineMedium)
            Text(
                "You have ${state.matchCount} potential matches.",
                style = MaterialTheme.typography.headlineSmall,
                modifier = Modifier.padding(top = 12.dp, bottom = 18.dp),
            )
        }
        if (state.urgentNames.isNotEmpty()) {
            item { Text("Urgent applications", style = MaterialTheme.typography.titleMedium) }
            items(state.urgentNames) { n ->
                ElevatedCard(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                    Text(n, Modifier.padding(16.dp))
                }
            }
        }
        item { Spacer(Modifier.height(14.dp)); Text("Reminders", style = MaterialTheme.typography.titleMedium) }
        items(state.reminderMessages.take(4)) { m ->
            OutlinedCard(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                Text(m, Modifier.padding(16.dp), style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}
