// FeeFix India — Android API client contract (reference scaffold).
// Dependency-free OkHttp + kotlinx-serialization-free (org.json) so the file
// documents the full contract without Gradle. Swap to Retrofit in the app.
package `in`.feefix

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

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

class FeeFixApi(private val baseUrl: String) {
    private val http = OkHttpClient()
    private val json = "application/json; charset=utf-8".toMediaType()

    private suspend fun call(request: Request): JSONObject = withContext(Dispatchers.IO) {
        http.newCall(request).execute().use { res ->
            JSONObject(res.body!!.string())
        }
    }

    private fun post(path: String, body: JSONObject) = Request.Builder()
        .url("$baseUrl$path").post(body.toString().toRequestBody(json)).build()

    private fun get(path: String) = Request.Builder().url("$baseUrl$path").build()

    /** Save profile + receive personalised, ranked, explained matches in one call. */
    suspend fun matchAndSave(sessionId: String, profile: StudentProfile): JSONObject =
        call(post("/api/students/$sessionId/profile", JSONObject().put("profile", profile.toJson())))

    /** Reminder center feed (severe-first). */
    suspend fun reminders(sessionId: String): JSONObject =
        call(get("/api/students/$sessionId/reminders"))

    /** Move a scheme along the tracker pipeline. status == null clears it. */
    suspend fun track(sessionId: String, schemeId: String, status: String?): JSONObject =
        call(post("/api/tracker/$sessionId/$schemeId",
            JSONObject().put("status", status ?: JSONObject.NULL)))

    /** All tracked items with scheme payloads attached. */
    suspend fun board(sessionId: String): JSONObject = call(get("/api/tracker/$sessionId"))
}
