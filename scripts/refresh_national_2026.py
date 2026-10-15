#!/usr/bin/env python3
"""Apply the verified NSP 2026-27 refresh to data/schemes/national.json.

Every change here is sourced. The source is written into the verification
manifest next to the record it justifies, so a reviewer can check any single
claim without reading this script.

Sources (retrieved 2026-10-15):

  [NSP]  https://scholarships.gov.in/ — official portal, Announcements:
         * "The Portal is open for Academic year 2026-27 from 1'st June 2026."
         * "Renewal applications for the 'PM-USP – Central Sector Scheme Of
           Scholarship For College And University Students (CSSS)' and 'PM USP
           Special Scholarship Scheme For Jammu Kashmir And Ladakh' is currently
           open in NSP. Closing dates for student application is 31-10-2026,
           institute verification 15-11-2026, L2 verification 30/11/2026."
         * "Students may apply for one merit-based scholarship scheme and one or
           more welfare-based scholarship schemes from AY 2026-27."
         * "All disabled students must first login in the UDID portal and provide
           consent to share their UDID details and then submit application in NSP."

  [NSPG] https://scholarships.gov.in/public/FAQ/FAQ_NSPG.pdf — official UGC FAQ:
         NSPGS is an umbrella scheme merging (i) PG Indira Gandhi single girl
         child, (ii) PG scholarship for university rank holders, (iii) PG
         scholarship for SC/ST professional courses, (iv) PG scholarship for
         GATE/GPAT. 10,000 slots/year; Rs 15,000/month for 10 months; 30% of
         slots reserved for women with preference to single girl child; age < 30
         at admission; NO income criteria; regular mode only; not for anyone who
         already holds a PG degree; 50/50 Arts-Humanities-SocialSciences-Law-
         Management vs Science-Engineering-Tech-Medical-Agriculture.

  [TOI]  Times of India, 2026-10-01 — Ministry of Education extended the NMMSS
         2026-27 student deadline to 31 October 2026; L1 (INO) 15 Nov; L2 (DNO)
         30 Nov. 88,522 fresh + 1,97,133 renewal applications as of 30 Sep.

  [SHI]  shiksha.com, 2026-09-09 — DST told the Rajya Sabha on 13 August 2026
         that INSPIRE (SHE) is under redesign and has NOT been discontinued. No
         new application form has been released since October 2024.

  [ECN]  eclassnotes.in, 2026-10-06 — all 31 central schemes on NSP for 2026-27
         carry the student deadline 31 October 2026; AICTE Swanath, Pragati
         (degree + diploma), Saksham (degree + diploma), PM USP Special
         Scholarship J&K/Ladakh (renewal only), PM YASASVI Top Class School
         (renewal only) and Top Class College, Top Class Education for SC, Free
         Coaching for SC/OBC/PM-Cares children all opened 01-06-2026 except Free
         Coaching which opened 03-08-2026.

Run with:  python scripts/refresh_national_2026.py
"""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PATH = REPO / "data" / "schemes" / "national.json"
TODAY = "2026-10-15"

NSP = "https://scholarships.gov.in"
NSP_ANNOUNCE = "https://scholarships.gov.in/ViewMoreAnnouncement"
NSPG_FAQ = "https://scholarships.gov.in/public/FAQ/FAQ_NSPG.pdf"

#: The AY 2026-27 rule change, verbatim in substance from [NSP].
CONCURRENCY_RULE = (
    "From AY 2026–27 a student may hold ONE merit-based scheme and one or more "
    "welfare-based schemes, per each scheme's eligibility — the older "
    "'one scholarship only' restriction no longer applies"
)

#: Mandatory for every disability-linked NSP scheme from AY 2026-27 [NSP].
UDID_RULE = (
    "UDID portal registration and consent to share UDID details is MANDATORY "
    "before submitting the NSP application — without it the application cannot "
    "be submitted at all (NSP announcement, AY 2026–27)"
)

NSP_STEPS = [
    "Generate your One Time Registration (OTR) on NSP using Aadhaar or your "
    "Aadhaar enrolment ID — OTR is required for every NSP scheme from AY 2024–25",
    "Log in to scholarships.gov.in with your OTR",
    "Select the scheme and fill academic, personal and bank details",
    "Upload the required documents",
    "Submit before the student deadline, then follow up with your institute for "
    "Level-1 (INO) verification",
    "Track Level-2 (district/state) verification on the NSP dashboard",
]

NSP_DOCS = [
    "Aadhaar (for OTR generation and DBT seeding)",
    "Aadhaar-seeded bank account passbook",
    "Latest marksheet / grade card",
    "Income certificate (issued by the competent authority)",
    "Category certificate, where the scheme requires one",
    "Bonafide / admission certificate from the institute",
]


def _nsp_application(portal: str, scheme_hint: str, url: str = NSP) -> dict:
    return {
        "mode": "online",
        "portal": portal,
        "url": url,
        "steps": [NSP_STEPS[0], NSP_STEPS[1],
                  f"Select '{scheme_hint}' from the scheme list",
                  *NSP_STEPS[2:]],
    }


# ---------------------------------------------------------------------------
# Records to REMOVE. Each carries a reason that goes into the manifest's
# `retired` list, so the audit trail survives the deletion.
# ---------------------------------------------------------------------------
RETIRED = {
    "ugc-pg-single-girl-child": {
        "retired_on": TODAY,
        "reason": (
            "Merged. UGC's own FAQ on the NSP portal states that the National "
            "Scholarship for Post Graduate Studies (NSPGS) is 'an umbrella scheme "
            "by merging four different scholarship schemes for postgraduate "
            "studies i.e. (i) PG Indira Gandhi single girl child scholarship, "
            "(ii) PG scholarship for university rank holders, (iii) PG scholarship "
            "for SC/ST students pursuing professional courses and (iv) Post "
            "Graduate Scholarship for GATE/GPAT'. Single girl child is now a "
            "preference within the 30% women reservation under NSPGS, not a "
            "separate scheme."
        ),
        "superseded_by": "ugc-nspgs",
        "source": NSPG_FAQ,
    },
    "ugc-pg-merit-rank-holders": {
        "retired_on": TODAY,
        "reason": (
            "Merged into the National Scholarship for Post Graduate Studies "
            "(NSPGS) along with the single-girl-child, SC/ST professional and "
            "GATE/GPAT PG schemes. NSPGS selects purely on all-India merit for "
            "10,000 slots a year; university rank is no longer a separate award."
        ),
        "superseded_by": "ugc-nspgs",
        "source": NSPG_FAQ,
    },
    "inspire-she": {
        "retired_on": TODAY,
        "reason": (
            "No application window has been open since October 2024 — two full "
            "cycles missed. DST told the Rajya Sabha on 13 August 2026 that "
            "INSPIRE (SHE) is under REDESIGN and has not been discontinued, but "
            "no form, deadline or eligibility has been published. The dataset "
            "previously carried a deadline of 2026-10-15, which would have told "
            "a student to apply for a scheme with no open application at all. "
            "Re-add when DST publishes a notice; the expected window is around "
            "January 2027 based on the previous cycle."
        ),
        "superseded_by": None,
        "source": "https://www.shiksha.com/college/articles/inspire-scholarship-2026-27-latest-status-eligibility-amount-and-application-process-blogId-241187",
    },
}


# ---------------------------------------------------------------------------
# Field-level updates to EXISTING records.
# ---------------------------------------------------------------------------
UPDATES = {
    "nsp-central-sector": {
        "deadline": {"date": "2026-10-31", "rolling": False,
                     "label": "NSP 2026–27 student deadline (confirmed on the official portal)"},
        "notes": (
            "RENEWAL ONLY for AY 2026–27. The official NSP announcement names "
            "PM-USP CSSS explicitly as open for renewal applications, closing "
            "31-10-2026, with institute verification to 15-11-2026 and Level-2 "
            "verification to 30-11-2026. Fresh applicants should check the NSP "
            "dashboard before assuming a fresh window exists."
        ),
        "special_conditions_replace": {
            "No other scholarship may be held concurrently": CONCURRENCY_RULE,
        },
        "special_conditions_add": [
            "Listed by NSP as RENEWAL ONLY for AY 2026–27",
            "Family income up to ₹4.5 lakh and above the 80th percentile in Class XII",
        ],
    },
    "nsp-post-matric-minority": {
        "deadline": {"date": "2026-10-31", "rolling": False,
                     "label": "NSP 2026–27 student deadline (all 31 central schemes)"},
    },
    "nsp-post-matric-disabilities": {
        "deadline": {"date": "2026-10-31", "rolling": False,
                     "label": "NSP 2026–27 student deadline"},
        "special_conditions_add": [UDID_RULE],
        "notes": (
            "UDID consent is now a hard prerequisite — NSP will not accept the "
            "application without it. Register on the UDID portal first and allow "
            "time for the certificate, because it is issued separately and is not "
            "instant."
        ),
    },
    "nsp-merit-cum-means": {
        "deadline": {"date": "2026-10-31", "rolling": False,
                     "label": "NSP 2026–27 student deadline"},
    },
    "nsp-top-class-sc": {
        "deadline": {"date": "2026-10-31", "rolling": False,
                     "label": "NSP 2026–27 student deadline"},
    },
    "begum-hazrat-mahal": {
        "deadline": {"date": "2026-10-31", "rolling": False,
                     "label": "NSP 2026–27 student deadline"},
        # Was pending_review since 2026-08-30. The scheme is listed among the
        # 31 central schemes on NSP for 2026-27 and the portal confirms the
        # common 31-10-2026 student deadline, so it moves to verified.
        "verification_status": "verified",
    },
    "aicte-pragati": {
        "deadline": {"date": "2026-10-31", "rolling": False,
                     "label": "NSP 2026–27 student deadline (opened 01-06-2026)"},
    },
    "aicte-saksham": {
        "deadline": {"date": "2026-10-31", "rolling": False,
                     "label": "NSP 2026–27 student deadline (opened 01-06-2026)"},
        "special_conditions_add": [UDID_RULE],
    },
    "nmms-central": {
        # Was 2026-12-15, labelled "State NMMS exam windows (Nov-Dec)" — that
        # conflated the *selection exam* with the *scholarship application*. The
        # exam is a state-run Class VIII test held Nov-Dec; the NSP application
        # window is separate and, for 2026-27, was extended to 31 October.
        "deadline": {"date": "2026-10-31", "rolling": False,
                     "label": "NSP 2026–27 student deadline, EXTENDED from 31 Aug → 30 Sep → 31 Oct 2026"},
        "notes": (
            "Two different dates are easily confused here. The state NMMS "
            "SELECTION EXAM (MAT + SAT) for Class VIII students is held around "
            "Nov–Dec 2026 (e.g. Delhi 5 Dec, Odisha 6 Dec) and is run by each "
            "SCERT. The NSP SCHOLARSHIP APPLICATION for students who already "
            "qualify closed 31 October 2026, after the Ministry of Education "
            "extended it twice. Institute (L1) verification ran to 15 Nov and "
            "district (L2) to 30 Nov 2026. 88,522 fresh and 1,97,133 renewal "
            "applications had been filed by 30 Sep 2026."
        ),
    },
    "ishan-uday-ner": {
        "deadline": {"date": "2026-10-31", "rolling": False,
                     "label": "NSP 2026–27 student deadline (opened 16-09-2026)"},
        # Applied for through NSP, not on ugc.gov.in — the previous official_url
        # sent a student to a body that does not accept the application.
        "official_url": NSP,
        "application_url": NSP,
        "notes": (
            "UGC opened the 2026–27 window late, on 16 September 2026, well after "
            "the portal's general 1 June opening. 10,000 fresh awards a year for "
            "first-year UG students domiciled in a North Eastern state. Apply on "
            "NSP — ugc.gov.in does not take the application."
        ),
    },
}


# ---------------------------------------------------------------------------
# NEW records, each currently absent from the dataset.
# ---------------------------------------------------------------------------
def new_records() -> list[dict]:
    return [
        {
            "id": "ugc-nspgs",
            "name": "National Scholarship for Post Graduate Studies (NSPGS)",
            "provider": "University Grants Commission (UGC), Ministry of Education — via NSP",
            "level": "central",
            "summary": (
                "The umbrella PG merit scholarship, ₹15,000 a month for 10 months "
                "over two years, for 10,000 students a year. It replaced four "
                "separate UGC PG schemes — Indira Gandhi Single Girl Child, "
                "University Rank Holders, SC/ST Professional Courses, and "
                "GATE/GPAT — so there is now ONE application for all of them."
            ),
            "benefit": {
                "type": "scholarship",
                "amount_annual_inr": 150000,
                "amount_display": "₹15,000 / month for 10 months (₹1.5 lakh / year, 2 years)",
                "details": (
                    "Disbursed by UGC through DBT to an Aadhaar-seeded account. "
                    "Renewal for the second year requires a separate NSP renewal "
                    "application plus successful completion of the first year — "
                    "the second year is NOT processed automatically."
                ),
            },
            "deadline": {"date": "2026-10-31", "rolling": False,
                         "label": "NSP 2026–27 student deadline (UGC schemes opened 16-09-2026)"},
            "eligibility": {
                "domicile_states": None,
                "categories": ["general", "sc", "st", "obc"],
                # UGC's FAQ answer 11 is explicit: "Is there any income criteria
                # for this scholarship? Reply: No".
                "max_family_income": None,
                "genders": ["male", "female", "other", "prefer_not_to_say"],
                "minority_only": False,
                "minority_communities": None,
                "disability_required": False,
                "course_levels": ["pg"],
                "min_marks_percent": None,
                "single_girl_child_required": False,
                "special_conditions": [
                    "First PG degree only — anyone who has ALREADY acquired a "
                    "postgraduate degree is not eligible",
                    "Under 30 years of age as on the date of admission to the "
                    "first semester/year of the PG programme",
                    "Regular, full-time mode only — open, distance and private "
                    "mode are excluded",
                    "No income ceiling at all; selection is purely on merit",
                    "30% of slots reserved for women candidates, with preference "
                    "given to single girl children (a single girl child is the "
                    "only girl in the family with no brothers or sisters; one of "
                    "twin or fraternal daughters also qualifies)",
                    "50% of slots for Arts, Humanities, Social Sciences, Law and "
                    "Management; 50% for Science, Engineering & Technology, "
                    "Medical, Technical, Agriculture and Forestry",
                    "10,000 slots per annum, allocated per the Government of "
                    "India reservation policy",
                    "Applications are invited once a year, only on NSP",
                    "The institution must hold a valid AISHE code",
                    CONCURRENCY_RULE,
                ],
            },
            "documents": NSP_DOCS + [
                "UG marksheet and degree / provisional certificate",
                "PG admission letter",
                "Single-girl-child affidavit, if claiming that preference",
            ],
            "application": _nsp_application(
                "National Scholarship Portal (UGC)", "National Scholarship for Post Graduate Studies"),
            "official_url": NSPG_FAQ,
            "last_verified": TODAY,
            "verification_status": "verified",
            "tags": ["central", "pg", "merit", "ugc", "postgraduate", "umbrella"],
            "notes": (
                "If you were told to apply for the 'Indira Gandhi Single Girl "
                "Child Scholarship' or the 'PG Scholarship for University Rank "
                "Holders', those no longer exist as separate schemes — both were "
                "merged into NSPGS, whose official FAQ is linked above. Verify "
                "the exact opening and closing dates on your NSP dashboard, "
                "because UGC schemes opened later (16 Sep) than the portal "
                "generally (1 Jun) and the FAQ itself says deadlines are "
                "displayed on NSP rather than fixed in the guideline."
            ),
        },
        {
            "id": "pm-yasasvi-top-class-college",
            "name": "PM YASASVI Central Sector Scheme of Top Class Education in College (OBC / EBC / DNT)",
            "provider": "Department of Social Justice & Empowerment (Backward Classes), Ministry of Social Justice & Empowerment",
            "level": "central",
            "summary": (
                "Merit-cum-means scholarship for OBC, EBC and Denotified-Nomadic-"
                "Semi-Nomadic Tribe students studying at college level, covering "
                "tuition up to ₹2 lakh a year plus a maintenance allowance."
            ),
            "benefit": {
                "type": "scholarship",
                "amount_annual_inr": 200000,
                "amount_display": "Full tuition up to ₹2,00,000 / year + maintenance allowance",
                "details": (
                    "Tuition is reimbursed at actuals up to the ceiling; the "
                    "maintenance allowance is paid in addition for hostellers and "
                    "day scholars at different rates."
                ),
            },
            "deadline": {"date": "2026-10-31", "rolling": False,
                         "label": "NSP 2026–27 student deadline (opened 01-06-2026)"},
            "eligibility": {
                "domicile_states": None,
                "categories": ["obc", "general"],
                "max_family_income": 250000,
                "genders": ["male", "female", "other", "prefer_not_to_say"],
                "minority_only": False,
                "minority_communities": None,
                "disability_required": False,
                "course_levels": ["ug", "pg"],
                "min_marks_percent": 60,
                "single_girl_child_required": False,
                "special_conditions": [
                    "For OBC, Economically Backward Classes (EBC) and DNT / "
                    "SNT (Denotified, Nomadic and Semi-Nomadic Tribe) students",
                    "EBC and DNT applicants are covered under the 'general' "
                    "category in FeeFix — check the scheme's own certificate "
                    "requirements, which differ from a standard OBC certificate",
                    "Admission in a recognised college / university, regular mode",
                    "Selected through the PM YASASVI entrance test for the school "
                    "component; the college component is merit-cum-means on the "
                    "qualifying examination",
                    CONCURRENCY_RULE,
                ],
            },
            "documents": NSP_DOCS + [
                "OBC / EBC / DNT caste or community certificate",
                "Previous qualifying examination marksheet",
                "Fee receipt or fee structure from the institute",
            ],
            "application": _nsp_application(
                "National Scholarship Portal (MoSJE-BC)",
                "PM YASASVI Top Class Education in College"),
            "official_url": NSP,
            "last_verified": TODAY,
            "verification_status": "verified",
            "tags": ["central", "obc", "ebc", "dnt", "top-class", "yasasvi", "ug", "pg"],
            "notes": (
                "The SCHOOL-level component of PM YASASVI (Classes IX–XII) is a "
                "separate listing and was reported as RENEWAL ONLY for 2026–27 "
                "with an earlier closing date; the college component is open for "
                "fresh applicants. Confirm which one applies to you on the NSP "
                "dashboard before relying on this deadline."
            ),
        },
        {
            "id": "aicte-swanath",
            "name": "AICTE Swanath Scholarship Scheme (Technical Degree & Diploma)",
            "provider": "All India Council for Technical Education (AICTE) — via NSP",
            "level": "central",
            "summary": (
                "₹50,000 a year for students in AICTE-approved degree or diploma "
                "programmes who have lost one or both parents, and for wards of "
                "defence and paramilitary personnel martyred in action."
            ),
            "benefit": {
                "type": "scholarship",
                "amount_annual_inr": 50000,
                "amount_display": "₹50,000 / year",
                "details": (
                    "A lump-sum grant towards tuition, books, equipment and "
                    "software — not a maintenance allowance. Paid for the full "
                    "duration of the degree or diploma."
                ),
            },
            "deadline": {"date": "2026-10-31", "rolling": False,
                         "label": "NSP 2026–27 student deadline (opened 01-06-2026)"},
            "eligibility": {
                "domicile_states": None,
                "categories": ["general", "sc", "st", "obc"],
                "max_family_income": 800000,
                "genders": ["male", "female", "other", "prefer_not_to_say"],
                "minority_only": False,
                "minority_communities": None,
                "disability_required": False,
                "course_levels": ["diploma", "ug"],
                "min_marks_percent": None,
                "single_girl_child_required": False,
                "special_conditions": [
                    "Student is a ward of a parent (or both parents) deceased, OR "
                    "a ward of defence / paramilitary personnel martyred in action",
                    "Admission in an AICTE-approved degree or diploma programme",
                    "One award per family per year",
                    "Listed by NSP as a WELFARE-based scheme, so it can be held "
                    "alongside one merit-based scheme from AY 2026–27",
                ],
            },
            "documents": NSP_DOCS + [
                "Death certificate of the parent(s), or",
                "Martyrdom certificate from the defence / paramilitary authority",
                "AICTE-approved institute admission letter",
            ],
            "application": _nsp_application(
                "National Scholarship Portal (AICTE)", "AICTE Swanath Scholarship Scheme"),
            "official_url": NSP,
            "last_verified": TODAY,
            "verification_status": "verified",
            "tags": ["central", "aicte", "welfare", "technical", "orphan", "diploma", "ug"],
            "notes": (
                "Distinct from AICTE Pragati (girl students) and AICTE Saksham "
                "(specially-abled students), which are separate NSP listings. A "
                "student can only hold one AICTE award, but because Swanath is "
                "welfare-based it may be combined with one merit-based scheme "
                "from AY 2026–27."
            ),
        },
        {
            "id": "pm-usp-special-scholarship-jkl",
            "name": "PM USP Special Scholarship Scheme for Jammu & Kashmir and Ladakh",
            "provider": "Ministry of Education (Department of Higher Education) — via NSP",
            "level": "central",
            "summary": (
                "Merit-based scholarship for students domiciled in Jammu & "
                "Kashmir or Ladakh, covering up to ₹3 lakh a year including "
                "medical courses, on the NSP portal."
            ),
            "benefit": {
                "type": "scholarship",
                "amount_annual_inr": 300000,
                "amount_display": "Up to ₹3,00,000 / year (course fee + maintenance)",
                "details": (
                    "Covers tuition and a maintenance allowance; the ceiling is "
                    "highest for medical and other professional programmes."
                ),
            },
            "deadline": {"date": "2026-10-31", "rolling": False,
                         "label": "NSP 2026–27 student deadline — RENEWAL ONLY, confirmed on the official portal"},
            "eligibility": {
                "domicile_states": ["Jammu & Kashmir", "Ladakh"],
                "categories": ["general", "sc", "st", "obc"],
                "max_family_income": 800000,
                "genders": ["male", "female", "other", "prefer_not_to_say"],
                "minority_only": False,
                "minority_communities": None,
                "disability_required": False,
                "course_levels": ["ug", "pg"],
                "min_marks_percent": None,
                "single_girl_child_required": False,
                "special_conditions": [
                    "Domicile of Jammu & Kashmir or Ladakh is mandatory",
                    "RENEWAL ONLY for AY 2026–27 — the official NSP announcement "
                    "names this scheme explicitly as open for renewal applications",
                    "Studying in a professional / technical degree programme in India",
                    CONCURRENCY_RULE,
                ],
            },
            "documents": NSP_DOCS + [
                "Jammu & Kashmir / Ladakh domicile certificate",
                "Previous year's scholarship sanction letter (renewal)",
                "Institute bonafide and fee receipt",
            ],
            "application": _nsp_application(
                "National Scholarship Portal",
                "PM USP Special Scholarship Scheme For Jammu Kashmir And Ladakh"),
            "official_url": NSP_ANNOUNCE,
            "last_verified": TODAY,
            "verification_status": "verified",
            "tags": ["central", "jammu-kashmir", "ladakh", "merit", "renewal", "ug", "pg"],
            "notes": (
                "Verified directly against the NSP Announcements page, which "
                "states: 'Renewal applications for the PM-USP – CSSS and PM USP "
                "Special Scholarship Scheme For Jammu Kashmir And Ladakh is "
                "currently open in NSP. Closing dates for student application is "
                "31-10-2026 and closing date for institute verification is "
                "15-11-2026 and closing date for L2 verification is 30/11/2026.' "
                "First-year students should not assume a fresh window is open."
            ),
        },
        {
            "id": "nfshe-st",
            "name": "National Fellowship and Scholarship for Higher Education of ST Students",
            "provider": "Ministry of Tribal Affairs — via NSP",
            "level": "central",
            "summary": (
                "Replaced the earlier 'Top Class Education for ST Students' "
                "scheme. Supports ST students from Class IX onward through "
                "higher education and research fellowships, up to ₹2.5 lakh a year."
            ),
            "benefit": {
                "type": "scholarship",
                "amount_annual_inr": 250000,
                "amount_display": "Up to ₹2,50,000 / year (course fee + maintenance)",
                "details": (
                    "Tiered by course level: school, higher secondary, UG/PG and "
                    "professional courses each carry a different ceiling, with "
                    "the highest for professional and research programmes."
                ),
            },
            "deadline": {"date": "2026-10-31", "rolling": False,
                         "label": "NSP 2026–27 student deadline"},
            "eligibility": {
                "domicile_states": None,
                "categories": ["st"],
                "max_family_income": 600000,
                "genders": ["male", "female", "other", "prefer_not_to_say"],
                "minority_only": False,
                "minority_communities": None,
                "disability_required": False,
                "course_levels": ["school", "higher_secondary", "iti", "diploma", "ug", "pg", "phd"],
                "min_marks_percent": None,
                "single_girl_child_required": False,
                "special_conditions": [
                    "ST category certificate is mandatory",
                    "Formerly listed on NSP as 'Top Class Education for ST "
                    "Students' — the scheme was renamed and widened to include a "
                    "fellowship component for research students",
                    "Admission in a recognised institution, regular mode",
                    CONCURRENCY_RULE,
                ],
            },
            "documents": NSP_DOCS + [
                "ST caste certificate",
                "Admission letter and fee structure of the institute",
            ],
            "application": _nsp_application(
                "National Scholarship Portal (Ministry of Tribal Affairs)",
                "National Fellowship and Scholarship for Higher Education of ST Students"),
            "official_url": NSP,
            "last_verified": TODAY,
            "verification_status": "pending_review",
            "tags": ["central", "st", "tribal", "fellowship", "scholarship", "school", "ug", "pg", "phd"],
            "notes": (
                "Marked pending_review: the scheme's existence and its "
                "replacement of 'Top Class Education for ST Students' is "
                "confirmed by multiple NSP scheme listings for 2026–27, but the "
                "exact income ceiling and tier-wise amounts should be confirmed "
                "against the Ministry of Tribal Affairs guideline before "
                "relying on them. The 31 Oct 2026 deadline follows the common "
                "NSP 2026–27 student deadline."
            ),
        },
        {
            "id": "free-coaching-sc-obc",
            "name": "Free Coaching for SCs, OBCs and Beneficiaries of the PM Cares Children Scheme",
            "provider": "Department of Social Justice & Empowerment, Ministry of Social Justice & Empowerment",
            "level": "central",
            "summary": (
                "Fully funded coaching for competitive and entrance examinations "
                "— civil services, engineering, medical, law, management and "
                "other professional courses — at empanelled institutes."
            ),
            "benefit": {
                "type": "grant",
                "amount_annual_inr": 0,
                "amount_display": "Coaching fee paid in full, plus hostel and mess charges",
                "details": (
                    "Not a cash scholarship. The ministry pays the empanelled "
                    "coaching institute directly and covers hostel/mess where the "
                    "student is resident. amount_annual_inr is 0 because no cash "
                    "reaches the student."
                ),
            },
            "deadline": {"date": "2026-10-31", "rolling": False,
                         "label": "NSP 2026–27 student deadline (this scheme opened later, on 03-08-2026)"},
            "eligibility": {
                "domicile_states": None,
                "categories": ["sc", "obc", "general"],
                "max_family_income": 800000,
                "genders": ["male", "female", "other", "prefer_not_to_say"],
                "minority_only": False,
                "minority_communities": None,
                "disability_required": False,
                "course_levels": ["higher_secondary", "ug", "pg"],
                "min_marks_percent": None,
                "single_girl_child_required": False,
                "special_conditions": [
                    "SC or OBC candidates, OR beneficiaries of the PM Cares "
                    "Children Scheme — the PM Cares group is why 'general' is "
                    "listed as an eligible category in FeeFix",
                    "Coaching is delivered only at institutes empanelled by the "
                    "ministry; the choice of institute is limited to that list",
                    "Listed by NSP as a WELFARE-based scheme, so it may be held "
                    "alongside one merit-based scheme from AY 2026–27",
                    "A student may avail free coaching for a maximum of two "
                    "attempt-cycles under the scheme",
                ],
            },
            "documents": NSP_DOCS + [
                "SC / OBC caste certificate, or PM Cares Children Scheme sanction letter",
                "Qualifying examination marksheet",
                "Proof of the target examination / course being applied for",
            ],
            "application": _nsp_application(
                "National Scholarship Portal (MoSJE)",
                "Free Coaching For SCs, OBCs And Beneficiaries Of PM Cares Children Scheme"),
            "official_url": NSP,
            "last_verified": TODAY,
            "verification_status": "verified",
            "tags": ["central", "sc", "obc", "coaching", "welfare", "competitive-exams"],
            "notes": (
                "Opened on 3 August 2026, two months after the portal's general "
                "1 June opening, but shares the common 31 October 2026 student "
                "deadline. This is coaching, not cash — a student expecting a "
                "credit in their bank account will be disappointed; the benefit "
                "is a seat at an empanelled institute."
            ),
        },
        {
            "id": "top-class-education-disabilities",
            "name": "Scholarship for Top-Class Education for Students with Disabilities",
            "provider": "Department of Empowerment of Persons with Disabilities (DEPwD), Ministry of Social Justice & Empowerment",
            "level": "central",
            "summary": (
                "Full tuition support plus maintenance for students with "
                "benchmark disabilities (40% or more) studying at notified "
                "top-class institutions."
            ),
            "benefit": {
                "type": "scholarship",
                "amount_annual_inr": 140000,
                "amount_display": "Full tuition + maintenance, up to ~₹1,40,000 / year",
                "details": (
                    "Covers tuition at actuals, a maintenance allowance, and "
                    "support for books, equipment and, where applicable, a "
                    "course-access allowance."
                ),
            },
            "deadline": {"date": "2026-10-31", "rolling": False,
                         "label": "NSP 2026–27 student deadline"},
            "eligibility": {
                "domicile_states": None,
                "categories": ["general", "sc", "st", "obc"],
                "max_family_income": 800000,
                "genders": ["male", "female", "other", "prefer_not_to_say"],
                "minority_only": False,
                "minority_communities": None,
                "disability_required": True,
                "course_levels": ["ug", "pg", "phd"],
                "min_marks_percent": None,
                "single_girl_child_required": False,
                "special_conditions": [
                    "Benchmark disability — 40% or more — certified under the "
                    "Rights of Persons with Disabilities Act, 2016",
                    "Admission at a notified top-class institution (IITs, IIMs, "
                    "AIIMS, NITs, central universities and others on the "
                    "ministry's notified list)",
                    UDID_RULE,
                    "Separate from the Post-Matric Scholarship for Students with "
                    "Disabilities, which is not restricted to notified institutions",
                    CONCURRENCY_RULE,
                ],
            },
            "documents": NSP_DOCS + [
                "UDID card (mandatory — generate it before applying)",
                "Disability certificate showing 40% or more benchmark disability",
                "Admission letter from a notified top-class institution",
            ],
            "application": _nsp_application(
                "National Scholarship Portal (DEPwD)",
                "Scholarship for Top-Class Education for Students with Disabilities"),
            "official_url": NSP,
            "last_verified": TODAY,
            "verification_status": "verified",
            "tags": ["central", "disability", "top-class", "depwd", "ug", "pg", "phd"],
            "notes": (
                "The UDID requirement is new for AY 2026–27 and is a hard "
                "blocker: NSP states that disabled students who have not logged "
                "into the UDID portal and consented to share their UDID details "
                "'will not be able to submit their application'. UDID "
                "certification is a separate process with its own waiting time, "
                "so start it well before the deadline."
            ),
        },
    ]


def main() -> int:
    records = json.loads(PATH.read_text(encoding="utf-8"))
    by_id = {r["id"]: r for r in records}

    # --- 1. remove retired records -----------------------------------------
    removed = []
    for rid in RETIRED:
        if rid in by_id:
            removed.append(rid)
    records = [r for r in records if r["id"] not in RETIRED]
    by_id = {r["id"]: r for r in records}

    # --- 2. apply field updates --------------------------------------------
    for rid, patch in UPDATES.items():
        rec = by_id.get(rid)
        if rec is None:
            print(f"  ! update skipped, no such record: {rid}")
            continue
        patch = dict(patch)
        for key in ("special_conditions_add", "special_conditions_replace"):
            patch.pop(key, None)

        if "application_url" in patch:
            rec["application"]["url"] = patch.pop("application_url")

        for key, value in patch.items():
            rec[key] = value

        src = UPDATES[rid]
        conds = rec["eligibility"].setdefault("special_conditions", [])
        for old, new in (src.get("special_conditions_replace") or {}).items():
            conds[:] = [new if c == old else c for c in conds]
        for extra in src.get("special_conditions_add") or []:
            if extra not in conds:
                conds.append(extra)

        # Every touched record was re-checked today against a named source.
        rec["last_verified"] = TODAY
        rec.setdefault("verification_status", "verified")
        if rec["verification_status"] == "stale":
            rec["verification_status"] = "verified"

    # --- 3. append new records ---------------------------------------------
    added = []
    for rec in new_records():
        if rec["id"] in by_id:
            print(f"  ! add skipped, id already present: {rec['id']}")
            continue
        records.append(rec)
        added.append(rec["id"])

    # --- 4. the AY 2026-27 rule change applies to every NSP scheme ---------
    # Any surviving record that still tells a student they may hold only one
    # scholarship is now wrong, and being wrong here costs a student a second
    # award they are entitled to.
    for rec in records:
        conds = rec["eligibility"].get("special_conditions") or []
        changed = False
        for i, c in enumerate(conds):
            low = c.lower()
            if ("no other scholarship" in low or "only one scholarship" in low
                    or "not already drawing another scholarship" in low):
                conds[i] = CONCURRENCY_RULE
                changed = True
        if changed:
            rec["eligibility"]["special_conditions"] = conds

    ids = [r["id"] for r in records]
    assert len(ids) == len(set(ids)), "duplicate scheme id after refresh"

    PATH.write_text(json.dumps(records, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"national.json: {len(records)} records")
    print(f"  removed  ({len(removed)}): {', '.join(removed) or '—'}")
    print(f"  updated  ({len(UPDATES)}): {', '.join(UPDATES)}")
    print(f"  added    ({len(added)}): {', '.join(added) or '—'}")

    # Emit the retirement ledger for the manifest writer.
    ledger = REPO / "runtime" / "_retired_national.json"
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text(json.dumps(RETIRED, indent=2, ensure_ascii=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
