#!/usr/bin/env python3
"""Apply the verified 2026-27 refresh to every STATE scheme file.

Companion to scripts/refresh_national_2026.py. Same discipline: every change
carries a source, and confidence is encoded in `verification_status` rather than
being flattened into "verified".

THE PROBLEM THIS FIXES
----------------------
Before this pass, 20 of the 58 state records carried a deadline of 2026-11-30,
2026-12-31 or `rolling` that did not correspond to anything the administering
department had published. Several windows had already CLOSED (Maharashtra
30 Sep, Assam 30 Sep, Bihar 30 Sep, Odisha 29 Sep, Karnataka BC 30 Sep), and
four portals had moved to a different domain. A student following this data
would have prepared documents for a deadline that passed weeks ago, or gone to
a URL that is no longer the portal.

POLICY APPLIED
--------------
1. A date confirmed by a recent, scheme-specific source  -> set it,
   `verification_status: verified`.
2. Sources conflict, or the department has published nothing for 2026-27
   -> keep the record but set `pending_review`, and say in `notes` what the
   conflict is. An honest "we don't know" beats a confident wrong date.
3. Portal moved -> update `official_url` and `application.url`, and name the old
   URL in `notes` so a student with a bookmark understands the redirect.
4. Window already closed -> set the REAL (past) date. Do not invent a 2027 date.
   `agents/verify_dataset.py` then flags `deadline_stale`, which is the system
   working as designed: the record surfaces for re-verification when the next
   cycle opens. A past date that is true is more useful than a future date that
   is invented, because it tells the student to prepare for next June instead of
   sending them to a form that does not exist.

Sources retrieved 2026-10-15; see each STATE_SOURCES entry.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "data" / "schemes"
TODAY = "2026-10-15"

#: The AY 2026-27 NSP rule change, which also reaches state schemes that are
#: filed through the National Scholarship Portal.
CONCURRENCY_RULE = (
    "From AY 2026–27 a student may hold ONE merit-based scheme and one or more "
    "welfare-based schemes, per each scheme's eligibility — the older "
    "'one scholarship only' restriction no longer applies"
)

OTR_RULE = (
    "An NSP One Time Registration (OTR) number is now required before the state "
    "portal will accept the application — generate it on scholarships.gov.in "
    "using Aadhaar first, it is not instant"
)

SOURCES = {
    "assam": "buddy4study.com/article/assam-scholarship (2026-09-08): Assam "
             "post-matric SC/OBC close 30 Sep 2026; ST closes 6 Oct 2026; filed "
             "through NSP.",
    "bihar": "shiksha.com (2026-09-11) + fastjobsearchers.com (2026-10-15): "
             "Bihar PMS 2026-27 window 15 Jul - 30 Sep 2026 (extended from "
             "15 Sep). BC/EBC on pmsonline.bihar.gov.in, SC/ST on "
             "scstpmsonline.bihar.gov.in. NSP OTR now required; income "
             "certificate must be dated on/after 01-Apr-2026; Aadhaar seeding "
             "mandatory; max 3 defect corrections each within 15 days.",
    "jharkhand": "ekalyanscholarship.in (2026-08-29) + yojnahub.com (2026-10-09): "
                 "e-Kalyan 2026-27 student application 25 Aug - 20 Nov 2026; "
                 "institute registration 25 Aug - 25 Sep 2026. Portal "
                 "ekalyan.cgg.gov.in confirmed. NSP OTR now mandatory. Income "
                 "ceiling Rs 2,50,000 for ST/SC/BC.",
    "karnataka": "scholarshipscheme.com (2026-09-07): Karnataka SSP 2026-27 - "
                 "Social Welfare Department (SC/ST post-matric) closes "
                 "31 Jan 2027; Backward Classes, Tribal Welfare and Minorities "
                 "Welfare Departments closed 30 Sep 2026.",
    "kerala": "scholarshipscheme.com (2026-09-28) + indiascholarships.in "
              "(2026-09-30): E-Grantz 3.0 last date 30 Nov 2026; Suvarna "
              "Jubilee Merit 30 Nov 2026; C.H. Mohammed Koya 30 Nov 2026. "
              "Portal egrantz.kerala.gov.in confirmed. SC/ST/OEC have no income "
              "ceiling; OBC/general Rs 1,00,000; 75% attendance required.",
    "maharashtra": "careers360.com (2026-10-01) + buddy4study.com (2026-06-23): "
                   "MahaDBT 2026-27 window 1 Jun - 30 Sep 2026, CLOSED. The "
                   "portal moved to MahaDBT 2.0 at mahadbt2.maharashtra.gov.in "
                   "(formerly the Aaple Sarkar portal).",
    "odisha": "buddy4study.com (2026-09-10): Odisha State Scholarship Portal - "
              "Post-Matric closed 29 Sep 2026; Pre-Matric Class IX-X closed "
              "9 Oct 2026; Banishree open to 30 Nov 2026; Nirman Shramik Kalyan "
              "Yojana to 31 Oct 2026; e-Medhabruti Technical/Professional and "
              "PG Merit 'to be announced'.",
    "tamil_nadu": "indiascholarships.in (2026-10-01) + shikshasphere.com "
                  "(checked 2026-10, citing bcw.tn.gov.in): TN BC/MBC/DNC and "
                  "SC/ST post-matric close 30 Nov 2026; Pudhumai Penn and Tamil "
                  "Pudhalvan close 31 Oct 2026; First Graduate Concession closed "
                  "25 Sep 2026. Applications now run through the Unified State "
                  "Scholarship Portal (UMIS) at umis.tn.gov.in. NOTE: "
                  "shikshasphere reports the 2026-27 BC/MBC/DNC window as 'not "
                  "yet notified' on the department page, which conflicts with "
                  "the 30 Nov date - hence pending_review.",
    "uttar_pradesh": "shiksha.com (2026-10-12) + jagranjosh.com (2026-10-14) + "
                     "scholarship.up.in (2026-09-23): UP Scholarship 2026-27 on "
                     "scholarship.up.gov.in. Class 9-12 (Pre-Matric and "
                     "Post-Matric) fresh applications ran 11 Aug - 21 Sep 2026 "
                     "and renewal closed 25 Aug 2026 - both CLOSED. Dashmottar "
                     "(UG, PG, Diploma, ITI and other post-matric) fresh "
                     "applications run 15 Sep - 31 Oct 2026 and renewal "
                     "15 Sep - 15 Oct 2026. Disbursal: Class 9-12 fresh "
                     "25-31 Jan 2027; Dashmottar fresh 27-31 Jan 2027.",
    "west_bengal": "knowscholarship.com (2026-08-07) + agrijob.in (2026-10-12) "
                   "+ careers360.com (2026-08-21) + careerflora.com "
                   "(2026-09-25): OASIS official portal is oasis.wb.gov.in; "
                   "Aikyashree runs on nspwb.wbmdfc.org (WBMDFC also at "
                   "wbmdfc.org) and closes 26 Oct 2026 with post-matric/TSP/MCM/"
                   "SVMCM reported extended to 15 Feb 2027; SVMCM's own portal "
                   "is svmcm.wbhed.gov.in; Nabanna educational assistance is on "
                   "cmrf.wb.gov.in with no fixed deadline (90 days from "
                   "registration to upload documents); Kanyashree is on "
                   "wbkanyashree.gov.in with a 31 Dec 2026 deadline and a "
                   "Rs 1.2 lakh income ceiling.",
}

#: scheme_id -> field patches. ``note`` is appended to any existing notes.
PATCHES: dict[str, dict[str, dict]] = {
    "assam": {
        "assam-postmatric-sc": {
            "deadline": {"date": "2026-09-30", "rolling": False,
                         "label": "Assam 2026–27 window CLOSED on 30 Sep 2026 (filed via NSP)"},
            "status": "verified",
            "note": (
                "The 2026–27 window closed on 30 September 2026. The previous "
                "entry showed 30 November, which was never published by the "
                "department. Assam post-matric applications are filed through "
                "the National Scholarship Portal, so the NSP OTR requirement "
                "applies. Expect the next cycle to open around June 2027 with "
                "the NSP academic year."
            ),
            "add_conditions": [OTR_RULE, CONCURRENCY_RULE],
        },
        "assam-postmatric-obc": {
            "deadline": {"date": "2026-09-30", "rolling": False,
                         "label": "Assam 2026–27 window CLOSED on 30 Sep 2026 (filed via NSP)"},
            "status": "verified",
            "note": (
                "The 2026–27 window closed on 30 September 2026; the ST "
                "post-matric window ran slightly longer, to 6 October 2026. "
                "Filed through NSP, so OTR is required."
            ),
            "add_conditions": [OTR_RULE, CONCURRENCY_RULE],
        },
    },
    "bihar": {
        "bihar-pms-scst": {
            "deadline": {"date": "2026-09-30", "rolling": False,
                         "label": "Bihar PMS 2026–27 CLOSED on 30 Sep 2026 (window was 15 Jul – 30 Sep)"},
            "official_url": "https://scstpmsonline.bihar.gov.in",
            "application_url": "https://scstpmsonline.bihar.gov.in",
            "status": "verified",
            "note": (
                "PORTAL CHANGE: SC/ST post-matric applications now run on "
                "scstpmsonline.bihar.gov.in, separately from the BC/EBC portal. "
                "The 2026–27 window was 15 July to 30 September 2026, extended "
                "from an original 15 September close. New for this cycle: an NSP "
                "OTR number is required to register, the income certificate must "
                "be dated on or after 1 April 2026, academic documents must fall "
                "between 1 April 2026 and 31 March 2027, Aadhaar-bank seeding is "
                "mandatory before the form can be finalised, and a student gets "
                "at most three defect corrections, each within 15 days."
            ),
            "add_conditions": [OTR_RULE,
                               "Income certificate must be dated on or after 1 April 2026",
                               "Aadhaar seeding of the bank account is mandatory — the "
                               "application cannot be finalised without it",
                               "At most three defect corrections, each re-finalised within 15 days"],
        },
        "bihar-pms-obc": {
            "deadline": {"date": "2026-09-30", "rolling": False,
                         "label": "Bihar PMS 2026–27 CLOSED on 30 Sep 2026 (window was 15 Jul – 30 Sep)"},
            "official_url": "https://pmsonline.bihar.gov.in",
            "application_url": "https://pmsonline.bihar.gov.in",
            "status": "verified",
            "note": (
                "PORTAL CHANGE: BC/EBC post-matric applications run on "
                "pmsonline.bihar.gov.in. The legacy pmsonline.bih.nic.in address "
                "is still referenced by older guides. Window was 15 July to "
                "30 September 2026. Same new prerequisites as the SC/ST portal: "
                "NSP OTR, income certificate dated on/after 1 April 2026, and "
                "mandatory Aadhaar-bank seeding."
            ),
            "add_conditions": [OTR_RULE,
                               "Income certificate must be dated on or after 1 April 2026",
                               "Aadhaar seeding of the bank account is mandatory"],
        },
    },
    "jharkhand": {
        "jharkhand-ekalyan-scst": {
            "deadline": {"date": "2026-11-20", "rolling": False,
                         "label": "e-Kalyan 2026–27 student application closes 20 Nov 2026"},
            "status": "verified",
            "note": (
                "Window is 25 August to 20 November 2026 for students; institute "
                "registration ran 25 August to 25 September 2026, so an institute "
                "that missed its own registration cannot verify your form. "
                "Portal ekalyan.cgg.gov.in is confirmed correct. Income ceiling "
                "₹2,50,000 for ST/SC/BC. Helpdesk 1800-599-1289, "
                "+91-8409588101, +91-7258010024 (Mon–Fri 11:00–16:00)."
            ),
            "add_conditions": [OTR_RULE,
                               "Your institute must have completed its own e-Kalyan "
                               "registration (closed 25 Sep 2026) or it cannot verify "
                               "your application"],
        },
        "jharkhand-ekalyan-obc": {
            "deadline": {"date": "2026-11-20", "rolling": False,
                         "label": "e-Kalyan 2026–27 student application closes 20 Nov 2026"},
            "status": "verified",
            "note": "Same e-Kalyan window as the SC/ST component: 25 Aug – 20 Nov 2026.",
            "add_conditions": [OTR_RULE],
        },
        "jharkhand-ekalyan-minority": {
            "deadline": {"date": "2026-11-20", "rolling": False,
                         "label": "e-Kalyan 2026–27 student application closes 20 Nov 2026"},
            "status": "verified",
            "note": "Same e-Kalyan window: 25 Aug – 20 Nov 2026.",
            "add_conditions": [OTR_RULE],
        },
        "jharkhand-ekalyan-outside": {
            "deadline": {"date": "2026-11-20", "rolling": False,
                         "label": "e-Kalyan 2026–27 (outside state) closes 20 Nov 2026"},
            "status": "verified",
            "note": (
                "The 'outside state' component follows the same e-Kalyan window, "
                "25 Aug – 20 Nov 2026. Jharkhand domicile students studying "
                "elsewhere in India apply here rather than in the within-state "
                "component."
            ),
            "add_conditions": [OTR_RULE],
        },
        "marang-gomke-munda-jh": {
            # Not part of the e-Kalyan post-matric schedule; no 2026-27 date
            # published. Keep the record, downgrade honestly.
            "status": "pending_review",
            "note": (
                "Could not be confirmed against a 2026–27 notification in this "
                "review pass. It is administered separately from the e-Kalyan "
                "post-matric schedule (which runs to 20 Nov 2026), so the "
                "2027-03-31 date shown here is carried forward from the previous "
                "cycle and should be treated as unverified. Check "
                "ekalyan.cgg.gov.in or the Jharkhand Tribal Welfare Department "
                "before relying on it."
            ),
        },
    },
    "karnataka": {
        "karnataka-postmatric-scst": {
            "deadline": {"date": "2027-01-31", "rolling": False,
                         "label": "Karnataka SSP 2026–27, Social Welfare Dept (SC/ST) closes 31 Jan 2027"},
            "status": "verified",
            "note": (
                "Karnataka runs two different closing dates in the same academic "
                "year, which is the single most common source of confusion here. "
                "The Social Welfare Department (SC/ST post-matric) closes "
                "31 January 2027. The Backward Classes, Tribal Welfare and "
                "Minorities Welfare Departments closed on 30 September 2026. "
                "Confirm which department administers YOUR course on the SSP "
                "portal before assuming a date."
            ),
        },
        "karnataka-vidyasiri-obc": {
            "deadline": {"date": "2026-09-30", "rolling": False,
                         "label": "Karnataka SSP 2026–27, Backward Classes Dept CLOSED on 30 Sep 2026"},
            "status": "verified",
            "note": (
                "CLOSED. The Backward Classes Department window for 2026–27 "
                "closed on 30 September 2026, three months earlier than the "
                "Social Welfare (SC/ST) window that runs to 31 January 2027. The "
                "previous entry showed 31 December for both, which was wrong for "
                "this one."
            ),
        },
        "karnataka-prize-money-scst": {
            "status": "pending_review",
            "note": (
                "swdoms.karnataka.gov.in could not be confirmed as live during "
                "this review pass, and no 2026–27 notification was located for "
                "the SC/ST prize-money scheme. The 2027-02-28 date is carried "
                "forward from the previous cycle and is unverified."
            ),
        },
        "kmdc-arivu-loan": {
            "status": "pending_review",
            "note": (
                "No 2026–27 notification located for the KMDC Arivu education "
                "loan in this review pass; the 2026-12-15 date is carried "
                "forward and unverified. Arivu is a subsidised LOAN, not a "
                "scholarship — repayment obligations apply."
            ),
        },
        "karnataka-labour-welfare": {
            "status": "pending_review",
            "note": (
                "No 2026–27 notification located for the Karnataka Labour "
                "Welfare Board scholarship in this review pass; the 2026-11-30 "
                "date is carried forward and unverified."
            ),
        },
    },
    "kerala": {
        "kerala-egrantz-scst": {
            "deadline": {"date": "2026-11-30", "rolling": False,
                         "label": "E-Grantz 3.0, 2026–27 closes 30 Nov 2026"},
            "status": "verified",
            "note": (
                "Was recorded as 'rolling', which is wrong — E-Grantz runs an "
                "annual window. The 2026–27 close is 30 November 2026 on the "
                "E-Grantz 3.0 portal (egrantz.kerala.gov.in, confirmed). Note "
                "that individual sub-schemes on the same portal close earlier: "
                "the Kedavilakku scheme closed 30 September 2026, and school "
                "data entry for SC/ST/OBC students closed 31 July 2026, so a "
                "student who waits for the portal deadline can still miss their "
                "own scheme. Income: no ceiling for SC/ST/OEC, ₹1,00,000 for "
                "OBC/general. Minimum 75% attendance."
            ),
            "add_conditions": [
                "Minimum 75% attendance is required",
                "Sub-schemes on the same portal close on different dates — check "
                "your own scheme's window, not just the portal's",
            ],
        },
        "kerala-suvarna-jubilee": {
            "deadline": {"date": "2026-11-30", "rolling": False,
                         "label": "Suvarna Jubilee Merit Scholarship 2026–27 closes 30 Nov 2026"},
            "status": "verified",
            "note": "Deadline confirmed as 30 November 2026 (was 31 October).",
        },
        "ch-muhammedkoya-kl": {
            "deadline": {"date": "2026-11-30", "rolling": False,
                         "label": "C.H. Mohammed Koya Scholarship 2026–27 closes 30 Nov 2026"},
            "status": "verified",
            "note": "30 November 2026 confirmed; administered by the Directorate of Minority Welfare.",
        },
        "kerala-higher-education": {
            "status": "verified",
            "note": (
                "31 October 2026 confirmed for the central-sector scholarship "
                "routed through the Directorate of Collegiate Education."
            ),
        },
        "vidya-samunnathi-kl": {
            "status": "pending_review",
            "note": (
                "kswcfc.org resolves and carries the government UX4G "
                "accessibility widget, but its homepage currently renders "
                "placeholder content ('Add more content here…'), so the scheme "
                "could not be confirmed from the portal itself. The 2026-11-30 "
                "date is carried forward and unverified — contact the Kerala "
                "State Welfare Corporation directly before relying on it."
            ),
        },
    },
    "maharashtra": {
        # All six MahaDBT records share one portal change and one closed window.
        "_all": {
            "deadline": {"date": "2026-09-30", "rolling": False,
                         "label": "MahaDBT 2026–27 CLOSED on 30 Sep 2026 (window was 1 Jun – 30 Sep)"},
            "official_url": "https://mahadbt2.maharashtra.gov.in",
            "application_url": "https://mahadbt2.maharashtra.gov.in",
            "status": "verified",
            "note": (
                "TWO CORRECTIONS. (1) The window closed on 30 September 2026 — "
                "it ran 1 June to 30 September and no extension was announced, "
                "so the 30 November date previously shown here was never "
                "published. (2) The portal moved to MahaDBT 2.0 at "
                "mahadbt2.maharashtra.gov.in (previously the Aaple Sarkar "
                "portal); mahadbt.maharashtra.gov.in is the legacy address. "
                "Eight state departments administer post-matric awards through "
                "it. Maharashtra domicile is required. Expect the next cycle to "
                "open around 1 June 2027."
            ),
        },
    },
    "odisha": {
        "prerana-scst-od": {
            "deadline": {"date": "2026-09-29", "rolling": False,
                         "label": "Odisha Post-Matric 2026–27 CLOSED on 29 Sep 2026"},
            "status": "verified",
            "note": (
                "CLOSED on 29 September 2026 on the Odisha State Scholarship "
                "Portal. The previous entry showed 31 December, which was never "
                "published. The Pre-Matric (Class IX–X) window ran slightly "
                "longer, to 9 October 2026. Bidesh Sikhyabruti closed earlier "
                "still, on 18 September 2026."
            ),
        },
        "prerana-obc-od": {
            "deadline": {"date": "2026-09-29", "rolling": False,
                         "label": "Odisha Post-Matric 2026–27 CLOSED on 29 Sep 2026"},
            "status": "verified",
            "note": "CLOSED on 29 September 2026, same window as the SC/ST post-matric component.",
        },
        "banishree-od": {
            "deadline": {"date": "2026-11-30", "rolling": False,
                         "label": "Banishree Scholarship 2026–27 closes 30 Nov 2026"},
            "status": "verified",
            "note": (
                "Was recorded as 'rolling'; it is an annual window closing "
                "30 November 2026. Administered through the Odisha State "
                "Scholarship Portal for students with disabilities."
            ),
        },
        "medhabruti-od": {
            "status": "pending_review",
            "note": (
                "e-Medhabruti (Technical & Professional, and PG Merit) is listed "
                "by the Odisha portal as 'to be announced' for 2026–27, so the "
                "2026-12-31 date shown here is carried forward from the previous "
                "cycle and is NOT confirmed. Known criteria from the same "
                "listing: family income up to ₹8,00,000 and at least 55% in the "
                "last examination. Watch scholarship.odisha.gov.in for the "
                "notification."
            ),
            "add_conditions": [
                "Family income up to ₹8,00,000 and minimum 55% in the last "
                "examination (per the Odisha portal listing)",
            ],
        },
        "nua-o-scholarship": {
            "status": "pending_review",
            "note": (
                "No 2026–27 notification located in this review pass; the "
                "2027-02-28 date is carried forward and unverified."
            ),
        },
        "kalia-scholarship-od": {
            "status": "pending_review",
            "note": (
                "No 2026–27 notification located in this review pass. The KALIA "
                "scheme's continuation and its scholarship component should be "
                "confirmed on kalia.odisha.gov.in before relying on the "
                "'rolling' designation."
            ),
        },
    },
    "tamil_nadu": {
        "_all": {
            # The state moved to a Unified State Scholarship Portal.
            "official_url": "https://umis.tn.gov.in",
            "application_url": "https://umis.tn.gov.in",
        },
        "tn-postmatric-scst": {
            "deadline": {"date": "2026-11-30", "rolling": False,
                         "label": "TN Post-Matric SC/ST 2026–27 closes 30 Nov 2026"},
            "status": "pending_review",
            "note": (
                "PORTAL CHANGE: Tamil Nadu scholarship applications now run "
                "through the Unified State Scholarship Portal (UMIS) at "
                "umis.tn.gov.in, administered via the department pages at "
                "bcw.tn.gov.in. The legacy tnscholarships.tn.gov.in address was "
                "previously recorded here. Deadline 30 November 2026 comes from "
                "a scheme listing retrieved 2026-10-01; marked pending_review "
                "because a second source checked in October 2026 reported the "
                "2026–27 window as 'not yet notified' on the department page. "
                "Confirm on UMIS before relying on the date. SC/ST post-matric "
                "is administered by the Adi Dravidar and Tribal Welfare "
                "Department."
            ),
        },
        "tn-bcmbc-postmatric": {
            "deadline": {"date": "2026-11-30", "rolling": False,
                         "label": "TN BC/MBC/DNC Post-Matric 2026–27 closes 30 Nov 2026"},
            "status": "pending_review",
            "note": (
                "Same UMIS portal change as the SC/ST record. Two sources "
                "disagree on the income ceiling for BC/MBC/DNC post-matric "
                "(₹2,00,000 in one, ₹2,50,000 in another) and one reports the "
                "2026–27 window as not yet notified, so this is pending_review "
                "rather than verified. BC/MBC/DNC students may also apply "
                "through the National Scholarship Portal."
            ),
        },
        "tn-pudhumai-penn": {
            "deadline": {"date": "2026-10-31", "rolling": False,
                         "label": "Pudhumai Penn 2026–27 closes 31 Oct 2026"},
            "status": "pending_review",
            "note": (
                "Was recorded as 'rolling'; the 2026–27 listing gives "
                "31 October 2026 for Pudhumai Penn (₹12,000) and for the related "
                "Tamil Pudhalvan scheme. Marked pending_review because the date "
                "comes from an aggregator listing rather than a department "
                "notification, and because a genuinely rolling scheme and an "
                "annual one are materially different things to tell a student. "
                "Administered by the Social Welfare and Women Empowerment "
                "Department; portal penkalvi.tn.gov.in."
            ),
        },
        "tn-first-graduate": {
            "status": "pending_review",
            "note": (
                "The First Graduate Concession is an Anna University fee "
                "concession with its own counselling-tied window, reported as "
                "closing 25 September 2026 — not the 30 November scholarship "
                "cycle, and not rolling as previously recorded. It is also a "
                "fee CONCESSION applied at admission rather than a cash award, "
                "so it may not be something a student applies for separately at "
                "all. Confirm with the institution's admissions office."
            ),
        },
        "tn-farmers-scholarship": {
            "status": "pending_review",
            "note": (
                "No 2026–27 notification located in this review pass; the "
                "2026-12-31 date is carried forward and unverified. Also note "
                "the recorded official_url (www.tn.gov.in) is the state's "
                "general portal, not a scheme page — applications run through "
                "UMIS at umis.tn.gov.in."
            ),
        },
    },
    "uttar_pradesh": {
        "up-postmatric-scst": {
            "deadline": {"date": "2026-10-31", "rolling": False,
                         "label": "UP Dashmottar (post-matric) fresh applications close 31 Oct 2026"},
            "status": "verified",
            "note": (
                "Uttar Pradesh runs TWO separate post-matric windows in the same "
                "year and conflating them is the most common mistake here. "
                "(1) Class 11–12 post-matric: fresh applications ran 11 August "
                "to 21 September 2026 and renewals closed 25 August 2026 — both "
                "CLOSED. (2) Dashmottar, covering UG, PG, Diploma, ITI and other "
                "post-matric courses: fresh applications run 15 September to "
                "31 October 2026, renewals 15 September to 15 October 2026. The "
                "date shown is the Dashmottar fresh deadline, which is the one "
                "still open. Portal scholarship.up.gov.in is confirmed correct. "
                "Renewal applicants must complete DigiLocker and OTP "
                "authentication and LOCK the application — an unlocked form is "
                "not submitted. Disbursal for Dashmottar fresh is 27–31 January "
                "2027. Scheme notifications for both were issued 20 July 2026 by "
                "the Social Welfare Department."
            ),
            "add_conditions": [
                "Applications must be LOCKED after submission — an unlocked form "
                "is not treated as submitted",
                "DigiLocker and OTP authentication are part of the submission flow",
                "Class 11–12 post-matric closed on 21 Sep 2026; only Dashmottar "
                "(UG/PG/Diploma/ITI) remains open to 31 Oct 2026",
            ],
        },
        "up-postmatric-obc-general": {
            "deadline": {"date": "2026-10-31", "rolling": False,
                         "label": "UP Dashmottar (post-matric) fresh applications close 31 Oct 2026"},
            "status": "verified",
            "note": (
                "Same two-window structure as the SC/ST record: Class 11–12 "
                "closed 21 September 2026, Dashmottar (UG/PG/Diploma/ITI) fresh "
                "runs to 31 October 2026 with renewal closing 15 October 2026. "
                "Administered by the Backward Classes Welfare Department "
                "alongside the Social Welfare and Minority Welfare Departments."
            ),
            "add_conditions": [
                "Applications must be LOCKED after submission — an unlocked form "
                "is not treated as submitted",
            ],
        },
        "up-prematric": {
            "deadline": {"date": "2026-09-21", "rolling": False,
                         "label": "UP Pre-Matric (Class 9–10) 2026–27 CLOSED on 21 Sep 2026"},
            "status": "verified",
            "note": (
                "CLOSED. Fresh applications for Class 9–10 ran 11 August to "
                "21 September 2026; renewal applications closed earlier, on "
                "25 August 2026. The previously recorded 30 November date was "
                "never published. Hard copies had to reach the institution "
                "between 16 September and 4 November 2026. Disbursal for Class "
                "9–12 fresh applications is scheduled 25–31 January 2027. Expect "
                "the next cycle to open around August 2027."
            ),
        },
        "kanya-sumangala-up": {
            "status": "pending_review",
            "note": (
                "No 2026–27 notification located in this review pass; the "
                "'rolling' designation is carried forward and unverified. "
                "Kanya Sumangala is a conditional cash transfer paid in instalments "
                "tied to birth, school enrolment and age milestones rather than an "
                "annual scholarship application, which is why it does not follow "
                "the scholarship.up.gov.in cycle — applications are filed on "
                "mksy.up.gov.in. Confirm the current instalment schedule there."
            ),
        },
        "rani-laxmibai-kosh-up": {
            "status": "pending_review",
            "note": (
                "No 2026–27 notification located in this review pass; the "
                "'rolling' designation is carried forward and unverified. Portal "
                "mahilakalyan.up.nic.in is the Women's Welfare department site "
                "rather than a scheme-specific application page."
            ),
        },
        "cm-abhyudaya-up": {
            "status": "pending_review",
            "note": (
                "No 2026–27 notification located in this review pass; the "
                "'rolling' designation is carried forward and unverified. "
                "Abhyudaya is primarily a free-coaching scheme for competitive "
                "examinations, so like the central Free Coaching scheme its "
                "benefit is a seat at a centre rather than a cash award."
            ),
        },
    },
    "west_bengal": {
        "sv-mcm-wb": {
            "official_url": "https://svmcm.wbhed.gov.in",
            "application_url": "https://svmcm.wbhed.gov.in",
            "deadline": {"date": "2026-12-31", "rolling": False,
                         "label": "SVMCM renewal closes 31 Dec 2026; fresh window not yet announced"},
            "status": "pending_review",
            "note": (
                "PORTAL CHANGE: SVMCM's own portal is svmcm.wbhed.gov.in (Higher "
                "Education Department), not the svmcm.wb.gov.in previously "
                "recorded. SVMCM applications are ALSO taken on the Aikyashree "
                "NSP-WB portal at nspwb.wbmdfc.org, so there are two valid entry "
                "points and they have different windows. The 31 December 2026 "
                "date applies to RENEWAL applications; the fresh-application "
                "deadline was not announced at the time of this review, and the "
                "2025–26 window was reopened for SVMCM fresh and renewal 'until "
                "further notice'. Marked pending_review because a renewal-only "
                "date is not a usable deadline for a first-year student."
            ),
        },
        "aikyashree-wb": {
            "official_url": "https://nspwb.wbmdfc.org",
            "application_url": "https://nspwb.wbmdfc.org",
            "deadline": {"date": "2026-10-26", "rolling": False,
                         "label": "Aikyashree 2026–27 closes 26 Oct 2026 (extension to 15 Feb 2027 reported for some schemes)"},
            "status": "verified",
            "note": (
                "PORTAL CHANGE: Aikyashree now runs on the NSP-WB portal at "
                "nspwb.wbmdfc.org, operated by the West Bengal Minorities' "
                "Development & Finance Corporation for the Minority Affairs and "
                "Madrasah Education Department. The previously recorded "
                "wbmdfcscholarship.gov.in is not the current portal; WBMDFC's "
                "own site is wbmdfc.org. The 2026–27 window opened 1 August 2026 "
                "and closes 26 October 2026 for Pre-Matric, Post-Matric, MCM and "
                "SVMCM (fresh and renewal); several college notices report an "
                "extension to 15 February 2027 for Post-Matric, TSP, MCM and "
                "SVMCM, so confirm on the portal. Income ceiling ₹2,00,000 for "
                "Pre/Post-Matric and ₹2,50,000 for MCM, with 50% minimum marks. "
                "Helpline 1800-120-2130 (toll free) or 033-4004-7468."
            ),
        },
        "oasis-sc-st-wb": {
            "official_url": "https://oasis.wb.gov.in",
            "application_url": "https://oasis.wb.gov.in",
            "status": "pending_review",
            "note": (
                "PORTAL CHANGE: the official OASIS portal is oasis.wb.gov.in "
                "(Backward Classes Welfare Department), not the oasis.gov.in "
                "previously recorded. OASIS consolidates seven separate "
                "scholarship schemes for SC, ST and OBC students from Class 5 to "
                "PhD. Marked pending_review on the DEADLINE: the portal homepage "
                "does not publish a fixed closing date for 2026–27 and simply "
                "shows applications as open, so the 30 November date here is "
                "carried forward rather than confirmed. One source quotes "
                "31 October 2026, another 31 March 2026. ST students must "
                "generate an NSP OTR number first. Helpline +91 84200 23311."
            ),
            "add_conditions": [
                "ST students must generate an NSP OTR number on "
                "scholarships.gov.in before the OASIS application will be accepted",
            ],
        },
        "oasis-obc-wb": {
            "official_url": "https://oasis.wb.gov.in",
            "application_url": "https://oasis.wb.gov.in",
            "status": "pending_review",
            "note": "Same OASIS portal change and same unpublished-deadline caveat as the SC/ST record.",
        },
        "oasis-pre-sc-wb": {
            "official_url": "https://oasis.wb.gov.in",
            "application_url": "https://oasis.wb.gov.in",
            "status": "pending_review",
            "note": (
                "Same OASIS portal change. Pre-Matric SC/ST covers Class 9–10 at "
                "₹150/month for day scholars and ₹750/month for hostellers, plus "
                "tuition reimbursement, with a ₹2,50,000 family income ceiling. "
                "Deadline unpublished on the portal, hence pending_review."
            ),
        },
        "nabanna-wb": {
            "official_url": "https://cmrf.wb.gov.in",
            "application_url": "https://cmrf.wb.gov.in",
            "status": "verified",
            "note": (
                "PORTAL CHANGE: Nabanna educational assistance is applied for on "
                "cmrf.wb.gov.in — the Chief Minister's Relief Fund — under the "
                "button 'Apply For Financial Assistance for Education'. The "
                "previously recorded wbcmo.gov.in is the Chief Minister's Office "
                "site, not the application portal. 'Rolling' is CORRECT here: "
                "the portal publishes no fixed last date, and once registered a "
                "student has 90 days to upload documents and submit. Eligibility "
                "is deliberately narrow — above 50% but BELOW 60% in the last "
                "examination (below 53% for PG), i.e. it targets students who "
                "miss merit scholarships — with a ₹1,20,000 family income "
                "ceiling. The award is widely reported as around ₹10,000 but the "
                "portal publishes no fixed rate chart."
            ),
        },
        "kanyashree-k2": {
            "official_url": "https://wbkanyashree.gov.in",
            "application_url": "https://wbkanyashree.gov.in",
            "deadline": {"date": "2026-12-31", "rolling": False,
                         "label": "Kanyashree K1/K2 applications close 31 Dec 2026"},
            "status": "verified",
            "note": (
                "Was recorded as 'rolling'. Applications are accepted throughout "
                "the academic year but CLOSE on 31 December 2026, and late "
                "submissions are not accepted — so 'rolling' understated a real "
                "deadline. K1 is ₹1,000/year for unmarried girls aged 13–18 in "
                "Class 8–12; K2 is a ₹25,000 one-time grant for unmarried women "
                "aged 18+ in higher education. Family income ceiling ₹1,20,000. "
                "Applications may be filed through the school or college as well "
                "as online. Contact support.kanyashree@wb.gov.in."
            ),
            "add_conditions": [
                "Applicant must be UNMARRIED — marriage disqualifies",
                "Family income up to ₹1,20,000 per year",
            ],
        },
        "wbfs-freeship-wb": {
            "status": "pending_review",
            "note": (
                "No 2026–27 notification located in this review pass; the "
                "2026-11-15 date is carried forward and unverified. Portal "
                "wbhed.gov.in (Higher Education Department) is the department "
                "site rather than a scheme-specific application page."
            ),
        },
        "hindi-scholarship-wb": {
            "status": "pending_review",
            "note": (
                "No 2026–27 notification located in this review pass; the "
                "2026-12-15 date is carried forward and unverified. school.wb.gov.in "
                "is the School Education Department portal, not a scheme page."
            ),
        },
    },
}


def apply_patch(rec: dict, patch: dict) -> bool:
    """Apply one patch to one record. Returns True if anything changed."""
    changed = False

    if "deadline" in patch:
        if rec.get("deadline") != patch["deadline"]:
            rec["deadline"] = dict(patch["deadline"])
            changed = True

    for key in ("official_url",):
        if key in patch and rec.get(key) != patch[key]:
            rec[key] = patch[key]
            changed = True
    if "application_url" in patch and rec["application"].get("url") != patch["application_url"]:
        rec["application"]["url"] = patch["application_url"]
        changed = True

    if "status" in patch and rec.get("verification_status") != patch["status"]:
        rec["verification_status"] = patch["status"]
        changed = True

    if "note" in patch:
        note = patch["note"].strip()
        existing = (rec.get("notes") or "").strip()
        # Replace rather than append: these notes supersede the old ones, and
        # stacking both would leave contradictory text in the record.
        if existing != note:
            rec["notes"] = note
            changed = True

    for cond in patch.get("add_conditions") or []:
        conds = rec["eligibility"].setdefault("special_conditions", [])
        if cond not in conds:
            conds.append(cond)
            changed = True

    # Any record touched today was re-checked today.
    if changed:
        rec["last_verified"] = TODAY
    return changed


def main() -> int:
    report = []
    for state_file, patches in PATCHES.items():
        path = DATA / f"{state_file}.json"
        records = json.loads(path.read_text(encoding="utf-8"))
        by_id = {r["id"]: r for r in records}
        shared = patches.get("_all", {})
        touched = 0

        for rec in records:
            merged = dict(shared)
            merged.update(patches.get(rec["id"], {}))
            # A per-record patch wins on scalar keys; conditions accumulate.
            if rec["id"] in patches and "_all" in patches:
                both = list((shared.get("add_conditions") or [])) + \
                       list((patches[rec["id"]].get("add_conditions") or []))
                if both:
                    merged["add_conditions"] = both
            if not merged:
                continue
            if apply_patch(rec, merged):
                touched += 1

        ids = [r["id"] for r in records]
        assert len(ids) == len(set(ids)), f"duplicate id in {state_file}.json"
        path.write_text(json.dumps(records, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
        report.append((state_file, len(records), touched))

    print(f"{'file':<16} {'records':>8} {'changed':>8}")
    for name, n, t in report:
        print(f"{name:<16} {n:>8} {t:>8}")
    print(f"{'TOTAL':<16} {sum(r[1] for r in report):>8} {sum(r[2] for r in report):>8}")

    # Emit the source ledger for the manifest writer.
    ledger = REPO / "runtime" / "_state_sources.json"
    ledger.write_text(json.dumps(SOURCES, indent=2, ensure_ascii=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
