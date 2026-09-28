"""Multilingual chat strings + script detection for the reach layer.

V3 intent: a student who types Bengali gets the entire conversation in
Bengali — questions, prompts, and the match summary — while the matching
engine stays language-neutral. Detection is script-based (reliable and free).
"""

from __future__ import annotations

import re

BN_RE = re.compile(r"[ঀ-৿]")
HI_RE = re.compile(r"[ऀ-ॿ]")
TA_RE = re.compile(r"[஀-௿]")
BN_DIGITS = str.maketrans("০১২৩৪৫৬৭৮৯", "0123456789")
HI_DIGITS = str.maketrans("०१२३४५६७८९", "0123456789")


def detect_lang(text: str) -> str:
    if BN_RE.search(text):
        return "bn"
    if HI_RE.search(text):
        return "hi"
    if TA_RE.search(text):
        return "ta"
    return "en"


def normalize_digits(text: str) -> str:
    return text.translate(BN_DIGITS).translate(HI_DIGITS)


STR = {
    "en": {
        "welcome": (
            "👋 Welcome to *FeeFix* — I find scholarships and fee waivers you qualify for, "
            "in 3 questions.\n\n*Question 1 of 3:* Which state do you live in (domicile)?"
        ),
        "state_retry": "I couldn't recognise that state. Try e.g. *West Bengal* or *Bihar*.",
        "q2": ("✅ Noted: *{state}*.\n\n*Question 2 of 3:* What are you studying? "
               "(e.g. Class 10, HS, ITI, Diploma, B.Tech/UG, M.Sc/PG, PhD)"),
        "course_retry": "Hmm — say something like *B.Tech*, *Class 12*, *ITI*, *Diploma*, or *MSc*.",
        "q3": ("✅ Got it: *{course}*.\n\n*Question 3 of 3:* What is your approximate annual "
               "family income? (e.g. ₹2,00,000 or '2 lakh')"),
        "income_retry": "Please give a number — like *₹1,50,000* or *2.5 lakh*.",
        "header": "🎯 *{n} schemes match your profile.*",
        "rolling": "rolling",
        "days_left": "{n} days left",
        "tail": ("\nOn the FeeFix site you can add category, marks, gender and minority details "
                 "to refine these results — and track every application. Ask me anything now "
                 "(e.g. \"what documents do these need?\") — or type *restart*."),
        "fresh": "Let's start fresh! ",
    },
    "bn": {
        "welcome": (
            "👋 *FeeFix*-এ স্বাগতম — ৩টি প্রশ্নের উত্তর দিন, আপনার যোগ্য বৃত্তি ও ফি-মওকুফ খুঁজে দেব।\n\n"
            "*প্রশ্ন ১ / ৩:* আপনার অধিবাস কোন রাজ্যে?"
        ),
        "state_retry": "রাজ্যটি চিনতে পারলাম না। যেমন লিখুন: *পশ্চিমবঙ্গ* বা *বিহার*।",
        "q2": ("✅ ঠিক আছে: *{state}*।\n\n*প্রশ্ন ২ / ৩:* আপনি এখন কী পড়ছেন? "
               "(যেমন: ক্লাস ১০, HS, ITI, ডিপ্লোমা, B.Tech/স্নাতক, MSc/PG, PhD)"),
        "course_retry": "বুঝতে পারিনি — যেমন লিখুন: *বি.টেক*, *ক্লাস ১২*, *আইটিআই*, *ডিপ্লোমা* বা *এমএসসি*।",
        "q3": ("✅ নোট করলাম: *{course}*।\n\n*প্রশ্ন ৩ / ৩:* আপনার আনুমানিক বার্ষিক পারিবারিক আয় কত? "
               "(যেমন: ₹2,00,000 বা '২ লাখ')"),
        "income_retry": "একটি সংখ্যা লিখুন — যেমন *₹1,50,000* বা *২.৫ লাখ*।",
        "header": "🎯 *আপনার প্রোফাইলের সাথে {n}টি প্রকল্প মিলেছে।*",
        "rolling": "সারা বছর খোলা",
        "days_left": "{n} দিন বাকি",
        "tail": ("\nFeeFix ওয়েবসাইটে ক্যাটাগরি, নম্বর, লিঙ্গ ও সংখ্যালঘু তথ্য যোগ করে ফলাফল আরও "
                 "নিখুঁত করতে পারবেন — আর প্রতিটি আবেদন ট্র্যাক করতে পারবেন। এখন যেকোনো প্রশ্ন করুন "
                 "(যেমন: \"কী কী নথি লাগবে?\") — বা *restart* লিখুন।"),
        "fresh": "চলুন আবার শুরু করি! ",
    },
    "hi": {
        "welcome": (
            "👋 *FeeFix* में स्वागत है — 3 सवालों के जवाब दीजिए, मैं आपकी योग्यता की छात्रवृत्ति और "
            "फ़ीस-माफ़ी ढूँढ दूँगा।\n\n*प्रश्न 1 / 3:* आपका अधिवास किस राज्य में है?"
        ),
        "state_retry": "राज्य समझ नहीं आया। जैसे लिखें: *पश्चिम बंगाल* या *बिहार*।",
        "q2": ("✅ नोट किया: *{state}*।\n\n*प्रश्न 2 / 3:* आप अभी क्या पढ़ रहे हैं? "
               "(जैसे: कक्षा 10, HS, ITI, डिप्लोमा, B.Tech/स्नातक, MSc/PG, PhD)"),
        "course_retry": "समझ नहीं आया — जैसे लिखें: *बी.टेक*, *कक्षा 12*, *ITI*, *डिप्लोमा* या *MSc*।",
        "income_retry": "कृपया एक संख्या लिखें — जैसे *₹1,50,000* या *2.5 लाख*।",
        "q3": ("✅ समझ गया: *{course}*।\n\n*प्रश्न 3 / 3:* आपकी अनुमानित वार्षिक पारिवारिक आय कितनी है? "
               "(जैसे: ₹2,00,000 या '2 लाख')"),
        "header": "🎯 *आपकी प्रोफ़ाइल से {n} योजनाएँ मेल खाती हैं।*",
        "rolling": "पूरे साल खुला",
        "days_left": "{n} दिन शेष",
        "tail": ("\nFeeFix वेबसाइट पर श्रेणी, अंक, लिंग और अल्पसंख्यक विवरण जोड़कर परिणाम और बेहतर "
                 "बनाए जा सकते हैं — और हर आवेदन ट्रैक किया जा सकता है। अब कुछ भी पूछिए "
                 "(जैसे: \"कौन से दस्तावेज़ चाहिए?\") — या *restart* लिखें।"),
        "fresh": "चलिए फिर से शुरू करते हैं! ",
    },
    "ta": {
        "welcome": (
            "👋 *FeeFix*-க்கு வரவேற்கிறோம் — 3 கேள்விகளுக்குப் பதிலளியுங்கள், "
            "நீங்கள் தகுதிபெறும் உதவித்தொகைகளையும் கட்டண மாற்றுகளையும் கண்டுபிடிக்கிறேன்.\n\n"
            "*கேள்வி 1 / 3:* உங்கள் குடியிருப்பு எந்த மாநிலம்?"
        ),
        "state_retry": "மாநிலம் புரியவில்லை. எ.கா.: *தமிழ்நாடு* அல்லது *கேரளா* என எழுதுங்கள்.",
        "q2": ("✅ குறித்துவிட்டேன்: *{state}*.\n\n*கேள்வி 2 / 3:* நீங்கள் என்ன படித்துக்கொண்டிருக்கிறீர்கள்? "
               "(எ.கா.: வகுப்பு 10, +2, ITI, டிப்ளமோ, B.Tech/UG, MSc/PG, PhD)"),
        "course_retry": "புரியவில்லை — எ.கா.: *B.Tech*, *வகுப்பு 12*, *ITI*, *டிப்ளமோ* அல்லது *MSc* என எழுதுங்கள்.",
        "q3": ("✅ புரிந்தது: *{course}*.\n\n*கேள்வி 3 / 3:* உங்கள் சராசரி ஆண்டு குடும்ப வருமானம் எவ்வளவு? "
               "(எ.கா.: ₹2,00,000 அல்லது '2 லட்சம்')"),
        "income_retry": "ஒரு எண்ணை எழுதுங்கள் — எ.கா.: *₹1,50,000* அல்லது *2.5 லட்சம்*.",
        "header": "🎯 *உங்கள் விவரத்துடன் {n} திட்டங்கள் பொருந்துகின்றன.*",
        "rolling": "ஆண்டு முழுவதும் திறந்தது",
        "days_left": "{n} நாட்கள் மீதம்",
        "tail": ("\nFeeFix இணையதளத்தில் பிரிவு, மதிப்பெண், பாலினம் மற்றும் சிறுபான்மை விவரங்களைச் "
                 "சேர்த்து முடிவுகளை மேலும் செம்மைப்படுத்தலாம் — ஒவ்வொரு விண்ணப்பத்தையும் "
                 "கண்காணிக்கலாம். இப்போது எதுவும் கேளுங்கள் "
                 "(எ.கா.: \"என்ன ஆவணங்கள் தேவை?\") — அல்லது *restart* என எழுதுங்கள்."),
        "fresh": "மீண்டும் தொடங்குவோம்! ",
    },
}


def tr(lang: str, key: str, **slots) -> str:
    tpl = STR.get(lang, STR["en"]).get(key, STR["en"][key])
    return tpl.format(**slots) if slots else tpl
