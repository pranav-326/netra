"""Origin clues other than IP addresses (Layer 3).

Extracts location evidence carried by the email itself (bank details, phone numbers,
the sender's clock, writing language, the sender's country domain) and combines it
into a probable country with an honest confidence.

Every clue says what it actually locates. An IBAN locates the bank account the money
goes to, which may belong to a money mule rather than the sender; a phone number
locates where the number is registered, which for VoIP says little about the caller.
The assessment keeps those distinctions visible instead of collapsing them into one
confident pin on a map. Location is not evidence of maliciousness, so nothing here
adds risk points.
"""

import re
from collections import defaultdict
from datetime import datetime
from email.utils import parseaddr, parsedate_to_datetime
from functools import lru_cache
from typing import Dict, List, Optional, Tuple

import phonenumbers
import pytz
from phonenumbers import PhoneNumberType, geocoder

from netra_common.models.email import LocationClue, OriginAnalysisResult, OriginAssessment

from .content_engine import strip_html_tags

MAX_TEXT_CHARS = 200_000
MAX_PHONES = 5
WEIGHT = {"strong": 3.0, "medium": 2.0, "weak": 0.5}

# An IBAN and a SWIFT code for the same account are one piece of evidence, not two.
CATEGORY = {"iban": "payment", "swift": "payment", "phone": "phone", "timezone": "timezone",
            "language": "language", "sender_domain": "sender_domain"}

# Official IBAN length per country (SWIFT IBAN registry). The length check plus the
# mod-97 checksum keeps random alphanumeric strings from passing as bank accounts.
IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29,
    "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29,
    "ES": 24, "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28,
    "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20,
    "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MD": 24, "ME": 22, "MK": 19,
    "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29,
    "RO": 24, "RS": 22, "SA": 24, "SC": 31, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25, "SV": 28,
    "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}
IBAN_CANDIDATE = re.compile(r"\b([A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?)\b")

# Only after the words SWIFT or BIC: otherwise ordinary words such as "INVOICES"
# (IN = India) read as bank codes.
SWIFT_IN_CONTEXT = re.compile(
    r"\b(?:swift|bic)(?:\s*(?:/|or|-)\s*(?:swift|bic))?(?:\s*code)?\s*(?:no\.?|number|#)?\s*[:\-]?\s*"
    r"([A-Za-z]{6}[A-Za-z0-9]{2}(?:[A-Za-z0-9]{3})?)\b", re.I)

# Numbers written for a domestic audience only count when they look like phone numbers:
# a bare run of digits is more often an order or invoice number.
PHONE_SEPARATORS = re.compile(r"[\s\-.()]")
NANP_REGIONS = frozenset(phonenumbers.COUNTRY_CODE_TO_REGION_CODE.get(1, ()))
NON_GEOGRAPHIC = {PhoneNumberType.TOLL_FREE, PhoneNumberType.PREMIUM_RATE, PhoneNumberType.SHARED_COST,
                  PhoneNumberType.UAN, PhoneNumberType.PERSONAL_NUMBER}

# Two-letter domains sold worldwide as brand names rather than used by their country.
GENERIC_CCTLDS = {"io", "co", "me", "tv", "ai", "cc", "ws", "fm", "am", "ly", "gg", "to", "sh", "la", "nu",
                  "tk", "ml", "ga", "cf", "gq", "vc", "ac", "so", "gl", "sx", "bz", "cx", "st", "vg", "pw", "su"}

SCRIPTS = [  # (language key, display name, character range)
    ("ja", "Japanese", "぀-ヿ"), ("ko", "Korean", "가-힯"),
    ("zh", "Chinese", "一-鿿"), ("cyrillic", "Cyrillic-script language", "Ѐ-ӿ"),
    ("ar", "Arabic", "؀-ۿ"), ("hi", "Hindi", "ऀ-ॿ"), ("th", "Thai", "฀-๿"),
    ("he", "Hebrew", "֐-׿"), ("el", "Greek", "Ͱ-Ͽ"),
]
STOPWORDS = {
    "en": {"the", "and", "you", "your", "is", "are", "to", "of", "for", "with", "this", "that", "please", "have"},
    "es": {"el", "la", "los", "las", "que", "y", "en", "por", "para", "con", "su", "usted", "cuenta", "una", "del", "al"},
    "pt": {"o", "os", "que", "não", "para", "com", "sua", "seu", "você", "uma", "do", "da", "dos", "das", "em", "conta"},
    "fr": {"le", "les", "des", "et", "est", "vous", "votre", "pour", "avec", "une", "du", "dans", "sur", "pas"},
    "de": {"der", "die", "das", "und", "ist", "sie", "ihr", "ihre", "nicht", "mit", "für", "ein", "eine", "den", "bitte"},
    "it": {"il", "lo", "gli", "di", "che", "per", "con", "una", "della", "sono", "non", "suo", "tuo", "grazie"},
    "nl": {"het", "een", "van", "niet", "uw", "voor", "met", "op", "te", "dit", "u", "wij"},
    "tr": {"ve", "bir", "bu", "için", "ile", "lütfen", "değil", "hesabınız", "sizin"},
    "id": {"dan", "yang", "anda", "untuk", "dengan", "ini", "dari", "akun", "tidak", "kami"},
}
LANGUAGE_NAMES = {"es": "Spanish", "pt": "Portuguese", "fr": "French", "de": "German", "it": "Italian",
                  "nl": "Dutch", "tr": "Turkish", "id": "Indonesian"}
LANGUAGE_COUNTRIES = {
    "es": ["ES", "MX", "AR", "CO", "PE", "VE", "CL", "EC", "GT", "CU", "BO", "DO", "HN", "PY", "SV", "NI", "CR", "PA", "UY"],
    "pt": ["BR", "PT", "AO", "MZ"], "fr": ["FR", "BE", "CH", "CA", "SN", "CI", "CM", "MA", "TN", "DZ", "CD"],
    "de": ["DE", "AT", "CH"], "it": ["IT", "CH"], "nl": ["NL", "BE", "SR"], "tr": ["TR", "CY"], "id": ["ID"],
    "ja": ["JP"], "ko": ["KR"], "zh": ["CN", "TW", "HK", "SG"], "cyrillic": ["RU", "UA", "BY", "KZ", "BG", "RS"],
    "ar": ["SA", "AE", "EG", "MA", "DZ", "IQ", "JO", "KW", "QA", "LB", "TN", "OM"], "hi": ["IN"], "th": ["TH"],
    "he": ["IL"], "el": ["GR", "CY"],
}


def country_name(code: str) -> str:
    return pytz.country_names.get(code.upper(), code.upper())


def _names(codes: List[str], limit: int = 4) -> str:
    shown = ", ".join(country_name(c) for c in codes[:limit])
    return shown + (f" and {len(codes) - limit} more" if len(codes) > limit else "")


# ---------------------------------------------------------------------------
# Payment details
# ---------------------------------------------------------------------------

def _iban_checksum_ok(iban: str) -> bool:
    rearranged = iban[4:] + iban[:4]
    try:
        return int("".join(str(int(ch, 36)) for ch in rearranged)) % 97 == 1
    except ValueError:
        return False


def find_ibans(text: str) -> List[LocationClue]:
    clues, seen = [], set()
    for match in IBAN_CANDIDATE.finditer(text.upper()):
        compact = match.group(1).replace(" ", "")
        length = IBAN_LENGTHS.get(compact[:2])
        if not length or len(compact) < length:
            continue
        iban = compact[:length]
        if iban in seen or not _iban_checksum_ok(iban):
            continue
        seen.add(iban)
        cc = iban[:2]
        clues.append(LocationClue(
            kind="iban", measures="payment destination (bank account)",
            value=f"{iban[:4]} •••• {iban[-4:]}", countries=[cc], region=country_name(cc), strength="strong",
            note="Where the money goes: often a money-mule account rather than the sender's own.",
        ))
    return clues


def find_swift_codes(text: str) -> List[LocationClue]:
    clues, seen = [], set()
    for match in SWIFT_IN_CONTEXT.finditer(text):
        code = match.group(1).upper()
        cc = code[4:6]
        if code in seen or cc not in pytz.country_names:
            continue
        seen.add(code)
        clues.append(LocationClue(
            kind="swift", measures="payment destination (bank)", value=code, countries=[cc],
            region=country_name(cc), strength="strong",
            note="The receiving bank's country: where the money goes, not necessarily the sender.",
        ))
    return clues


# ---------------------------------------------------------------------------
# Phone numbers
# ---------------------------------------------------------------------------

def find_phones(text: str) -> List[LocationClue]:
    numbers, seen = [], set()
    for region in (None, "US"):  # international format first, then North American style
        for match in phonenumbers.PhoneNumberMatcher(text, region, leniency=phonenumbers.Leniency.VALID):
            raw = match.raw_string.strip()
            if region and not (raw.startswith("+") or PHONE_SEPARATORS.search(raw)):
                continue
            e164 = phonenumbers.format_number(match.number, phonenumbers.PhoneNumberFormat.E164)
            if e164 not in seen:
                seen.add(e164)
                numbers.append((raw, match.number))
    clues = []
    for raw, number in numbers[:MAX_PHONES]:
        cc = phonenumbers.region_code_for_number(number)
        kind = phonenumbers.number_type(number)
        pretty = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        if kind in NON_GEOGRAPHIC and cc in NANP_REGIONS:
            clues.append(LocationClue(kind="phone", measures="contact phone number", value=pretty, countries=[],
                                      strength="weak", note="North American toll-free or special number: carries no location."))
            continue
        place = geocoder.description_for_number(number, "en") or country_name(cc)
        note = None
        if kind == PhoneNumberType.VOIP:
            note = "VoIP number: can be used from anywhere."
        elif kind in NON_GEOGRAPHIC:
            note = "Non-geographic number: indicates the country only."
        clues.append(LocationClue(kind="phone", measures="contact phone number", value=pretty, countries=[cc],
                                  region=place, strength="medium", note=note))
    return clues


# ---------------------------------------------------------------------------
# The sender's clock
# ---------------------------------------------------------------------------

# Territories with no resident senders; pytz lists timezones for them.
UNINHABITED = {"AQ", "BV", "HM", "UM", "TF", "GS", "IO"}


@lru_cache(maxsize=512)
def countries_with_offset(offset_minutes: int, year: int, month: int) -> Tuple[str, ...]:
    """Countries with a timezone at this UTC offset in that month (daylight saving included)."""
    moment = datetime(year, month, 15, 12)
    found = set()
    for cc, zones in pytz.country_timezones.items():
        if cc in UNINHABITED:
            continue
        for zone in zones:
            try:
                offset = pytz.timezone(zone).localize(moment).utcoffset()
            except Exception:
                continue
            if offset is not None and int(offset.total_seconds() // 60) == offset_minutes:
                found.add(cc)
                break
    return tuple(sorted(found))


def find_timezone(date_header: Optional[str]) -> List[LocationClue]:
    if not date_header:
        return []
    try:
        sent = parsedate_to_datetime(date_header)
    except (TypeError, ValueError, IndexError):
        return []
    if sent is None or sent.tzinfo is None:  # "-0000" means the sender's zone is unknown
        return []
    minutes = int(sent.utcoffset().total_seconds() // 60)
    sign = "+" if minutes >= 0 else "-"
    label = f"UTC{sign}{abs(minutes) // 60:02d}:{abs(minutes) % 60:02d}"
    if minutes == 0:
        return [LocationClue(kind="timezone", measures="sender's clock (Date header)", value=label, countries=[],
                             strength="weak", note="UTC is also the default for servers and webmail: uninformative.")]
    year = min(max(sent.year, 1971), 2037)  # guard against absurd dates in forged headers
    candidates = list(countries_with_offset(minutes, year, sent.month))
    if not candidates:
        return []
    distinctive = len(candidates) <= 6
    return [LocationClue(
        kind="timezone", measures="sender's clock (Date header)", value=label, countries=candidates,
        region=_names(candidates), strength="medium" if distinctive else "weak",
        note=None if distinctive else "Shared by many countries: useful to confirm or contradict, not to locate.",
    )]


# ---------------------------------------------------------------------------
# Writing language
# ---------------------------------------------------------------------------

def detect_language(text: str) -> Optional[Tuple[str, str]]:
    """(language key, display name), or None for English or too little text."""
    letters = [ch for ch in text if ch.isalpha()]
    if len(letters) < 40:
        return None
    for key, name, char_range in SCRIPTS:
        count = len(re.findall(f"[{char_range}]", text))
        if count >= 20 and count >= 0.2 * len(letters):
            if key == "zh" and re.search("[぀-ヿ]", text):
                return "ja", "Japanese"  # Japanese mixes kanji with kana
            return key, name
    words = re.findall(r"[^\W\d_]+", text.lower())
    hits = {lang: sum(1 for w in words if w in stop) for lang, stop in STOPWORDS.items()}
    ranked = sorted(hits.items(), key=lambda kv: kv[1], reverse=True)
    (best, best_hits), (_, second_hits) = ranked[0], ranked[1]
    if best == "en" or best_hits < 5 or best_hits < 1.5 * second_hits:
        return None
    return best, LANGUAGE_NAMES[best]


def find_language(text: str) -> List[LocationClue]:
    found = detect_language(text)
    if not found:
        return []
    key, name = found
    countries = LANGUAGE_COUNTRIES[key]
    return [LocationClue(kind="language", measures="writing language", value=name, countries=countries,
                         region=_names(countries), strength="weak")]


# ---------------------------------------------------------------------------
# Sender domain
# ---------------------------------------------------------------------------

def find_sender_domain(from_header: Optional[str]) -> List[LocationClue]:
    _, address = parseaddr(from_header or "")
    if "@" not in address:
        return []
    domain = address.rsplit("@", 1)[1].strip(" >").lower().rstrip(".")
    tld = domain.rsplit(".", 1)[-1]
    if len(tld) != 2 or tld in GENERIC_CCTLDS:
        return []
    cc = "GB" if tld == "uk" else tld.upper()
    if cc not in pytz.country_names:
        return []
    return [LocationClue(kind="sender_domain", measures="sender's domain registry", value=f"{domain} (.{tld})",
                         countries=[cc], region=country_name(cc), strength="weak",
                         note="Country domains can be registered from anywhere.")]


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------

def _describe(clue: LocationClue) -> str:
    where = f" → {clue.region}" if clue.region else ""
    return f"{clue.measures}: {clue.value}{where}"


def _sender_assessment(clues: List[LocationClue]) -> Tuple[Optional[str], str, str, List[str], List[str]]:
    """(country, confidence, sentence, supporting, conflicting) from sender-side clues only."""
    per_category: Dict[str, Dict[str, float]] = defaultdict(dict)
    for clue in clues:
        if not clue.countries:
            continue
        share = WEIGHT[clue.strength] / len(clue.countries)
        scores = per_category[CATEGORY[clue.kind]]
        for cc in clue.countries:
            scores[cc] = max(scores.get(cc, 0.0), share)

    totals: Dict[str, float] = defaultdict(float)
    for scores in per_category.values():
        for cc, weight in scores.items():
            totals[cc] += weight
    located = [_describe(c) for c in clues if c.countries]

    if not totals:
        sentence = ("Sender: clues found, but none of them names a country." if clues
                    else "Sender: no location clues in this email.")
        return None, "undetermined", sentence, [], []

    top_score = max(totals.values())
    leaders = sorted(cc for cc, score in totals.items() if abs(score - top_score) < 1e-9)
    if len(leaders) > 1:
        # e.g. a UTC+1 clock alone fits dozens of countries equally: naming one of them
        # would be an invented answer.
        return None, "undetermined", (f"Sender: the clues fit {len(leaders)} countries equally "
                                      f"({_names(leaders)}); not enough to single one out."), located, []

    top = leaders[0]
    supporting = [c for c in clues if top in c.countries]
    conflicting = [c for c in clues if c.countries and top not in c.countries]
    agreeing_kinds = {CATEGORY[c.kind] for c in supporting}
    serious_conflict = any(c.strength in ("strong", "medium") for c in conflicting)

    if len(agreeing_kinds) >= 3 and not serious_conflict:
        confidence = "high"
    elif len(agreeing_kinds) >= 2 and not serious_conflict:
        confidence = "medium"
    else:
        confidence = "low"

    sentence = f"Sender: probably {country_name(top)} ({confidence} confidence), from {len(supporting)} clue(s)"
    if conflicting:
        sentence += f"; {len(conflicting)} clue(s) point elsewhere"
    return top, confidence, sentence + ".", [_describe(c) for c in supporting], [_describe(c) for c in conflicting]


def assess(clues: List[LocationClue]) -> OriginAssessment:
    """Probable sender country, with bank details reported separately as the payment destination."""
    payment = [c for c in clues if CATEGORY[c.kind] == "payment"]
    sender = [c for c in clues if CATEGORY[c.kind] != "payment"]

    country, confidence, sentence, supporting, conflicting = _sender_assessment(sender)
    payment_countries = sorted({cc for c in payment for cc in c.countries})

    parts = [sentence]
    if payment_countries:
        parts.append(f"Payment goes to {_names(payment_countries)} (bank details): "
                     "often a money-mule account rather than the sender's own.")
        if country and country not in payment_countries:
            parts.append("The money leaves the sender's apparent country, a common money-mule pattern.")
    if not clues:
        parts = ["No location clues found in this email."]

    return OriginAssessment(
        country=country, country_name=country_name(country) if country else None, confidence=confidence,
        payment_countries=payment_countries, summary=" ".join(parts),
        supporting=supporting + [_describe(c) for c in payment], conflicting=conflicting,
    )


def analyze_origin(subject: Optional[str], body_plain: Optional[str], body_html: Optional[str],
                   date_header: Optional[str], from_header: Optional[str]) -> OriginAnalysisResult:
    text = " ".join(part for part in (subject, body_plain, strip_html_tags(body_html or "")) if part)
    text = text[:MAX_TEXT_CHARS]
    clues = (find_ibans(text) + find_swift_codes(text) + find_phones(text) + find_timezone(date_header)
             + find_language(text) + find_sender_domain(from_header))
    return OriginAnalysisResult(clues=clues, assessment=assess(clues))
