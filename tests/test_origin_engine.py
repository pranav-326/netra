"""Tests for location clues other than IP, and how they combine into an assessment."""

import pytest

from netra_common.models.email import AnalysisResults, LocationClue, OriginAnalysisResult
from services.analyzer.src.engines.origin_engine import (
    analyze_origin,
    assess,
    detect_language,
    find_ibans,
    find_language,
    find_phones,
    find_sender_domain,
    find_swift_codes,
    find_timezone,
)
from services.threat_engine.src.scorer import evaluate_threat_score


# --- IBAN -------------------------------------------------------------------------

def test_valid_iban_is_found_and_masked():
    clues = find_ibans("Please remit to IBAN DE89 3704 0044 0532 0130 00 by Friday.")
    assert len(clues) == 1
    clue = clues[0]
    assert clue.countries == ["DE"] and clue.strength == "strong"
    assert clue.value == "DE89 •••• 3000"
    assert "0532" not in clue.value  # the account number is not stored
    assert "money-mule" in clue.note


def test_iban_with_bad_checksum_is_rejected():
    assert find_ibans("IBAN DE89 3704 0044 0532 0130 01") == []


def test_iban_followed_by_more_text_is_still_found():
    assert [c.countries for c in find_ibans("GB82WEST12345698765432 PLEASE PAY TODAY")] == [["GB"]]


def test_lowercase_iban_is_found():
    assert [c.countries for c in find_ibans("iban: gb82 west 1234 5698 7654 32")] == [["GB"]]


# --- SWIFT ------------------------------------------------------------------------

def test_swift_code_after_keyword_is_found():
    clues = find_swift_codes("Beneficiary bank SWIFT/BIC: DEUTDEFF500")
    assert [(c.value, c.countries) for c in clues] == [("DEUTDEFF500", ["DE"])]


def test_capitalised_words_are_not_swift_codes():
    assert find_swift_codes("ATTACHED INVOICES PASSWORD RESET") == []


# --- Phone numbers ----------------------------------------------------------------

def test_international_numbers_give_country_and_region():
    clues = find_phones("Call +1-813-776-1410 or our office +234 803 123 4567")
    assert [(c.countries, c.region) for c in clues] == [(["US"], "Florida"), (["NG"], "Nigeria")]


def test_toll_free_north_american_number_carries_no_location():
    clues = find_phones("Call 1-888-555-0199 to cancel")
    assert len(clues) == 1 and clues[0].countries == []
    assert "toll-free" in clues[0].note


def test_bare_digit_runs_are_not_phone_numbers():
    assert find_phones("Order 4155552671 has shipped") == []


# --- Timezone ---------------------------------------------------------------------

def test_distinctive_offset_narrows_to_few_countries():
    clue = find_timezone("Mon, 07 Sep 2026 12:00:00 +0530")[0]
    assert clue.value == "UTC+05:30" and clue.strength == "medium"
    assert set(clue.countries) == {"IN", "LK"}


def test_utc_offset_is_uninformative():
    clue = find_timezone("Mon, 07 Sep 2026 12:00:00 +0000")[0]
    assert clue.countries == [] and "uninformative" in clue.note


def test_unknown_zone_and_garbage_dates_give_nothing():
    assert find_timezone("Mon, 07 Sep 2026 12:00:00 -0000") == []
    assert find_timezone("not a date") == []
    assert find_timezone(None) == []


def test_daylight_saving_is_respected():
    # UTC+2 in July is Central Europe on summer time; in January it is not.
    july = set(find_timezone("Wed, 15 Jul 2026 12:00:00 +0200")[0].countries)
    january = set(find_timezone("Thu, 15 Jan 2026 12:00:00 +0200")[0].countries)
    assert "DE" in july and "DE" not in january


# --- Language ---------------------------------------------------------------------

@pytest.mark.parametrize("text,language", [
    ("Revisa tu cuenta: examinamos un error al reintentar su pago para la cuenta del usuario con el banco", "es"),
    ("Cliente, regularize sua conta corrente com o banco para que não seja bloqueada em dos dias", "pt"),
    ("【三井住友】SMBCカードアカウントの再認証が必要です。こちらからログインしてください。お客様の情報を確認いたします。", "ja"),
])
def test_language_detection(text, language):
    assert detect_language(text)[0] == language


def test_english_and_short_text_give_no_language_clue():
    assert find_language("Please verify your account and confirm the payment for this invoice today") == []
    assert find_language("Hola") == []


# --- Sender domain ----------------------------------------------------------------

def test_country_domain_is_a_weak_clue():
    clue = find_sender_domain("Banco <avisos@banco-seguro.com.br>")[0]
    assert clue.countries == ["BR"] and clue.strength == "weak"


@pytest.mark.parametrize("sender", ["x <a@startup.io>", "x <a@shop.co>", "x <a@example.com>", "no address"])
def test_generic_and_non_country_domains_give_nothing(sender):
    assert find_sender_domain(sender) == []


# --- Assessment -------------------------------------------------------------------

def clue(kind, countries, strength):
    return LocationClue(kind=kind, measures=kind, value="x", countries=countries, strength=strength)


def test_no_clues_is_undetermined():
    result = assess([])
    assert result.confidence == "undetermined" and result.country is None


def test_sender_clues_of_two_kinds_are_medium():
    result = assess([clue("phone", ["IN"], "medium"), clue("timezone", ["IN", "LK"], "medium")])
    assert (result.country, result.confidence) == ("IN", "medium")


def test_three_agreeing_kinds_are_high():
    result = assess([clue("phone", ["IN"], "medium"), clue("timezone", ["IN", "LK"], "medium"),
                     clue("language", ["IN"], "weak")])
    assert (result.country, result.confidence) == ("IN", "high")


def test_payment_details_are_reported_apart_from_the_sender():
    result = assess([clue("iban", ["DE"], "strong")])
    assert result.country is None  # bank details alone do not locate the sender
    assert result.payment_countries == ["DE"]
    assert "money-mule" in result.summary


def test_iban_and_swift_for_one_account_are_one_destination():
    result = assess([clue("iban", ["DE"], "strong"), clue("swift", ["DE"], "strong")])
    assert result.payment_countries == ["DE"]


def test_sender_in_one_country_paying_into_another_is_flagged():
    # A Mumbai phone and an Indian clock, asking for payment into a German account.
    result = assess([clue("iban", ["DE"], "strong"), clue("swift", ["DE"], "strong"),
                     clue("phone", ["IN"], "medium"), clue("timezone", ["IN", "LK"], "medium")])
    assert (result.country, result.confidence) == ("IN", "medium")
    assert result.payment_countries == ["DE"]
    assert "money leaves the sender's apparent country" in result.summary
    assert result.conflicting == []  # the bank details are not evidence against India


def test_conflicting_sender_evidence_is_low_and_reported():
    result = assess([clue("phone", ["NG"], "medium"), clue("timezone", ["IN", "LK"], "medium")])
    assert (result.country, result.confidence) == ("NG", "low")
    assert len(result.conflicting) == 1


def test_one_weak_clue_names_a_country_at_low_confidence():
    result = assess([clue("sender_domain", ["BR"], "weak")])
    assert (result.country, result.confidence) == ("BR", "low")


def test_a_language_alone_names_no_country():
    result = assess([clue("language", ["BR", "PT", "AO", "MZ"], "weak")])
    assert result.country is None


def test_a_broad_timezone_alone_names_no_country():
    result = assess([clue("timezone", ["AD", "AT", "BE", "DE", "FR", "NG"], "weak")])
    assert result.country is None and result.confidence == "undetermined"
    assert "fit 6 countries equally" in result.summary


def test_timezone_candidates_exclude_uninhabited_territories():
    assert "AQ" not in find_timezone("Wed, 15 Jul 2026 12:00:00 -0400")[0].countries


def test_clues_without_countries_do_not_invent_one():
    result = assess([clue("phone", [], "weak")])
    assert result.confidence == "undetermined"
    assert "none of them names a country" in result.summary


# --- End to end -------------------------------------------------------------------

def test_bec_email_end_to_end():
    result = analyze_origin(
        subject="Updated bank details for invoice 4471",
        body_plain="Please send payment to IBAN GB82 WEST 1234 5698 7654 32. Questions? Call +44 20 7946 0958.",
        body_html=None,
        date_header="Tue, 15 Jan 2026 09:30:00 +0000",
        from_header="Accounts <ap@vendor-billing.co.uk>",
    )
    kinds = sorted(c.kind for c in result.clues)
    assert kinds == ["iban", "phone", "sender_domain", "timezone"]
    assessment = result.assessment
    assert (assessment.country, assessment.confidence) == ("GB", "medium")  # phone + domain
    assert assessment.payment_countries == ["GB"]
    assert "leaves the sender" not in assessment.summary  # paying within the same country


def test_origin_adds_no_risk_points():
    analysis = AnalysisResults(origin_analysis=OriginAnalysisResult(
        clues=[clue("iban", ["NG"], "strong")], assessment=assess([clue("iban", ["NG"], "strong")])))
    assert all(c.category != "origin" for c in evaluate_threat_score(analysis)[3])
    assert evaluate_threat_score(analysis)[4] == evaluate_threat_score(AnalysisResults())[4]
