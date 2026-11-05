"""Tests for the pii_redactor public API."""

from __future__ import annotations

import logging
import re

import pytest

import pii_redactor
from pii_redactor import (
    BUILTIN_DETECTORS,
    Detector,
    RedactionResult,
    RedactorError,
    Span,
    Vault,
    redact,
    restore,
)

EMAIL = "sentinel.user@example.com"
PHONE = "+34 612 345 678"
CARD = "4111 1111 1111 1111"
IBAN = "GB82 WEST 1234 5698 7654 32"
IPV4 = "203.0.113.7"
SENSITIVE_VALUES = (EMAIL, PHONE, CARD, IBAN, IPV4)
MIXED = f"Contact {EMAIL}, {PHONE}, card {CARD}, {IBAN} from {IPV4}."
MIXED_REDACTED = "Contact <EMAIL_1>, <PHONE_1>, card <CARD_1>, <IBAN_1> from <IPV4_1>."

DETECTION_CASES = [
    ("a@b.co", "<EMAIL_1>"),
    ("ana@localhost", "ana@localhost"),
    ("+1 415 555 2671", "<PHONE_1>"),
    ("+123456789012345", "<PHONE_1>"),
    ("+1234567", "+1234567"),
    ("+1234567890123456", "+1234567890123456"),
    ("(555) 123-4567", "<PHONE_1>"),
    ("555-123-4567", "<PHONE_1>"),
    ("612 345 678", "<PHONE_1>"),
    ("555.123.4567", "<PHONE_1>"),
    ("2024-01-15", "2024-01-15"),
    ("15.01.2024", "15.01.2024"),
    ("2019-2021", "2019-2021"),
    ("4111111111111111", "<CARD_1>"),
    ("4111-1111-1111-1111", "<CARD_1>"),
    ("378282246310005", "<CARD_1>"),
    ("4222222222222", "<CARD_1>"),
    ("4111111111111112", "4111111111111112"),
    ("DE89 3704 0044 0532 0130 00", "<IBAN_1>"),
    ("FR14 2004 1010 0505 0001 3M02 606", "<IBAN_1>"),
    ("GB82WEST12345698765432", "<IBAN_1>"),
    ("GB00 WEST 1234 5698 7654 32", "GB00 WEST 1234 5698 7654 32"),
    ("192.168.1.10", "<IPV4_1>"),
    ("0.0.0.0", "<IPV4_1>"),  # noqa: S104
    ("255.255.255.255", "<IPV4_1>"),
    ("01.2.3.4", "01.2.3.4"),
    ("1.2.3.4.5", "1.2.3.4.5"),
    ("1.2.3", "1.2.3"),
    ("999.999.999.999", "999.999.999.999"),
]

ROUND_TRIP_TEXTS = [
    "",
    "no pii here",
    "Mail ana@example.com or +34 612 345 678",
    MIXED,
    "https://example.com/?u=ana@example.com&x=1",
    "(call +34 612 345 678).",
    "Caf\u00e9 ana@example.com \u4f60\u597d",
    "ana@example.com ana@example.com bob@example.org",
]


def test_version_is_exposed() -> None:
    assert pii_redactor.__version__ == "0.1.0"


def test_null_handler_is_installed() -> None:
    handlers = logging.getLogger("pii_redactor").handlers
    assert any(isinstance(handler, logging.NullHandler) for handler in handlers)


def test_builtin_detector_names() -> None:
    assert [d.name for d in BUILTIN_DETECTORS] == ["EMAIL", "PHONE", "CARD", "IBAN", "IPV4"]


def test_acceptance_example() -> None:
    result = redact("Mail ana@example.com or +34 612 345 678")
    assert result.text == "Mail <EMAIL_1> or <PHONE_1>"
    assert result.counts == {"EMAIL": 1, "PHONE": 1}
    assert result.spans == (
        Span(5, 20, "EMAIL", "<EMAIL_1>"),
        Span(24, 39, "PHONE", "<PHONE_1>"),
    )
    assert isinstance(result, RedactionResult)


def test_mixed_text_with_every_entity() -> None:
    result = redact(MIXED)
    assert result.text == MIXED_REDACTED
    assert result.counts == {"EMAIL": 1, "PHONE": 1, "CARD": 1, "IBAN": 1, "IPV4": 1}
    assert restore(result.text, result.vault) == MIXED


@pytest.mark.parametrize(("text", "expected"), DETECTION_CASES)
def test_detection_cases(text: str, expected: str) -> None:
    assert redact(text).text == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("https://example.com/?u=ana@example.com&x=1", "https://example.com/?u=<EMAIL_1>&x=1"),
        ("(call +34 612 345 678).", "(call <PHONE_1>)."),
        ("Phone:+34612345678;", "Phone:<PHONE_1>;"),
        ("mailto:ana@example.com.", "mailto:<EMAIL_1>."),
        ("", ""),
    ],
)
def test_edge_cases(text: str, expected: str) -> None:
    result = redact(text)
    assert result.text == expected


def test_empty_string_has_no_findings() -> None:
    result = redact("")
    assert result.spans == ()
    assert result.counts == {}
    assert len(result.vault) == 0


def test_unicode_text_is_preserved() -> None:
    text = "Caf\u00e9 ana@example.com \u4f60\u597d \u00f1"
    assert redact(text).text == "Caf\u00e9 <EMAIL_1> \u4f60\u597d \u00f1"


def test_non_ascii_digits_are_not_detected() -> None:
    group = "\u0661\u0661\u0661\u0661"
    text = " ".join(["\u0664\u0661\u0661\u0661", group, group, group])
    assert redact(text).text == text


def test_email_length_limits() -> None:
    assert redact("a" * 64 + "@example.com").text == "<EMAIL_1>"
    too_long_local = "a" * 65 + "@example.com"
    assert redact(too_long_local).text == too_long_local
    domain = ".".join(["a" * 63] * 3 + ["b" * 57, "com"])
    assert len(domain) == 253
    assert redact("ana@" + domain).text == "<EMAIL_1>"
    too_long_domain = "ana@" + ".".join(["a" * 63] * 4 + ["com"])
    assert redact(too_long_domain).text == too_long_domain


def test_same_value_shares_placeholder_and_vault_continues_numbering() -> None:
    vault = Vault()
    first = redact("ana@example.com and ana@example.com", vault=vault)
    assert first.vault is vault
    assert first.text == "<EMAIL_1> and <EMAIL_1>"
    assert first.counts == {"EMAIL": 2}
    assert len(vault) == 1
    second = redact("bob@example.org", vault=vault)
    assert second.text == "<EMAIL_2>"
    assert redact("bob@example.org", vault=vault).text == "<EMAIL_2>"


def test_numbering_follows_first_appearance() -> None:
    result = redact("b@example.com a@example.com b@example.com")
    assert result.text == "<EMAIL_1> <EMAIL_2> <EMAIL_1>"


@pytest.mark.parametrize("text", ROUND_TRIP_TEXTS)
def test_round_trip(text: str) -> None:
    result = redact(text)
    assert restore(result.text, result.vault) == text


def test_restore_ignores_placeholders_never_issued() -> None:
    result = redact("ana@example.com")
    assert restore("<EMAIL_9> and <EMAIL_1>", result.vault) == "<EMAIL_9> and ana@example.com"
    assert restore(result.text, Vault()) == result.text
    assert restore("<EMAIL_1>", Vault()) == "<EMAIL_1>"


def test_restore_enforces_size_limit() -> None:
    with pytest.raises(RedactorError) as info:
        restore("a" * 11, Vault(), max_chars=10)
    assert info.value.code == "input_too_large"


@pytest.mark.parametrize(
    "placeholder_format",
    ["<{entity}_{n}>", "[[{entity}:{n}]]", "{{{entity}-{n}}}", "{entity}#{n}#"],
)
def test_custom_formats_round_trip(placeholder_format: str) -> None:
    text = "Mail ana@example.com and bob@example.org, ip 10.0.0.1."
    result = redact(text, placeholder_format=placeholder_format)
    assert "ana@example.com" not in result.text
    assert "10.0.0.1" not in result.text
    assert restore(result.text, result.vault) == text


def test_restore_requires_exact_placeholder_tokens() -> None:
    result = redact("ana@example.com", placeholder_format="{entity}{n}")
    assert result.text == "EMAIL1"
    assert restore("EMAIL1 EMAIL10", result.vault) == "ana@example.com EMAIL10"


def test_placeholder_collisions_are_avoided() -> None:
    detectors = (
        Detector("A1", re.compile("x")),
        Detector("A", re.compile(r"y[0-9]+")),
    )
    text = "x " + " ".join(f"y{i}" for i in range(1, 12))
    vault = Vault()
    result = redact(text, detectors=detectors, vault=vault, placeholder_format="{entity}{n}")
    assert len({span.placeholder for span in result.spans}) == 12
    assert len(vault) == 12
    assert restore(result.text, vault) == text


def test_vault_distinct_format_limit() -> None:
    vault = Vault()
    for index in range(16):
        placeholder_format = "<" * (index + 1) + "{entity}_{n}>"
        redact(f"u{index}@example.com", vault=vault, placeholder_format=placeholder_format)
    with pytest.raises(RedactorError) as info:
        redact("late@example.com", vault=vault, placeholder_format="<<<<<<<<<<<<<<<<<{entity}{n}")
    assert info.value.code == "invalid_format"


def test_overlap_longest_span_wins() -> None:
    custom = Detector("CONTACT", re.compile(r"Contact: ana@example\.com"))
    result = redact("Contact: ana@example.com", detectors=(*BUILTIN_DETECTORS, custom))
    assert result.text == "<CONTACT_1>"
    assert result.counts == {"CONTACT": 1}


def test_overlap_shorter_custom_span_loses() -> None:
    custom = Detector("DOMAIN", re.compile(r"example\.com"))
    result = redact("ana@example.com", detectors=(*BUILTIN_DETECTORS, custom))
    assert result.text == "<EMAIL_1>"


def test_overlap_equal_length_earliest_start_wins() -> None:
    custom = Detector("PRE", re.compile(r"x ana@example\.c"))
    result = redact("x ana@example.com", detectors=(*BUILTIN_DETECTORS, custom))
    assert result.text == "<PRE_1>om"


def test_overlap_full_tie_uses_detector_order() -> None:
    first = Detector("AAA", re.compile("ab"))
    second = Detector("BBB", re.compile("ab"))
    assert redact("ab", detectors=(first, second)).text == "<AAA_1>"
    assert redact("ab", detectors=(second, first)).text == "<BBB_1>"


def test_custom_validate_and_empty_matches() -> None:
    even = Detector("EVEN", re.compile(r"[0-9]+"), lambda value: int(value) % 2 == 0)
    assert redact("12 13", detectors=(even,)).text == "<EVEN_1> 13"
    empty = Detector("EMPTY", re.compile("x*"))
    assert redact("abc", detectors=(empty,)).text == "abc"
    assert redact("axb", detectors=(empty,)).text == "a<EMPTY_1>b"


def test_no_detectors_leaves_text_unchanged() -> None:
    assert redact("ana@example.com", detectors=()).text == "ana@example.com"


def test_size_limit() -> None:
    with pytest.raises(RedactorError) as info:
        redact("a" * 11, max_chars=10)
    assert info.value.code == "input_too_large"
    assert redact("a" * 10, max_chars=10).text == "a" * 10
    with pytest.raises(RedactorError) as default_info:
        redact("a" * 1_000_001)
    assert default_info.value.code == "input_too_large"


@pytest.mark.parametrize("limit", [0, -1, True])
def test_invalid_size_limit(limit: int) -> None:
    with pytest.raises(RedactorError) as info:
        redact("a", max_chars=limit)
    assert info.value.code == "invalid_format"


@pytest.mark.parametrize(
    "text",
    [
        "a" * 100_000 + "@",
        "1" * 100_000,
        "1 " * 50_000,
        "a." * 50_000 + "@",
        "+" + "1 " * 50_000,
        "A" * 100_000,
        "1." * 50_000,
    ],
)
def test_adversarial_inputs_complete_unchanged(text: str) -> None:
    assert redact(text).text == text


def test_no_original_value_leaks() -> None:
    events: list[object] = []
    result = redact(MIXED, on_event=events.append)
    with pytest.raises(RedactorError) as info:
        redact(MIXED, max_chars=5)
    with pytest.raises(RedactorError) as format_info:
        redact(MIXED, placeholder_format=MIXED)
    blobs = [
        result.text,
        repr(result),
        str(result),
        repr(result.vault),
        str(result.vault),
        repr(result.spans),
        repr(result.counts),
        str(events),
        str(info.value),
        repr(info.value),
        str(format_info.value),
    ]
    for value in SENSITIVE_VALUES:
        assert all(value not in blob for blob in blobs)
    assert len(str(info.value)) <= 200
    assert len(events) == 5


def test_event_payloads() -> None:
    events: list[object] = []
    redact("ana@example.com ana@example.com 10.0.0.1", on_event=events.append)
    assert events == [
        {"type": "redacted", "entity": "EMAIL", "placeholder": "<EMAIL_1>"},
        {"type": "redacted", "entity": "EMAIL", "placeholder": "<EMAIL_1>"},
        {"type": "redacted", "entity": "IPV4", "placeholder": "<IPV4_1>"},
    ]


def test_failing_event_hook_is_contained(caplog: pytest.LogCaptureFixture) -> None:
    def boom(payload: object) -> None:
        raise RuntimeError(EMAIL)

    with caplog.at_level(logging.WARNING, logger="pii_redactor"):
        result = redact(EMAIL, on_event=boom)
    assert result.text == "<EMAIL_1>"
    assert "RuntimeError" in caplog.text
    assert EMAIL not in caplog.text


def test_result_is_immutable_and_repr_shows_counts_only() -> None:
    result = redact("ana@example.com")
    assert repr(result) == "RedactionResult(counts={'EMAIL': 1})"
    assert str(result) == repr(result)
    with pytest.raises(AttributeError):
        result.text = "changed"  # type: ignore[misc]
    with pytest.raises(TypeError):
        result.counts["EMAIL"] = 5  # type: ignore[index]


def test_span_fields() -> None:
    assert Span._fields == ("start", "end", "entity", "placeholder")


def test_vault_basics() -> None:
    vault = Vault()
    assert repr(vault) == "Vault(0 entries)"
    assert len(vault) == 0
    result = redact("ana@example.com", vault=vault)
    assert repr(vault) == "Vault(1 entries)"
    assert str(vault) == "Vault(1 entries)"
    assert vault.get("<EMAIL_1>") == "ana@example.com"
    assert vault.get("<EMAIL_2>") is None
    copy = vault.to_dict()
    assert copy == {"<EMAIL_1>": "ana@example.com"}
    copy.clear()
    assert len(vault) == 1
    assert result.vault is vault


def test_vault_evicts_oldest_entries() -> None:
    vault = Vault(max_entries=2)
    result = redact("a1@example.com b2@example.com c3@example.com", vault=vault)
    assert result.text == "<EMAIL_1> <EMAIL_2> <EMAIL_3>"
    assert len(vault) == 2
    assert vault.get("<EMAIL_1>") is None
    assert vault.get("<EMAIL_3>") == "c3@example.com"
    assert restore(result.text, vault) == "<EMAIL_1> b2@example.com c3@example.com"


@pytest.mark.parametrize("limit", [0, -5, True, "10"])
def test_vault_rejects_invalid_max_entries(limit: object) -> None:
    with pytest.raises(RedactorError) as info:
        Vault(max_entries=limit)  # type: ignore[arg-type]
    assert info.value.code == "invalid_format"


@pytest.mark.parametrize(
    "name",
    ["email", "", "1ABC", "A" * 33, "AB-C", "ABC\n", "A B"],
)
def test_invalid_detector_names(name: str) -> None:
    with pytest.raises(RedactorError) as info:
        Detector(name, re.compile("x"))
    assert info.value.code == "invalid_detector"


def test_valid_detector_name_limits() -> None:
    assert Detector("A", re.compile("x")).name == "A"
    assert Detector("A" * 32, re.compile("x")).name == "A" * 32
    assert Detector("ORDER_ID2", re.compile("x")).validate is None


def test_invalid_detector_fields() -> None:
    with pytest.raises(RedactorError) as pattern_info:
        Detector("ABC", "x")  # type: ignore[arg-type]
    assert pattern_info.value.code == "invalid_detector"
    with pytest.raises(RedactorError) as bytes_info:
        Detector("ABC", re.compile(b"x"))  # type: ignore[arg-type]
    assert bytes_info.value.code == "invalid_detector"
    with pytest.raises(RedactorError) as validate_info:
        Detector("ABC", re.compile("x"), "no")  # type: ignore[arg-type]
    assert validate_info.value.code == "invalid_detector"


def test_detector_is_immutable() -> None:
    detector = Detector("ABC", re.compile("x"))
    with pytest.raises(AttributeError):
        detector.name = "DEF"  # type: ignore[misc]


def test_redact_rejects_non_detectors() -> None:
    with pytest.raises(RedactorError) as info:
        redact("x", detectors=("EMAIL",))  # type: ignore[arg-type]
    assert info.value.code == "invalid_detector"


@pytest.mark.parametrize(
    "placeholder_format",
    [
        "<{entity}>",
        "<{n}>",
        "{entity}_{n:>5}",
        "{entity!r}_{n}",
        "{entity}_{n}_{x}",
        "{entity}_{n}{",
        "{}",
        "{entity.__class__}_{n}",
        "<" * 65 + "{entity}_{n}",
        "plain",
        None,
    ],
)
def test_invalid_placeholder_formats(placeholder_format: object) -> None:
    with pytest.raises(RedactorError) as info:
        redact("ana@example.com", placeholder_format=placeholder_format)  # type: ignore[arg-type]
    assert info.value.code == "invalid_format"


def test_error_is_a_value_error_with_code() -> None:
    error = RedactorError("input_too_large", "x" * 500)
    assert isinstance(error, ValueError)
    assert error.code == "input_too_large"
    assert len(str(error)) == 200
