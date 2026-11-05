"""Detector definition and the built-in PII detectors.

Every built-in pattern uses explicit bounded quantifiers and never nests or overlaps
unbounded quantifiers, so matching time is linear in the input size. Numeric patterns are
anchored so they never match inside a longer run of word characters or digit groups.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from .errors import RedactorError

_NAME_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{0,31}")

_BEFORE = r"(?<![\w.])"
_AFTER = r"(?!\w|[ .-][0-9])"

_EMAIL_LOCAL = r"(?<![A-Za-z0-9_%+-])[A-Za-z0-9_%+-][A-Za-z0-9._%+-]{0,63}@"
_EMAIL_LABELS = r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,126}"
_EMAIL_TLD = r"[A-Za-z]{2,63}(?![A-Za-z0-9-])"
_EMAIL = _EMAIL_LOCAL + _EMAIL_LABELS + _EMAIL_TLD

_PHONE_INTL = r"\+(?:[ .()-]{0,2}[0-9]){8,15}"
_PHONE_AREA = r"\([0-9]{2,4}\)[ .-]?[0-9]{2,4}"
_PHONE_PLAIN = r"[0-9]{2,4}[ .-][0-9]{2,4}"
_PHONE_FIRST = r"(?:" + _PHONE_AREA + "|" + _PHONE_PLAIN + ")"
_PHONE_MORE = r"(?:[ .-][0-9]{2,4}){0,2}"
_PHONE_NATIONAL = r"(?<![0-9][ .-])" + _PHONE_FIRST + _PHONE_MORE
_PHONE = _BEFORE + "(?:" + _PHONE_INTL + "|" + _PHONE_NATIONAL + ")" + _AFTER

_CARD = _BEFORE + r"(?<![0-9][ -])[0-9](?:[ -]?[0-9]){12,18}" + _AFTER

_IBAN_BODY = r"[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?"
_IBAN = _BEFORE + _IBAN_BODY + r"(?!\w)"

_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_IPV4 = _BEFORE + "(?:" + _OCTET + r"\.){3}" + _OCTET + r"(?!\w|\.[0-9])"

_NOT_PHONE_SHAPES: tuple[re.Pattern[str], ...] = (
    re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}"),
    re.compile(r"[0-9]{4}[.-][0-9]{2}[.-][0-9]{2}"),
    re.compile(r"[0-9]{2}[.-][0-9]{2}[.-][0-9]{4}"),
    re.compile(r"(?:19|20)[0-9]{2}-(?:19|20)[0-9]{2}"),
)


@dataclass(frozen=True)
class Detector:
    """A named PII detector.

    Attributes:
        name: Entity name used in placeholders; must match ``[A-Z][A-Z0-9_]{0,31}``.
        pattern: Compiled ``str`` pattern that finds candidate values. Custom patterns must
            avoid nested or overlapping unbounded quantifiers; ReDoS safety of custom
            patterns is the caller's responsibility.
        validate: Optional predicate that receives a candidate and returns ``False`` to
            drop it (for example a checksum).

    Raises:
        RedactorError: with code ``invalid_detector`` when a field is invalid.
    """

    name: str
    pattern: re.Pattern[str]
    validate: Callable[[str], bool] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or _NAME_PATTERN.fullmatch(self.name) is None:
            raise RedactorError(
                "invalid_detector",
                "detector name must match [A-Z][A-Z0-9_]{0,31}",
            )
        if not isinstance(self.pattern, re.Pattern) or not isinstance(self.pattern.pattern, str):
            raise RedactorError(
                "invalid_detector",
                "detector pattern must be a compiled str pattern",
            )
        if self.validate is not None and not callable(self.validate):
            raise RedactorError("invalid_detector", "detector validate must be callable")


def _digits(text: str) -> str:
    """Return only the ASCII digits of ``text``."""
    return "".join(ch for ch in text if "0" <= ch <= "9")


def _luhn(digits: str) -> bool:
    """Return ``True`` when ``digits`` pass the Luhn check of ISO/IEC 7812-1."""
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _valid_email(text: str) -> bool:
    """Enforce the RFC 5321 domain limit of 253 characters."""
    return len(text.partition("@")[2]) <= 253


def _valid_phone(text: str) -> bool:
    """Check digit counts and reject date, year-range and IPv4 look-alikes."""
    count = len(_digits(text))
    if text.startswith("+"):
        return 8 <= count <= 15
    if not 7 <= count <= 12:
        return False
    return not any(shape.fullmatch(text) for shape in _NOT_PHONE_SHAPES)


def _valid_card(text: str) -> bool:
    """Require 13-19 digits that pass the Luhn check."""
    digits = _digits(text)
    return 13 <= len(digits) <= 19 and _luhn(digits)


def _valid_iban(text: str) -> bool:
    """Apply the ISO 13616 length range and the ISO 7064 MOD 97-10 check."""
    compact = text.replace(" ", "")
    if not 15 <= len(compact) <= 30:
        return False
    if not 2 <= int(compact[2:4]) <= 98:
        return False
    rearranged = compact[4:] + compact[:4]
    number = int("".join(str(int(char, 36)) for char in rearranged))
    return number % 97 == 1


BUILTIN_DETECTORS: tuple[Detector, ...] = (
    Detector("EMAIL", re.compile(_EMAIL), _valid_email),
    Detector("PHONE", re.compile(_PHONE), _valid_phone),
    Detector("CARD", re.compile(_CARD), _valid_card),
    Detector("IBAN", re.compile(_IBAN), _valid_iban),
    Detector("IPV4", re.compile(_IPV4)),
)
"""The five built-in detectors: EMAIL, PHONE, CARD, IBAN and IPV4."""
