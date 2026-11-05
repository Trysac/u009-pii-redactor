"""Local vault that maps placeholders back to the original values."""

from __future__ import annotations

import re
from string import Formatter

from .errors import RedactorError

DEFAULT_PLACEHOLDER_FORMAT = "<{entity}_{n}>"
DEFAULT_MAX_ENTRIES = 100_000

_MAX_FORMAT_CHARS = 64
_MAX_FORMATS = 16
_ENTITY_SOURCE = r"[A-Z][A-Z0-9_]{0,31}"
_NUMBER_SOURCE = r"[0-9]{1,12}"
_FORMATTER = Formatter()


def check_format(placeholder_format: str) -> str:
    """Validate ``placeholder_format`` and return a regex source matching its output.

    The format may only contain plain ``{entity}`` and ``{n}`` fields (both required), no
    format specs or conversions, and at most 64 characters.

    Raises:
        RedactorError: with code ``invalid_format`` when the format is not acceptable.
    """
    if not isinstance(placeholder_format, str) or len(placeholder_format) > _MAX_FORMAT_CHARS:
        raise RedactorError(
            "invalid_format",
            "placeholder_format must be a string of at most 64 characters",
        )
    try:
        parsed = list(_FORMATTER.parse(placeholder_format))
    except ValueError:
        raise RedactorError(
            "invalid_format",
            "placeholder_format is not a valid format string",
        ) from None
    parts: list[str] = []
    fields: set[str] = set()
    for literal, field, spec, conversion in parsed:
        parts.append(re.escape(literal))
        if field is None:
            continue
        if field not in ("entity", "n") or spec or conversion:
            raise RedactorError(
                "invalid_format",
                "placeholder_format may only use plain {entity} and {n} fields",
            )
        fields.add(field)
        parts.append(_ENTITY_SOURCE if field == "entity" else _NUMBER_SOURCE)
    if fields != {"entity", "n"}:
        raise RedactorError(
            "invalid_format",
            "placeholder_format must contain both {entity} and {n}",
        )
    return "".join(parts)


class Vault:
    """In-memory store mapping issued placeholders to the original values.

    The vault never prints its contents: ``repr`` and ``str`` only show the entry count.
    Numbering is per entity and per vault, so reusing a vault across ``redact`` calls keeps
    placeholders unique. The store holds at most ``max_entries`` entries; when it is full the
    oldest entries are evicted (their placeholders can no longer be restored). A vault is not
    thread-safe.

    Raises:
        RedactorError: with code ``invalid_format`` when ``max_entries`` is not a positive int.
    """

    __slots__ = (
        "_by_placeholder",
        "_by_value",
        "_counters",
        "_formats",
        "_max_entries",
        "_pattern",
    )

    def __init__(self, *, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
            raise RedactorError("invalid_format", "max_entries must be a positive integer")
        self._max_entries = max_entries
        self._by_placeholder: dict[str, tuple[str, str]] = {}
        self._by_value: dict[tuple[str, str], str] = {}
        self._counters: dict[str, int] = {}
        self._formats: dict[str, str] = {}
        self._pattern: re.Pattern[str] | None = None

    def get(self, placeholder: str) -> str | None:
        """Return the original value for an issued ``placeholder``, or ``None``."""
        entry = self._by_placeholder.get(placeholder)
        return None if entry is None else entry[1]

    def to_dict(self) -> dict[str, str]:
        """Return a copy of the placeholder-to-original mapping.

        Warning: the result contains the original, sensitive values. Treat it like the raw
        input and never log or persist it unprotected.
        """
        return {placeholder: entry[1] for placeholder, entry in self._by_placeholder.items()}

    def __len__(self) -> int:
        return len(self._by_placeholder)

    def __repr__(self) -> str:
        return f"Vault({len(self._by_placeholder)} entries)"

    __str__ = __repr__

    def _register_format(self, placeholder_format: str) -> None:
        """Remember a placeholder format so ``restore`` can recognise its placeholders."""
        if placeholder_format in self._formats:
            return
        source = check_format(placeholder_format)
        if len(self._formats) >= _MAX_FORMATS:
            raise RedactorError(
                "invalid_format",
                "a vault supports at most 16 distinct placeholder formats",
            )
        self._formats[placeholder_format] = source
        self._pattern = None

    def _issue(self, entity: str, value: str, placeholder_format: str) -> str:
        """Return the placeholder for ``value``, creating one when it is new."""
        key = (entity, value)
        existing = self._by_value.get(key)
        if existing is not None:
            return existing
        while True:
            number = self._counters.get(entity, 0) + 1
            self._counters[entity] = number
            placeholder = placeholder_format.format(entity=entity, n=number)
            if placeholder not in self._by_placeholder:
                break
        self._by_placeholder[placeholder] = key
        self._by_value[key] = placeholder
        while len(self._by_placeholder) > self._max_entries:
            oldest = next(iter(self._by_placeholder))
            self._by_value.pop(self._by_placeholder.pop(oldest), None)
        return placeholder

    def _restore_pattern(self) -> re.Pattern[str] | None:
        """Return a cached regex finding placeholder-shaped tokens, or ``None`` if empty."""
        if not self._by_placeholder:
            return None
        if self._pattern is None:
            body = "|".join(f"(?:{source})" for source in self._formats.values())
            self._pattern = re.compile(body)
        return self._pattern
