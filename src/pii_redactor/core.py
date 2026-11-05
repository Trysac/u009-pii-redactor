"""Redaction and restoration entry points."""

from __future__ import annotations

import bisect
import logging
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import NamedTuple

from .detectors import BUILTIN_DETECTORS, Detector
from .errors import RedactorError
from .vault import DEFAULT_PLACEHOLDER_FORMAT, Vault

DEFAULT_MAX_CHARS = 1_000_000

logger = logging.getLogger(__name__)


class Span(NamedTuple):
    """Location of one redacted value in the original text. It holds no original text."""

    start: int
    end: int
    entity: str
    placeholder: str


@dataclass(frozen=True, repr=False)
class RedactionResult:
    """Outcome of :func:`redact`.

    Attributes:
        text: The redacted text.
        vault: The vault holding the originals (the one passed in, or a new one).
        counts: Number of replaced occurrences per entity.
        spans: Replaced spans in the order they appear in the original text.

    ``repr`` and ``str`` only show the counts.
    """

    text: str
    vault: Vault
    counts: Mapping[str, int]
    spans: tuple[Span, ...]

    def __repr__(self) -> str:
        return f"RedactionResult(counts={dict(self.counts)!r})"


def _check_length(text: str, max_chars: int) -> None:
    if isinstance(max_chars, bool) or not isinstance(max_chars, int) or max_chars < 1:
        raise RedactorError("invalid_format", "max_chars must be a positive integer")
    if len(text) > max_chars:
        raise RedactorError("input_too_large", "text exceeds the max_chars limit")


def _select(text: str, detectors: Sequence[Detector]) -> list[tuple[int, int, str]]:
    """Find validated candidates and resolve overlaps (longest, then earliest, then order)."""
    candidates: list[tuple[int, int, int, int]] = []
    for index, detector in enumerate(detectors):
        validate = detector.validate
        for match in detector.pattern.finditer(text):
            start, end = match.span()
            if end <= start:
                continue
            if validate is not None and not validate(match.group(0)):
                continue
            candidates.append((start - end, start, index, end))
    candidates.sort()
    starts: list[int] = []
    ends: list[int] = []
    names: list[str] = []
    for _, start, index, end in candidates:
        position = bisect.bisect_left(starts, start)
        if position > 0 and ends[position - 1] > start:
            continue
        if position < len(starts) and starts[position] < end:
            continue
        starts.insert(position, start)
        ends.insert(position, end)
        names.insert(position, detectors[index].name)
    return list(zip(starts, ends, names, strict=True))


def _emit(on_event: Callable[[Mapping[str, str]], None] | None, span: Span) -> None:
    """Call the event hook; a failing hook never breaks redaction."""
    if on_event is None:
        return
    payload = {"type": "redacted", "entity": span.entity, "placeholder": span.placeholder}
    try:
        on_event(payload)
    except Exception as exc:
        logger.warning("on_event callback failed: %s", type(exc).__name__)


def redact(
    text: str,
    *,
    detectors: Sequence[Detector] = BUILTIN_DETECTORS,
    vault: Vault | None = None,
    placeholder_format: str = DEFAULT_PLACEHOLDER_FORMAT,
    max_chars: int = DEFAULT_MAX_CHARS,
    on_event: Callable[[Mapping[str, str]], None] | None = None,
) -> RedactionResult:
    """Replace PII in ``text`` with placeholders and store the originals in a vault.

    Every detector runs, candidates rejected by ``validate`` are dropped, overlaps are
    resolved by longest span then earliest start (then detector order), and the rest are
    replaced. Numbering is per entity and per vault, in order of first appearance, and the
    same value always maps to the same placeholder.

    Args:
        text: Text to redact.
        detectors: Detectors to run; defaults to :data:`BUILTIN_DETECTORS`.
        vault: Vault to reuse; a new one is created when ``None``.
        placeholder_format: Format with plain ``{entity}`` and ``{n}`` fields.
        max_chars: Maximum accepted length of ``text``.
        on_event: Optional hook called once per replaced occurrence with
            ``{"type": "redacted", "entity": ..., "placeholder": ...}``. It never receives
            original text and its exceptions are contained.

    Raises:
        RedactorError: ``input_too_large`` when ``text`` exceeds ``max_chars``,
            ``invalid_format`` for a bad ``placeholder_format`` or limit, and
            ``invalid_detector`` when ``detectors`` holds a non-:class:`Detector`.
    """
    _check_length(text, max_chars)
    for detector in detectors:
        if not isinstance(detector, Detector):
            raise RedactorError("invalid_detector", "detectors must be Detector instances")
    active = Vault() if vault is None else vault
    active._register_format(placeholder_format)
    selected = _select(text, detectors)
    pieces: list[str] = []
    spans: list[Span] = []
    counts: dict[str, int] = {}
    cursor = 0
    for start, end, entity in selected:
        placeholder = active._issue(entity, text[start:end], placeholder_format)
        pieces.append(text[cursor:start])
        pieces.append(placeholder)
        cursor = end
        spans.append(Span(start, end, entity, placeholder))
        counts[entity] = counts.get(entity, 0) + 1
    pieces.append(text[cursor:])
    logger.debug("redacted %d spans", len(spans))
    for span in spans:
        _emit(on_event, span)
    return RedactionResult(
        text="".join(pieces),
        vault=active,
        counts=MappingProxyType(counts),
        spans=tuple(spans),
    )


def restore(text: str, vault: Vault, *, max_chars: int = DEFAULT_MAX_CHARS) -> str:
    """Replace the placeholders issued by ``vault`` in ``text`` with their originals.

    Only exact placeholders present in the vault are replaced; anything that merely looks
    like a placeholder is left untouched. Restoration is a single pass, so restored values
    are never rescanned.

    Raises:
        RedactorError: ``input_too_large`` when ``text`` exceeds ``max_chars``.
    """
    _check_length(text, max_chars)
    pattern = vault._restore_pattern()
    if pattern is None:
        return text

    def _replace(match: re.Match[str]) -> str:
        token = match.group(0)
        value = vault.get(token)
        return token if value is None else value

    return pattern.sub(_replace, text)
