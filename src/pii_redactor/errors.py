"""Typed errors raised by the redaction library."""

from __future__ import annotations

from typing import Literal

ErrorCode = Literal["invalid_detector", "invalid_format", "input_too_large"]

_MAX_MESSAGE_CHARS = 200


class RedactorError(ValueError):
    """Base class of every error raised by this library.

    Attributes:
        code: Stable machine-readable error code. One of ``invalid_detector``,
            ``invalid_format`` or ``input_too_large``.

    Messages are static text; they never include the input being processed.
    """

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message[:_MAX_MESSAGE_CHARS])
        self.code: ErrorCode = code
