"""Behavior tests for the public API of pii_redactor."""

from __future__ import annotations

import pytest

import pii_redactor


def test_normalize_trims_and_lowercases() -> None:
    assert pii_redactor.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        pii_redactor.normalize(value)


def test_version_is_semver() -> None:
    parts = pii_redactor.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
