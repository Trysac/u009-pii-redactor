# Architecture

## Purpose

`trysac-pii-redactor` is a small, dependency-free Python library. It detects emails, phones, Luhn-valid cards, ISO 13616 IBANs and IPv4 addresses, replaces them with reversible placeholders, and restores them from a local vault.

## Shape

```text
caller code --> pii_redactor (public API in __init__.py)
                    |
                    +-- core.py: redact / restore (pure, no I/O)
                    +-- detectors.py: Detector and BUILTIN_DETECTORS
                    +-- vault.py: in-memory Vault (placeholder <-> value)
                    +-- errors.py: RedactorError with a stable code
```

- **Public API**: the names listed in `__all__` of `src/pii_redactor/__init__.py`. Anything else is
  internal and may change without a major version.
- **Redaction algorithm**: every detector runs, candidates rejected by `validate` are dropped,
  overlaps are resolved by longest span then earliest start, and the rest are replaced.
- **Errors**: invalid input raises `RedactorError` (a `ValueError` subclass) with a stable `code`
  and a static message that never contains the input text.
- **Side effects**: none. Logging uses `logging.getLogger(__name__)` with a `NullHandler`; the
  library never configures logging.

## Quality contract

`scripts/check.py` is the single definition of the gates; `fabrica.json` tells the factory and CI
how to run it. See [TESTING.md](TESTING.md).

## Decisions

Architecture decisions are recorded in [decisions/](decisions/) as numbered ADRs.
