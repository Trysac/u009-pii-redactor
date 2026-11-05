# Architecture

## Purpose

`trysac-pii-redactor` is a small, dependency-free Python library: Detect and mask emails, phones, Luhn-valid cards, ISO 13616 IBANs and IPv4 addresses before text reaches an LLM, with reversible placeholders and a written threat model

## Shape

```text
caller code --> pii_redactor (public API in __init__.py)
                    |
                    +-- pure functions, no I/O, no global state
```

- **Public API**: the names listed in `__all__` of `src/pii_redactor/__init__.py`. Anything else is
  internal and may change without a major version.
- **Errors**: invalid input raises built-in exceptions (`ValueError`, `TypeError`) with a clear
  message; the library never prints or exits.
- **Side effects**: none. If a feature needs I/O, isolate it in its own module behind a small
  interface and record the choice in an ADR.

## Quality contract

`scripts/check.py` is the single definition of the gates; `fabrica.json` tells the factory and CI
how to run it. See [TESTING.md](TESTING.md).

## Decisions

Architecture decisions are recorded in [decisions/](decisions/) as numbered ADRs.
