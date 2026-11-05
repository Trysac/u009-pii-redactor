# pii-redactor

[![PyPI version](https://img.shields.io/pypi/v/trysac-pii-redactor)](https://pypi.org/project/trysac-pii-redactor/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-pii-redactor)](LICENSE)
[![CI](https://github.com/Trysac/u009-pii-redactor/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u009-pii-redactor/actions/workflows/ci.yml)

Detect and mask emails, phones, Luhn-valid cards, ISO 13616 IBANs and IPv4 addresses before text reaches an LLM, with reversible placeholders and a written threat model

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-pii-redactor
# or
uv add trysac-pii-redactor
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import pii_redactor

# normalize() trims surrounding whitespace and lower-cases the text.
print(pii_redactor.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    pii_redactor.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
