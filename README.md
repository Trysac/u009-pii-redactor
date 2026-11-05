# pii-redactor

[![PyPI version](https://img.shields.io/pypi/v/trysac-pii-redactor)](https://pypi.org/project/trysac-pii-redactor/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-pii-redactor)](LICENSE)
[![CI](https://github.com/Trysac/u009-pii-redactor/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u009-pii-redactor/actions/workflows/ci.yml)

Detect and mask emails, phones, Luhn-valid cards, ISO 13616 IBANs and IPv4 addresses before text reaches an LLM, with reversible placeholders and a written threat model.

## Problem

Prompts built from user content carry emails, phone numbers, card numbers and IBANs that should not leave the system. Regex snippets copied between projects miss cases, backtrack catastrophically or leak values through logs and reprs. This library detects common PII with linear, checksum-validated patterns, replaces it with stable placeholders and restores them in the model's answer from a local vault that never prints its contents.

## Install

```sh
pip install trysac-pii-redactor
# or
uv add trysac-pii-redactor
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
from pii_redactor import redact, restore

result = redact("Mail ana@example.com or +34 612 345 678")
print(result.text)  # Mail <EMAIL_1> or <PHONE_1>
print(result.counts)  # {'EMAIL': 1, 'PHONE': 1}
print(repr(result.vault))  # Vault(2 entries)
print(restore("Reply to <EMAIL_1>", result.vault))  # Reply to ana@example.com
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
