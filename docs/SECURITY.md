# Security

`trysac-pii-redactor` removes common PII from text before it reaches an LLM and restores it
afterwards from a local vault. This document is the written threat model of the library.

## Threat model

### What the library defends

| Item | How it is defended |
|---|---|
| Built-in values leaking into the redacted text | Every validated match of EMAIL, PHONE, CARD, IBAN and IPV4 is replaced by a placeholder. |
| Originals leaking through `repr`, `str`, exceptions or events | `Vault`, `RedactionResult`, `Span`, `RedactorError` and the `on_event` payload never contain original text; messages are static and at most 200 characters. |
| False positives that would corrupt prompts | Cards use the Luhn check (ISO/IEC 7812-1), IBANs use the ISO 13616 length range and the ISO 7064 MOD 97-10 check, phones need 7-15 digits (national groups at most 12), IPv4 octets are 0-255 without leading zeros. Dates, year ranges and IPv4 shapes are not phones. |
| ReDoS and resource exhaustion | Built-in patterns use explicit bounded quantifiers and no nested or overlapping unbounded quantifiers, so matching is linear. Input is limited by `max_chars` (default 1 000 000, error code `input_too_large`). The vault is limited by `max_entries` (default 100 000, oldest entries evicted). Placeholder formats are limited to 64 characters, plain `{entity}` and `{n}` fields only. |
| Restoring text that was never redacted | `restore` replaces only exact placeholders present in the vault, in a single pass; look-alikes such as `<EMAIL_9>` stay untouched. |
| Logging | The library uses `logging.getLogger(__name__)` with a `NullHandler`, never configures logging and never logs input text. A failing `on_event` hook is contained and only its exception type name is logged. |

### What the library does not defend

- **Names, addresses and national IDs.** There is no NER. Plug a custom `Detector` for them.
- **Obfuscated values** such as spelled-out digits, `ana [at] example.com` or zero-width characters.
- **Placeholder injection.** An attacker in the same conversation can type a placeholder to have
  its value restored. Use one vault per trust boundary (per user or per conversation). Input that
  already contains placeholder-looking tokens can also be confused with issued placeholders.
- **The vault at rest.** `Vault.to_dict()` returns the original values. Encrypt and expire anything
  you persist; the library never writes the vault anywhere.
- **ReDoS in custom patterns.** Custom `Detector` patterns are the caller's responsibility.
- **Internationalised email addresses, IPv6 and lowercase IBANs**, which are out of scope.

## Detector notes

- EMAIL: local part 1-64 and domain at most 253 characters (RFC 5321 section 4.5.3.1), ASCII only.
- PHONE: `+` followed by 8-15 digits (ITU-T E.164) or grouped national formats with space, dash,
  dot or parentheses.
- CARD: 13-19 digits with optional single space or dash separators and a valid Luhn checksum.
- IBAN: two letters, two check digits and up to 30 alphanumerics in upper case, with optional
  spaces every four characters.
- IPV4: four dotted decimal octets.
- Numeric patterns are anchored so they never match inside a longer run of word characters or
  digit groups; a number followed by a separator and more digits is therefore left alone.

## Reporting a vulnerability

See the repository `SECURITY.md` for how to report a vulnerability privately.
