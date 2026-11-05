# Reversible placeholders with linear, checksum-validated detectors and a local vault

Status: accepted (generated, pending human review)

## Context

Prompts built from user content carry emails, phone numbers, card numbers and IBANs that must not leave the system. Ad-hoc regex snippets miss cases, backtrack catastrophically, produce false positives and leak values through reprs and logs. NER based tools such as Presidio need spaCy models and hundreds of MB, which rules them out for a small, browser-friendly library. The model's answer also needs the original values back.

## Decision

Use a zero-dependency library built on regular expressions with explicit bounded quantifiers (linear matching), plus validators (Luhn, ISO 7064 MOD 97-10, digit counts, domain length) to cut false positives. Candidates from all detectors are collected, overlaps are resolved by longest span, then earliest start, then detector order, and the text is rebuilt with placeholders numbered per entity and per vault in order of first appearance. Originals live only in a Vault whose repr and str show the entry count; restore is a single pass that replaces only placeholders the vault issued, found via a format-derived candidate regex plus dictionary lookup so its cost does not grow with vault size. Every untrusted input is bounded (max_chars, max_entries, format length) and failures raise one typed RedactorError with a stable code whose messages never include input.

## Consequences

The library is small, auditable and fast with predictable worst-case behaviour, and redaction is reversible. Detection is limited to formats expressible with linear patterns: no names, addresses, national IDs, IPv6 or obfuscated values, and grouped national phone numbers are capped at 12 digits and require separators. Numeric values adjacent to separator-and-digit runs are deliberately skipped to avoid partial matches of longer numbers. Custom detectors are the extension point but their ReDoS safety is the caller's responsibility. The vault is in-memory, not thread-safe, evicts the oldest entries when full and must be protected by the caller at rest; one vault per trust boundary is required to avoid placeholder injection. A vault accepts at most 16 distinct placeholder formats.
