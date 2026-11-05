# Project record

## Objective

Detect and mask emails, phones, Luhn-valid cards, ISO 13616 IBANs and IPv4 addresses before text reaches an LLM, with reversible placeholders and a written threat model

## Scope

- In scope: the public API documented in [README.md](../README.md), typed and tested.
- Out of scope: anything that needs runtime dependencies or I/O without an accepted ADR.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | pending measurement |
| Hours (human) | pending measurement |
| Cost (USD) | pending measurement |

## Factory run u009 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | claude-sonnet-5-5 | yes | 2222 | 48000 | 3811 | 0 | 0.2498 |
| generation | claude-sonnet-5-5 | yes | 2222 | 98601 | 0 | 3811 | 0.4956 |
| fix-1 | claude-sonnet-5-5 | no | 4 | 330 | 5404 | 24155 | 0.0192 |
| docs | claude-haiku-5-5 | no | 110476 | 2734 | 0 | 0 | 0.0621 |

Total: $0.8268. Prices: Anthropic list prices.
