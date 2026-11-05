"""Detect and mask PII before text reaches an LLM, with reversible placeholders.

``redact`` replaces emails, phone numbers, Luhn-valid card numbers, ISO 13616 IBANs and
IPv4 addresses with stable placeholders such as ``<EMAIL_1>`` and stores the originals in a
local :class:`Vault`. ``restore`` puts them back into the model's answer.

Threat model (see ``docs/SECURITY.md`` for the full version):

Defended
    * Built-in values never appear in the redacted text.
    * Originals never appear in ``repr``, ``str``, exception messages or events.
    * Checksums (Luhn, ISO 7064 MOD 97-10) cut false positives.
    * Built-in patterns are linear-time (no ReDoS) and input size is bounded.
    * ``restore`` only replaces placeholders the vault issued.

Not defended
    * Names, addresses and national IDs: plug in a custom :class:`Detector`.
    * Obfuscated values such as spelled-out digits.
    * An attacker in the same conversation typing a placeholder to have its value restored:
      use one vault per trust boundary.
    * The vault at rest: ``Vault.to_dict`` returns sensitive data.
    * ReDoS in custom patterns, which are the caller's responsibility.
"""

from __future__ import annotations

import logging

from .core import RedactionResult, Span, redact, restore
from .detectors import BUILTIN_DETECTORS, Detector
from .errors import RedactorError
from .vault import Vault

__all__ = [
    "BUILTIN_DETECTORS",
    "Detector",
    "RedactionResult",
    "RedactorError",
    "Span",
    "Vault",
    "__version__",
    "redact",
    "restore",
]

__version__ = "0.1.0"

logging.getLogger(__name__).addHandler(logging.NullHandler())
