"""Card-number primitives: Luhn check, brand (IIN) identification, PCI-compliant masking.

Nothing in this module ever returns or logs a full PAN except ``normalize`` (which the
detectors use internally and immediately discard). Every value that leaves the package
goes through ``mask_pan``.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

# --------------------------------------------------------------------------------------
# Brand ranges (IIN prefixes and valid lengths). Order matters: the first match wins, so
# narrower ranges come before broader ones that overlap them.
# Sources: public card-network acceptance guides and ISO/IEC 7812 IIN registrations.
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Brand:
    name: str
    ranges: tuple[tuple[int, int], ...]  # inclusive (low, high) prefixes of equal length
    lengths: tuple[int, ...]

    def matches(self, pan: str) -> bool:
        if len(pan) not in self.lengths:
            return False
        for low, high in self.ranges:
            width = len(str(low))
            if low <= int(pan[:width]) <= high:
                return True
        return False


BRANDS: tuple[Brand, ...] = (
    Brand("American Express", ((34, 34), (37, 37)), (15,)),
    Brand("Diners Club", ((300, 305), (36, 36), (38, 39)), (14, 16, 17, 18, 19)),
    Brand("JCB", ((3528, 3589),), (16, 17, 18, 19)),
    Brand("Mastercard", ((51, 55), (2221, 2720)), (16,)),
    Brand("Visa", ((4, 4),), (13, 16, 19)),
    Brand("Discover", ((6011, 6011), (644, 649), (65, 65)), (16, 17, 18, 19)),
    Brand("UnionPay", ((62, 62), (81, 81)), (16, 17, 18, 19)),
    Brand("Maestro", ((50, 50), (56, 58), (6304, 6304), (6759, 6759), (676770, 676774)),
          (13, 14, 15, 16, 17, 18, 19)),
)

# Published test PANs from card-network and payment-processor developer documentation.
# They pass Luhn and brand checks, so they are what the bundled sample data uses. Finding
# one in production is still a finding (test data in production), so they are flagged,
# not silently ignored; see --ignore-test-pans.
KNOWN_TEST_PANS: frozenset[str] = frozenset({
    "4111111111111111", "4012888888881881", "4222222222222", "4242424242424242",
    "4000056655665556", "4000000000000002", "5555555555554444", "5105105105105100",
    "2223003122003222", "5200828282828210", "378282246310005", "371449635398431",
    "378734493671000", "6011111111111117", "6011000990139424", "6011981111111113",
    "3530111333300000", "3566002020360505", "3056930009020004", "36227206271667",
    "30569309025904", "38520000023237", "6200000000000005", "6205500000000000004",
})

MIN_PAN, MAX_PAN = 13, 19


def luhn_valid(digits: str) -> bool:
    """Mod-10 check (ISO/IEC 7812-1 Annex B). ``digits`` must contain only 0-9."""
    if not digits.isdigit() or len(digits) < 2:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def luhn_check_digit(partial: str) -> str:
    """Return the digit that makes ``partial + digit`` Luhn-valid (used by the sample generator)."""
    for d in "0123456789":
        if luhn_valid(partial + d):
            return d
    raise ValueError("unreachable")  # pragma: no cover


def brand_of(pan: str) -> str | None:
    for brand in BRANDS:
        if brand.matches(pan):
            return brand.name
    return None


def brand_of_prefix(prefix: str) -> str | None:
    """Best-effort brand for a masked PAN where only the leading digits are visible."""
    for brand in BRANDS:
        for low, high in brand.ranges:
            width = len(str(low))
            if len(prefix) >= width and low <= int(prefix[:width]) <= high:
                return brand.name
    return None


def is_degenerate(pan: str) -> bool:
    """Reject numbers no issuer would assign: one repeated digit, or a straight run."""
    if len(set(pan)) == 1:
        return True
    steps = {(int(b) - int(a)) % 10 for a, b in zip(pan, pan[1:])}
    return steps in ({1}, {9})


def is_probable_pan(digits: str) -> tuple[bool, str | None]:
    """Return (is_pan, brand). A PAN must be 13-19 digits, Luhn-valid, in a known brand range."""
    if not (MIN_PAN <= len(digits) <= MAX_PAN) or not digits.isdigit():
        return False, None
    if is_degenerate(digits) or not luhn_valid(digits):
        return False, None
    brand = brand_of(digits)
    return brand is not None, brand


def max_visible(length: int) -> tuple[int, int]:
    """Most digits PCI DSS 3.4.1 lets you display: BIN + last four.

    Six leading digits for any PAN; eight for PANs of 16+ digits, reflecting the move to
    8-digit BINs (PCI SSC FAQ 1091). Returns (leading, trailing).
    """
    return (8 if length >= 16 else 6), 4


def mask_pan(pan: str, lead: int = 6, trail: int = 4) -> str:
    """Mask to first ``lead`` and last ``trail`` digits (default BIN-6 + last 4)."""
    if len(pan) <= lead + trail:
        return "*" * len(pan)
    return pan[:lead] + "*" * (len(pan) - lead - trail) + pan[-trail:]


class PanFingerprinter:
    """Counts unique PANs without storing them.

    HMAC-SHA256 under a random key generated per run and never written anywhere. Plain
    hashes of PANs are brute-forceable (the keyspace is small once BIN and last four are
    known), which is why PCI DSS 3.5.1.1 requires *keyed* hashes; the same logic applies
    to a scanner's own output, so fingerprints are never emitted.
    """

    def __init__(self, key: bytes | None = None) -> None:
        self._key = key if key is not None else os.urandom(32)

    def fingerprint(self, pan: str) -> str:
        return hmac.new(self._key, pan.encode("ascii"), hashlib.sha256).hexdigest()
