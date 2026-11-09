"""Detectors for account data in a line of text.

Each detector returns ``Hit`` objects. A Hit carries the full PAN only in a private field
used for de-duplication and unique counting; ``masked`` is what reports show. CVV and PIN
values are never kept at all, only their length.

Detection is deliberately conservative about what it calls a PAN (13-19 digits, Luhn, known
brand range, not a degenerate number, not glued to other digits or letters) and deliberately
broad about sensitive authentication data, because the cost of the two mistakes differs:
a false PAN wastes an analyst's minute, a missed CVV is a prohibited-storage violation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .cards import (KNOWN_TEST_PANS, MAX_PAN, MIN_PAN, brand_of_prefix, is_probable_pan, luhn_valid,
                    mask_pan, max_visible)

# Kinds of hit
PAN = "PAN"                       # full primary account number in clear text
TRACK = "TRACK_DATA"              # magnetic-stripe / chip equivalent track 1 or 2
CVV = "CVV"                       # card verification code (CVV2/CVC2/CID/CAV2)
PIN = "PIN"                       # PIN or PIN block
MASK_EXPOSED = "MASK_OVEREXPOSED"  # masked PAN showing more than BIN + last four

SAD_KINDS = frozenset({TRACK, CVV, PIN})


@dataclass
class Hit:
    kind: str
    start: int
    end: int
    masked: str
    brand: str | None = None
    confidence: str = "high"          # high | medium
    detail: str = ""
    test_pan: bool = False
    value_span: tuple[int, int] | None = None  # CVV/PIN value position (for redaction only)
    _pan: str | None = field(default=None, repr=False, compare=False)


# Words that, near a number, make it far more likely to be a card number.
CONTEXT_RE = re.compile(
    r"(?i)(card|\bcc\b|cc[_-]?(num|no)|\bpan\b|visa|master\s?card|\bmc\b|amex|discover|\bjcb\b|"
    r"diners|unionpay|maestro|credit|debit|acct|account[_ ]?(no|num)|payment|\bccn\b)")
CONTEXT_WINDOW = 48  # characters before the number

# Digit runs, optionally split into groups by single spaces or hyphens: "4111 1111 1111 1111".
GROUPED_DIGITS_RE = re.compile(r"\d+(?:[ -]\d+)*")

# Track 1: %B<PAN>^<NAME>^<YYMM><service code>...   Track 2: ;<PAN>=<YYMM><service code>...
TRACK1_RE = re.compile(r"%?B(\d{12,19})\^([^\^\r\n]{2,26})\^(\d{4})(\d{3})[^?\s]*\??")
TRACK2_RE = re.compile(r"(?:;|(?<!\d))(\d{12,19})=(\d{4})(\d{3})\d*\??")

# Masked PAN: leading digits, mask characters, trailing digits (separators allowed).
MASKED_RE = re.compile(r"(?<![\w*#])(\d(?:[ -]?\d){3,9})[ -]?((?:[*Xx#•][ -]?){2,13})(\d(?:[ -]?\d){0,6})(?![\w*#])")

# Card verification code labels. "Strong" labels are unambiguous on their own. "Weak"
# labels (cid, csc, pin) collide with ordinary words (customer id, Content-ID, push
# notification pins) and only count when a PAN or track is on the same line.
_KV = r"""["']?\s*(?:[:=]|=>)\s*["']?"""
CVV_STRONG = r"cvv2?|cvc2?|cav2|cvn2?|card[_ -]?security[_ -]?code|security[_ -]?code|card[_ -]?verification(?:[_ -]?(?:value|code|number))?|card[_ -]?code"
CVV_WEAK = r"cid|csc|cvd"
CVV_KV_STRONG = re.compile(rf"(?i)(?<![\w])({CVV_STRONG})(?![\w]){_KV}(\d{{3,4}})(?!\d)")
CVV_KV_WEAK = re.compile(rf"(?i)(?<![\w])({CVV_WEAK})(?![\w]){_KV}(\d{{3,4}})(?!\d)")
CVV_XML = re.compile(rf"(?i)<({CVV_STRONG}|{CVV_WEAK})>\s*(\d{{3,4}})\s*</")
PIN_BLOCK_KV = re.compile(rf"(?i)(?<![\w])(pin[_ -]?block|encrypted[_ -]?pin|epb)(?![\w]){_KV}([0-9A-F]{{16}}|[0-9A-F]{{32}})(?![0-9A-F])")
PIN_KV_WEAK = re.compile(rf"(?i)(?<![\w])(pin|pin[_ -]?code|pin[_ -]?number)(?![\w]){_KV}(\d{{4,12}})(?!\d)")

# Column headers (normalised: lower case, letters and digits only) that hold SAD or PANs.
CVV_COLUMNS = frozenset({"cvv", "cvv2", "cvc", "cvc2", "cav2", "cvn", "cid", "csc", "cvd", "securitycode",
                         "cardsecuritycode", "cardverificationvalue", "cardverificationcode", "cardcode"})
PIN_COLUMNS = frozenset({"pin", "pinblock", "encryptedpin", "pincode"})
PAN_COLUMNS = frozenset({"pan", "cardnumber", "cardno", "ccnumber", "ccnum", "cc", "creditcard",
                         "creditcardnumber", "cardnum", "primaryaccountnumber", "card", "debitcard",
                         "cardonfile", "ccno"})


def norm_header(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _has_context(line: str, start: int) -> bool:
    return bool(CONTEXT_RE.search(line[max(0, start - CONTEXT_WINDOW):start]))


def _boundary_ok(line: str, start: int, end: int) -> bool:
    """A PAN must not be glued to letters, other digits, or be the fraction of a decimal."""
    before = line[start - 1] if start > 0 else ""
    after = line[end] if end < len(line) else ""
    if before.isalnum() or after.isalnum() or before == "_" or after == "_":
        return False
    if before == "." and start > 1 and line[start - 2].isdigit():
        return False
    if after == "." and end + 1 < len(line) and line[end + 1].isdigit():
        return False
    return True


# Group-length patterns printed on cards and receipts. When a run of grouped digits could
# be read several ways ("4111 1111 1111 1111 123" is also a 19-digit number), a reading
# with a standard layout wins over a longer one.
STANDARD_GROUPS = frozenset({(4, 4, 4, 4), (4, 6, 5), (4, 6, 4), (4, 4, 4, 4, 3), (4, 4, 4, 4, 2),
                             (4, 4, 4, 4, 1), (4, 3, 3, 3), (4, 4, 4, 3), (4, 4, 4, 2), (4, 4, 5), (4, 4, 6)})


def find_pans(line: str, context_hint: bool = False) -> list[Hit]:
    """Find clear-text PANs, tolerating space/hyphen grouping ("4111-1111-1111-1111").

    A grouped run can hold a PAN followed by other numbers ("4111 1111 1111 1111 1229"),
    so for each starting group we look at every window of whole groups that is a valid PAN
    with one consistent separator. A window in a standard card layout wins; otherwise the
    longest. Scanning then continues after the chosen window.
    """
    hits: list[Hit] = []
    for m in GROUPED_DIGITS_RE.finditer(line):
        groups = [(g.start() + m.start(), g.end() + m.start()) for g in re.finditer(r"\d+", m.group(0))]
        i = 0
        while i < len(groups):
            candidates = []
            for j in range(i, len(groups)):
                s, e = groups[i][0], groups[j][1]
                raw = line[s:e]
                if len(set(re.findall(r"[ -]", raw))) > 1:
                    break
                digits = re.sub(r"[ -]", "", raw)
                if len(digits) > MAX_PAN:
                    break
                if len(digits) < MIN_PAN:
                    continue
                ok, brand = is_probable_pan(digits)
                if ok:
                    layout = tuple(b - a for a, b in groups[i:j + 1])
                    candidates.append((len(layout) == 1 or layout in STANDARD_GROUPS, len(digits), j, s, e, digits, brand))
            # A window must not be glued to letters or digits ("ID4111..." or a decimal).
            candidates = [c for c in candidates if _boundary_ok(line, c[3], c[4])]
            if candidates:
                _, _, j, s, e, digits, brand = max(candidates)
                strong = context_hint or _has_context(line, s)
                hits.append(Hit(PAN, s, e, mask_pan(digits), brand, "high" if strong else "medium",
                                "grouped" if (e - s) != len(digits) else "", digits in KNOWN_TEST_PANS,
                                _pan=digits))
                i = j + 1
            else:
                i += 1
    return hits


def find_tracks(line: str) -> list[Hit]:
    hits: list[Hit] = []
    for m in TRACK1_RE.finditer(line):
        ok, brand = is_probable_pan(m.group(1))
        if ok:
            hits.append(Hit(TRACK, m.start(), m.end(), mask_pan(m.group(1)), brand, "high",
                            "Track 1 (PAN, name, expiry, service code, discretionary data)",
                            m.group(1) in KNOWN_TEST_PANS, _pan=m.group(1)))
    for m in TRACK2_RE.finditer(line):
        ok, brand = is_probable_pan(m.group(1))
        yymm = m.group(2)
        if ok and 1 <= int(yymm[2:]) <= 12:
            hits.append(Hit(TRACK, m.start(), m.end(), mask_pan(m.group(1)), brand, "high",
                            "Track 2 equivalent (PAN, expiry, service code, discretionary data)",
                            m.group(1) in KNOWN_TEST_PANS, _pan=m.group(1)))
    return hits


def find_masked(line: str) -> tuple[list[Hit], int]:
    """Return (over-exposed masked PANs, count of compliant masked PANs)."""
    hits: list[Hit] = []
    compliant = 0
    for m in MASKED_RE.finditer(line):
        lead = re.sub(r"[ -]", "", m.group(1))
        stars = re.sub(r"[ -]", "", m.group(2))
        trail = re.sub(r"[ -]", "", m.group(3))
        length = len(lead) + len(stars) + len(trail)
        if not (MIN_PAN <= length <= MAX_PAN) or brand_of_prefix(lead) is None:
            continue
        max_lead, max_trail = max_visible(length)
        if len(lead) <= max_lead and len(trail) <= max_trail:
            compliant += 1
            continue
        shown = lead + "*" * len(stars) + trail
        hits.append(Hit(MASK_EXPOSED, m.start(), m.end(), mask_pan(shown, min(len(lead), 6), min(len(trail), 4)),
                        brand_of_prefix(lead), "high",
                        f"shows first {len(lead)} and last {len(trail)} of {length} digits "
                        f"(maximum is first {max_lead} and last {max_trail})"))
    return hits, compliant


def find_sad(line: str, has_card_on_line: bool) -> list[Hit]:
    """CVV/PIN values next to a label. Values are never retained, only their length."""
    hits: list[Hit] = []
    regexes = [(CVV_KV_STRONG, CVV), (CVV_XML, CVV), (PIN_BLOCK_KV, PIN)]
    if has_card_on_line:
        regexes += [(CVV_KV_WEAK, CVV), (PIN_KV_WEAK, PIN)]
    seen: set[int] = set()
    for rx, kind in regexes:
        for m in rx.finditer(line):
            if m.start(2) in seen:
                continue
            seen.add(m.start(2))
            label = m.group(1)
            hits.append(Hit(kind, m.start(), m.end(), "*" * len(m.group(2)), None, "high",
                            f"value labelled '{label}' ({len(m.group(2))} chars)",
                            value_span=(m.start(2), m.end(2))))
    return hits


def scan_line(line: str, context_hint: bool = False) -> tuple[list[Hit], int]:
    """Run every detector on one line. Returns (hits, compliant masked count).

    PAN hits that sit inside a track-data hit are dropped (the track hit already covers them).
    """
    tracks = find_tracks(line)
    pans = [p for p in find_pans(line, context_hint)
            if not any(t.start <= p.start < t.end for t in tracks)]
    masked, compliant = find_masked(line)
    sad = find_sad(line, bool(tracks or pans))
    return tracks + pans + masked + sad, compliant


def redact_line(line: str) -> str:
    """Return ``line`` with every PAN masked, track data replaced and CVV/PIN values starred."""
    hits, _ = scan_line(line, context_hint=True)
    out = line
    # Replace right to left so earlier offsets stay valid.
    spans: list[tuple[int, int, str]] = []
    for h in hits:
        if h.kind == PAN:
            spans.append((h.start, h.end, h.masked))
        elif h.kind == TRACK:
            spans.append((h.start, h.end, f"[TRACK DATA REMOVED {h.masked}]"))
        elif h.kind in (CVV, PIN) and h.value_span:
            s, e = h.value_span
            spans.append((s, e, "*" * (e - s)))
    for s, e, rep in sorted(spans, key=lambda t: t[0], reverse=True):
        out = out[:s] + rep + out[e:]
    return out


__all__ = ["Hit", "PAN", "TRACK", "CVV", "PIN", "MASK_EXPOSED", "SAD_KINDS", "scan_line", "redact_line",
           "find_pans", "find_tracks", "find_masked", "find_sad", "norm_header", "CVV_COLUMNS",
           "PIN_COLUMNS", "PAN_COLUMNS", "luhn_valid"]
