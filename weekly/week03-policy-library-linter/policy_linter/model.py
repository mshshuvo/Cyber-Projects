"""Parse a Markdown policy library into structured objects.

A policy is a Markdown file with a small front-matter block:

    ---
    id: POL-AC-001
    title: Access Control Policy
    version: 2.1
    status: approved            # draft | approved | retired
    owner: Head of IT Operations
    approver: Chief Risk Officer
    approved_on: 2026-03-14
    last_reviewed: 2026-03-14
    review_cycle_months: 12
    iso27001: [A.5.15, A.5.18, A.8.2]
    ---

The parser is deliberately a strict, tiny subset of YAML (``key: value``, inline
``[a, b]`` lists and ``- item`` block lists) so the tool needs only the standard library
and so a policy that would confuse a real YAML parser is flagged rather than guessed at.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

DRAFT, APPROVED, RETIRED = "draft", "approved", "retired"
STATUSES = (DRAFT, APPROVED, RETIRED)

#: Default pattern for document identifiers (policy, standard, procedure, guideline).
DEFAULT_ID_PATTERN = r"(?:POL|STD|PRC|GDL)-[A-Z]{2,5}-\d{3}"

_FENCE = re.compile(r"^\s*(```|~~~)")
_HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_LINK = re.compile(r"(?<!!)\[([^\]]+)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_SUPPRESS = re.compile(r"<!--\s*policylint-disable\s+([A-Z_,\s]+?)\s*-->")
_ACRONYM_DEF = re.compile(r"([A-Z][A-Za-z\-]+(?:\s+(?:of|and|for|the|[A-Z][A-Za-z\-]+))*)\s+\(([A-Z][A-Z0-9&]{1,7})\)")
_GLOSSARY_ENTRY = re.compile(r"^\s*[-*]\s+\*\*([^*]+)\*\*\s*(?:\(([A-Z][A-Z0-9&]{1,7})\))?\s*[:—\-]\s*(.+)$")


@dataclass
class Revision:
    """One row of a policy's revision history table."""
    version: str
    date_text: str
    author: str
    summary: str
    line: int

    @property
    def date(self) -> date | None:
        return parse_date(self.date_text)


@dataclass
class Reference:
    """A reference from one policy to another document or section."""
    kind: str               # "id" (POL-XX-000) or "link" (Markdown link)
    target: str             # the id, or the link target as written
    line: int
    pinned_version: str | None = None   # "v1.2" written after an id
    text: str = ""


@dataclass
class Policy:
    """A parsed policy document."""
    path: Path
    rel: str
    meta: dict[str, str | list[str]]
    meta_lines: dict[str, int]
    meta_errors: list[tuple[int, str]]
    lines: list[str]
    headings: list[tuple[int, str, int]] = field(default_factory=list)   # (level, text, line)
    revisions: list[Revision] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)
    definitions: dict[str, str] = field(default_factory=dict)          # term -> definition
    acronyms_defined: set[str] = field(default_factory=set)
    acronyms_used: dict[str, int] = field(default_factory=dict)        # acronym -> first line
    suppressed: set[str] = field(default_factory=set)
    has_front_matter: bool = True

    def get(self, key: str) -> str:
        """Scalar metadata value ('' if absent or a list)."""
        v = self.meta.get(key, "")
        return v if isinstance(v, str) else ""

    def get_list(self, key: str) -> list[str]:
        v = self.meta.get(key, [])
        return v if isinstance(v, list) else ([v] if v else [])

    @property
    def id(self) -> str:
        return self.get("id")

    @property
    def title(self) -> str:
        return self.get("title") or self.path.stem

    @property
    def status(self) -> str:
        return self.get("status").lower()

    @property
    def version(self) -> str:
        return self.get("version")

    def line_of(self, key: str) -> int:
        return self.meta_lines.get(key, 1)

    @property
    def anchors(self) -> set[str]:
        return {slugify(text) for _, text, _ in self.headings}


# --------------------------------------------------------------------------- helpers
def parse_date(text: str) -> date | None:
    """Parse an ISO date (YYYY-MM-DD); return None if missing or malformed."""
    try:
        return date.fromisoformat(text.strip())
    except (ValueError, AttributeError):
        return None


def add_months(d: date, months: int) -> date:
    """Add calendar months, clamping the day (31 Jan + 1 month = 28/29 Feb)."""
    y, m = divmod(d.month - 1 + months, 12)
    year, month = d.year + y, m + 1
    for day in (d.day, 30, 29, 28):
        try:
            return date(year, month, day)
        except ValueError:
            continue
    raise ValueError(f"cannot add {months} months to {d}")


def slugify(heading: str) -> str:
    """GitHub-style heading anchor: lower case, punctuation removed, spaces to hyphens."""
    s = re.sub(r"[`*_]", "", heading.strip().lower())
    s = re.sub(r"[^\w\- ]", "", s)
    return s.replace(" ", "-")


def version_key(v: str) -> tuple[int, ...] | None:
    """'2.1' -> (2, 1). None if not a dotted numeric version."""
    v = v.strip().lstrip("vV")
    if not re.fullmatch(r"\d+(?:\.\d+){0,2}", v):
        return None
    return tuple(int(p) for p in v.split("."))


def _strip_code(lines: list[str]) -> list[str]:
    """Blank out fenced code blocks and inline code so examples aren't linted."""
    out, in_fence = [], False
    for ln in lines:
        if _FENCE.match(ln):
            in_fence = not in_fence
            out.append("")
            continue
        out.append("" if in_fence else re.sub(r"`[^`]*`", "", ln))
    return out


def _parse_front_matter(lines: list[str]):
    """Return (meta, meta_lines, errors, body_start_index)."""
    meta: dict[str, str | list[str]] = {}
    where: dict[str, int] = {}
    errors: list[tuple[int, str]] = []
    if not lines or lines[0].strip() != "---":
        return meta, where, errors, 0, False
    current_list: str | None = None
    for i in range(1, len(lines)):
        raw = lines[i]
        if raw.strip() == "---":
            return meta, where, errors, i + 1, True
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        item = re.match(r"^\s+-\s+(.*)$", raw)
        if item and current_list:
            cast = meta[current_list]
            if isinstance(cast, list):
                cast.append(item.group(1).strip().strip("'\""))
            continue
        kv = re.match(r"^([A-Za-z_][\w\-]*)\s*:\s*(.*?)\s*(?:\s#.*)?$", raw)
        if not kv:
            errors.append((i + 1, f"unreadable front-matter line: {raw.strip()!r}"))
            continue
        key, val = kv.group(1).lower(), kv.group(2)
        if key in meta:
            errors.append((i + 1, f"duplicate front-matter key '{key}'"))
        where[key] = i + 1
        if val == "":
            meta[key], current_list = [], key
        elif val.startswith("["):
            meta[key] = [p.strip().strip("'\"") for p in val.strip("[]").split(",") if p.strip()]
            current_list = None
        else:
            meta[key], current_list = val.strip("'\""), None
    errors.append((1, "front matter is not closed with '---'"))
    return meta, where, errors, len(lines), True


def _parse_revisions(lines: list[str], headings: list[tuple[int, str, int]]) -> list[Revision]:
    """Read the first Markdown table under a 'Revision history' / 'Document control' heading."""
    start = next((ln for _, t, ln in headings
                  if re.search(r"revision|document control|version history", t, re.I)), None)
    if start is None:
        return []
    revs: list[Revision] = []
    cols: list[str] | None = None
    for idx in range(start, len(lines)):           # start is 1-based heading line
        row = lines[idx].strip()
        if _HEADING.match(row):
            break
        if not row.startswith("|"):
            if cols and revs:
                break
            continue
        cells = [c.strip() for c in row.strip("|").split("|")]
        if cols is None:
            cols = [c.lower() for c in cells]
            continue
        if all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
            continue
        rec = dict(zip(cols, cells))
        pick = lambda *names: next((rec[k] for k in rec if any(n in k for n in names)), "")
        revs.append(Revision(version=pick("version", "ver"), date_text=pick("date"),
                             author=pick("author", "by", "owner"),
                             summary=pick("change", "summary", "description"), line=idx + 1))
    return revs


def parse_policy(path: Path, root: Path, id_pattern: str = DEFAULT_ID_PATTERN) -> Policy:
    """Parse one Markdown policy file."""
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    meta, where, errors, body_start, has_fm = _parse_front_matter(lines)
    pol = Policy(path=path, rel=path.relative_to(root).as_posix(), meta=meta,
                 meta_lines=where, meta_errors=errors, lines=lines, has_front_matter=has_fm)
    for m in _SUPPRESS.finditer(text):
        pol.suppressed.update(c.strip() for c in m.group(1).split(",") if c.strip())

    clean = _strip_code(lines)
    id_re = re.compile(rf"\b({id_pattern})(?:\s+v(\d+(?:\.\d+)*))?\b")
    in_defs = False
    for i in range(body_start, len(clean)):
        ln, num = clean[i], i + 1
        h = _HEADING.match(ln)
        if h:
            pol.headings.append((len(h.group(1)), h.group(2).strip(), num))
            in_defs = bool(re.search(r"definition|glossary|terms", h.group(2), re.I))
            continue
        if in_defs:
            g = _GLOSSARY_ENTRY.match(ln)
            if g:
                pol.definitions[g.group(1).strip()] = g.group(3).strip()
                if g.group(2):
                    pol.acronyms_defined.add(g.group(2))
                if re.fullmatch(r"[A-Z][A-Z0-9&]{1,7}", g.group(1).strip()):
                    pol.acronyms_defined.add(g.group(1).strip())
        for m in _LINK.finditer(ln):
            pol.references.append(Reference("link", m.group(2), num, text=m.group(1)))
        for m in id_re.finditer(ln):
            if m.group(1) != pol.id:
                pol.references.append(Reference("id", m.group(1), num,
                                                pinned_version=m.group(2), text=m.group(0)))
        for m in _ACRONYM_DEF.finditer(ln):
            pol.acronyms_defined.add(m.group(2))
        prose = id_re.sub(" ", _LINK.sub(lambda m: m.group(1), ln))
        prose = re.sub(r"<!--.*?-->|https?://\S+", " ", prose)
        for m in re.finditer(r"\b([A-Z][A-Z0-9]{1,7})s?\b", prose):
            tok = m.group(1)
            if sum(ch.isupper() for ch in tok) >= 2:
                pol.acronyms_used.setdefault(tok, num)
    pol.revisions = _parse_revisions(lines, pol.headings)
    return pol


@dataclass
class Glossary:
    """Organisation-wide glossary: defined terms and acronyms."""
    path: Path | None = None
    terms: dict[str, str] = field(default_factory=dict)     # term -> definition
    acronyms: set[str] = field(default_factory=set)
    duplicates: list[tuple[str, int]] = field(default_factory=list)


def parse_glossary(path: Path | None) -> Glossary:
    """Parse '- **Term** (ACR): definition' lines from a glossary Markdown file."""
    g = Glossary(path=path)
    if path is None:
        return g
    for num, ln in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        m = _GLOSSARY_ENTRY.match(ln)
        if not m:
            continue
        term = m.group(1).strip()
        if term.lower() in {t.lower() for t in g.terms}:
            g.duplicates.append((term, num))
        g.terms[term] = m.group(3).strip()
        if m.group(2):
            g.acronyms.add(m.group(2))
        if re.fullmatch(r"[A-Z][A-Z0-9&]{1,7}", term):
            g.acronyms.add(term)
    return g


def load_library(root: Path, id_pattern: str = DEFAULT_ID_PATTERN,
                 exclude: tuple[str, ...] = ("README.md", "glossary.md")) -> list[Policy]:
    """Parse every *.md file under root (recursively), skipping excluded names."""
    files = sorted(p for p in root.rglob("*.md") if p.name.lower() not in {e.lower() for e in exclude})
    return [parse_policy(p, root, id_pattern) for p in files]
