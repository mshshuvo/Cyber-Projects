"""Turn files on disk into text the detectors can read.

Supported: plain text in any common encoding, gzip, ZIP archives (nested up to a limit),
Office Open XML / OpenDocument files (they are ZIPs of XML), SQLite databases (read row by
row), and other binary files via a ``strings``-style pass, so a POS cache or a core dump is
not silently skipped.

Every file that cannot be fully read is reported as a *coverage gap*. PCI DSS 12.5.2
asks for all locations of stored account data, so "we couldn't open it" is a result,
not a non-event: an encrypted ZIP on a file share is exactly where card data hides.
"""
from __future__ import annotations

import fnmatch
import gzip
import io
import os
import re
import sqlite3
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterator

DEFAULT_EXCLUDES = (".git/*", "*/.git/*", "__pycache__/*", "*/__pycache__/*", "node_modules/*", "*/node_modules/*")
OFFICE_EXT = {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".docm", ".xlsm"}
ZIP_EXT = {".zip", ".jar"} | OFFICE_EXT
XML_MEMBER = re.compile(r"\.(xml|rels)$", re.I)

# Office XML: end of a paragraph, row or shared string becomes a newline; end of a cell a
# tab; every other tag disappears so text split across runs (<w:t>4111</w:t><w:t> 1111</w:t>)
# is rejoined.
_BLOCK_END = re.compile(r"</(?:w:p|a:p|text:p|text:h|row|si|table:table-row)>|<w:br/>|<text:line-break/>", re.I)
_CELL_END = re.compile(r"</(?:c|w:tc|table:table-cell)>|<w:tab/>", re.I)
_TAG = re.compile(r"<[^>]+>")
_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e\t]{8,}")


@dataclass
class Limits:
    max_file_bytes: int = 50 * 1024 * 1024
    max_archive_depth: int = 2
    max_archive_members: int = 2000
    max_expanded_bytes: int = 200 * 1024 * 1024  # per top-level file, guards against zip bombs
    max_ratio: int = 200                         # compression ratio above which a member is refused
    scan_binary: bool = True


@dataclass
class Document:
    """One readable unit: a file, or a member inside an archive."""
    path: str                  # display path relative to the scan root; archive members use "!"
    container: str             # text | office | sqlite | binary-strings
    lines: list[str]
    ext: str = ""


@dataclass
class Gap:
    path: str
    reason: str


@dataclass
class ExtractResult:
    documents: list[Document] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    files_seen: int = 0


def decode(data: bytes) -> str:
    """Decode bytes, honouring BOMs, falling back to latin-1 (which never fails)."""
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def is_binary(data: bytes) -> bool:
    sample = data[:8192]
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        return False
    return b"\x00" in sample


def xml_to_text(xml: str) -> str:
    xml = _BLOCK_END.sub("\n", xml)
    xml = _CELL_END.sub("\t", xml)
    text = _TAG.sub("", xml)
    return (text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
            .replace("&quot;", '"').replace("&apos;", "'"))


def binary_strings(data: bytes) -> list[str]:
    """Printable ASCII runs of 8+ characters, one per line, like ``strings -n 8``."""
    return [m.group(0).decode("ascii") for m in _PRINTABLE_RUN.finditer(data)]


SQLITE_MAGIC = b"SQLite format 3\x00"


def sqlite_records(data: bytes, max_rows: int = 200_000) -> list[str]:
    """Render every row of every table as one line: ``table[rowN] col=value col=value``.

    A strings pass is not enough for databases: SQLite packs a row's values back to back,
    so a lane id, a PAN and an expiry come out as one run of digits ("014-0362000000000000052811").
    Reading the rows properly keeps column names next to values, which is also what lets
    a ``pan`` or ``cvv`` column count as context. The copy is opened read-only.
    """
    fd, tmp = tempfile.mkstemp(suffix=".db")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        con = sqlite3.connect(f"file:{tmp}?mode=ro&immutable=1", uri=True)
        try:
            lines: list[str] = []
            tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
            for t in tables:
                cur = con.execute(f'SELECT * FROM "{t.replace(chr(34), chr(34) * 2)}"')
                cols = [d[0] for d in cur.description]
                for n, row in enumerate(cur, start=1):
                    if len(lines) >= max_rows:
                        raise ValueError(f"more than {max_rows} rows; scan the database with a dedicated tool")
                    vals = " ".join(f"{c}={'' if v is None else (v.decode('latin-1') if isinstance(v, bytes) else v)}"
                                    for c, v in zip(cols, row))
                    lines.append(f"{t}[row{n}] {vals}")
            return lines
        finally:
            con.close()
    finally:
        os.unlink(tmp)


def excluded(rel: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(rel, p) for p in patterns)


class Extractor:
    def __init__(self, limits: Limits | None = None, excludes: tuple[str, ...] = DEFAULT_EXCLUDES) -> None:
        self.limits = limits or Limits()
        self.excludes = excludes

    # ---- public -----------------------------------------------------------------------
    def walk(self, root: Path) -> ExtractResult:
        result = ExtractResult()
        root = root.resolve()
        files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
        base = root.parent if root.is_file() else root
        for f in files:
            rel = PurePosixPath(f.relative_to(base)).as_posix()
            if excluded(rel, self.excludes):
                continue
            if f.is_symlink():
                result.gaps.append(Gap(rel, "symbolic link not followed; scan its target directly"))
                continue
            result.files_seen += 1
            try:
                size = f.stat().st_size
                if size > self.limits.max_file_bytes:
                    result.gaps.append(Gap(rel, f"larger than {self.limits.max_file_bytes // (1024 * 1024)} MB limit "
                                                f"({size // (1024 * 1024)} MB); raise --max-mb or scan separately"))
                    continue
                data = f.read_bytes()
            except OSError as exc:
                result.gaps.append(Gap(rel, f"unreadable: {exc.strerror or exc}"))
                continue
            budget = [self.limits.max_expanded_bytes]
            self._read(rel, f.suffix.lower(), data, 0, budget, result)
        return result

    # ---- internals --------------------------------------------------------------------
    def _read(self, rel: str, ext: str, data: bytes, depth: int, budget: list[int], out: ExtractResult) -> None:
        if ext == ".gz" or data[:2] == b"\x1f\x8b":
            try:
                inner = self._gunzip(data, budget)
            except (OSError, EOFError, ValueError) as exc:
                out.gaps.append(Gap(rel, f"gzip could not be expanded: {exc}"))
                return
            inner_ext = PurePosixPath(rel[:-3] if rel.endswith(".gz") else rel).suffix.lower()
            self._read(rel, inner_ext if inner_ext != ".gz" else "", inner, depth, budget, out)
            return
        if ext in ZIP_EXT or data[:4] == b"PK\x03\x04":
            self._read_zip(rel, ext, data, depth, budget, out)
            return
        if data.startswith(SQLITE_MAGIC):
            try:
                out.documents.append(Document(rel, "sqlite", sqlite_records(data), ext))
                return
            except (sqlite3.Error, ValueError) as exc:
                out.gaps.append(Gap(rel, f"SQLite database could not be read row by row ({exc}); "
                                         "fell back to a strings pass, which can miss values"))
        if is_binary(data):
            if not self.limits.scan_binary:
                out.gaps.append(Gap(rel, "binary file skipped (--no-binary)"))
                return
            out.documents.append(Document(rel, "binary-strings", binary_strings(data), ext))
            return
        out.documents.append(Document(rel, "text", decode(data).splitlines(), ext))

    def _gunzip(self, data: bytes, budget: list[int]) -> bytes:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            inner = gz.read(budget[0] + 1)
        if len(inner) > budget[0]:
            raise ValueError("expanded size exceeds the per-file budget (possible decompression bomb)")
        budget[0] -= len(inner)
        return inner

    def _read_zip(self, rel: str, ext: str, data: bytes, depth: int, budget: list[int], out: ExtractResult) -> None:
        if depth >= self.limits.max_archive_depth:
            out.gaps.append(Gap(rel, f"nested archive deeper than {self.limits.max_archive_depth} levels not expanded"))
            return
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            out.gaps.append(Gap(rel, "corrupt or unsupported ZIP"))
            return
        office = ext in OFFICE_EXT
        with zf:
            members = [i for i in zf.infolist() if not i.is_dir()]
            if len(members) > self.limits.max_archive_members:
                out.gaps.append(Gap(rel, f"{len(members)} members exceeds limit of {self.limits.max_archive_members}"))
                return
            office_text: list[str] = []
            for info in sorted(members, key=lambda i: i.filename):
                mrel = f"{rel}!{info.filename}"
                if info.flag_bits & 0x1:
                    out.gaps.append(Gap(mrel, "encrypted archive member; cannot be inspected. "
                                              "Encrypted is not the same as out of scope: confirm contents and key custody"))
                    continue
                if info.compress_size and info.file_size / max(info.compress_size, 1) > self.limits.max_ratio:
                    out.gaps.append(Gap(mrel, "compression ratio too high (possible decompression bomb); not expanded"))
                    continue
                if info.file_size > budget[0]:
                    out.gaps.append(Gap(mrel, "expanded size exceeds the per-file budget; not expanded"))
                    continue
                try:
                    blob = zf.read(info)
                except (zipfile.BadZipFile, RuntimeError, OSError, NotImplementedError) as exc:
                    out.gaps.append(Gap(mrel, f"member unreadable: {exc}"))
                    continue
                budget[0] -= len(blob)
                if office:
                    if XML_MEMBER.search(info.filename):
                        office_text.extend(xml_to_text(decode(blob)).splitlines())
                    continue
                self._read(mrel, PurePosixPath(info.filename).suffix.lower(), blob, depth + 1, budget, out)
            if office:
                out.documents.append(Document(rel, "office", office_text, ext))


def iter_lines(doc: Document) -> Iterator[tuple[int, str]]:
    for n, line in enumerate(doc.lines, start=1):
        yield n, line
