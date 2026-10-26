"""Unit tests for policy_linter. Run from the project folder: python -m unittest -v"""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import date
from pathlib import Path

from policy_linter.checks import (ANNEX_A_2022, LintConfig, health_score, load_owners,
                                  next_review_date, run_all)
from policy_linter.cli import main
from policy_linter.model import (add_months, load_library, parse_glossary, parse_policy,
                                 slugify, version_key)

AS_OF = date(2026, 10, 25)
SAMPLE = Path(__file__).resolve().parents[1] / "sample_data"

BODY = """
# {title}

## Purpose
Protect Information Assets.

## Scope
All staff.

## Roles and responsibilities
Owner maintains it.

## Compliance
Monitored by internal audit.

## Exceptions
Via the risk acceptance process.

## Review
Annually.

{extra}

## Revision history

| Version | Date | Author | Change |
|---|---|---|---|
{history}
"""


def policy_text(pid="POL-AA-001", title="Alpha Policy", version="1.0", status="approved",
                owner="CISO", approver="Risk Committee", approved="2026-03-01", reviewed="2026-03-01",
                cycle="12", extra="", history="| 1.0 | 2026-03-01 | Owner | First issue |",
                more_meta="") -> str:
    meta = [f"id: {pid}", f"title: {title}", f"version: {version}", f"status: {status}",
            f"owner: {owner}", f"approver: {approver}"]
    if approved:
        meta.append(f"approved_on: {approved}")
    if reviewed:
        meta.append(f"last_reviewed: {reviewed}")
    if cycle:
        meta.append(f"review_cycle_months: {cycle}")
    if more_meta:
        meta.append(more_meta)
    return "---\n" + "\n".join(meta) + "\n---\n" + BODY.format(title=title, extra=extra, history=history)


class LibraryCase(unittest.TestCase):
    """Builds a throwaway policy folder per test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name: str, text: str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def lint(self, **cfg):
        lib = load_library(self.root)
        findings, suppressed = run_all(lib, LintConfig(as_of=AS_OF, **cfg))
        return findings, suppressed

    def codes(self, **cfg) -> list[str]:
        return [f.code for f in self.lint(**cfg)[0]]


class TestHelpers(unittest.TestCase):
    def test_add_months_clamps_day(self):
        self.assertEqual(add_months(date(2026, 1, 31), 1), date(2026, 2, 28))
        self.assertEqual(add_months(date(2024, 1, 31), 1), date(2024, 2, 29))
        self.assertEqual(add_months(date(2025, 11, 20), 12), date(2026, 11, 20))
        self.assertEqual(add_months(date(2026, 10, 15), 3), date(2027, 1, 15))

    def test_slugify_matches_github(self):
        self.assertEqual(slugify("Escalation matrix"), "escalation-matrix")
        self.assertEqual(slugify("Roles & Responsibilities"), "roles--responsibilities")
        self.assertEqual(slugify("`Code` *style*"), "code-style")

    def test_version_key(self):
        self.assertEqual(version_key("2.1"), (2, 1))
        self.assertEqual(version_key("v1.10"), (1, 10))
        self.assertGreater(version_key("1.10"), version_key("1.9"))
        self.assertIsNone(version_key("draft"))

    def test_annex_a_has_93_controls(self):
        self.assertEqual(len(ANNEX_A_2022), 93)
        self.assertIn("A.8.34", ANNEX_A_2022)
        self.assertNotIn("A.9.2.3", ANNEX_A_2022)

    def test_health_score_bounds(self):
        self.assertEqual(health_score([], 5), 100)
        self.assertEqual(health_score([], 0), 0)


class TestParser(LibraryCase):
    def test_front_matter_lists_and_revisions(self):
        p = self.write("a.md", policy_text(more_meta="iso27001: [A.5.1, A.5.2]",
                                           history="| 1.0 | 2025-01-01 | Owner | First |\n"
                                                   "| 1.1 | 2026-03-01 | Owner | Update |"))
        pol = parse_policy(p, self.root)
        self.assertEqual(pol.id, "POL-AA-001")
        self.assertEqual(pol.get_list("iso27001"), ["A.5.1", "A.5.2"])
        self.assertEqual([r.version for r in pol.revisions], ["1.0", "1.1"])
        self.assertEqual(pol.revisions[1].date, date(2026, 3, 1))

    def test_block_list_and_bad_line(self):
        text = "---\nid: POL-AA-001\niso27001:\n  - A.5.1\n  - A.8.2\nthis is not yaml\n---\n# T\n"
        pol = parse_policy(self.write("a.md", text), self.root)
        self.assertEqual(pol.get_list("iso27001"), ["A.5.1", "A.8.2"])
        self.assertTrue(pol.meta_errors)

    def test_code_blocks_are_ignored(self):
        extra = "```\nSee POL-ZZ-999 and the [missing](nowhere.md) file. XYZ\n```"
        pol = parse_policy(self.write("a.md", policy_text(extra=extra)), self.root)
        self.assertEqual(pol.references, [])
        self.assertNotIn("XYZ", pol.acronyms_used)

    def test_glossary_parsing_and_duplicates(self):
        g = self.write("g.md", "- **Asset**: a thing\n- **Multi-Factor Authentication** (MFA): two factors\n"
                               "- **asset**: something else\n")
        gl = parse_glossary(g)
        self.assertIn("MFA", gl.acronyms)
        self.assertEqual(gl.duplicates, [("asset", 3)])


class TestGovernance(LibraryCase):
    def test_clean_policy_has_no_findings(self):
        self.write("a.md", policy_text())
        self.assertEqual(self.codes(), [])

    def test_missing_owner_and_self_approval(self):
        self.write("a.md", policy_text(owner=""))
        self.write("b.md", policy_text(pid="POL-BB-001", owner="CISO", approver="ciso"))
        codes = self.codes()
        self.assertIn("MISSING_OWNER", codes)
        self.assertIn("SELF_APPROVED", codes)

    def test_owner_register(self):
        self.write("a.md", policy_text(owner="Security Architect"))
        self.write("b.md", policy_text(pid="POL-BB-001", owner="Ghost Role"))
        reg = self.write("owners.csv", "role,holder,status\nSecurity Architect,,vacant\n")
        codes = self.codes(owners=load_owners(reg))      # only *.md files are policies
        self.assertIn("OWNER_VACANT", codes)
        self.assertIn("OWNER_NOT_IN_REGISTER", codes)

    def test_duplicate_id_flags_both_files(self):
        self.write("a.md", policy_text())
        self.write("b.md", policy_text(title="Beta"))
        self.assertEqual(self.codes().count("DUPLICATE_ID"), 2)

    def test_invalid_control_and_bad_dates(self):
        self.write("a.md", policy_text(approved="2026-13-01", more_meta="iso27001: [A.9.2.3, A.5.15]"))
        codes = self.codes()
        self.assertIn("INVALID_CONTROL_REF", codes)
        self.assertIn("BAD_DATE", codes)

    def test_no_front_matter(self):
        self.write("a.md", "# Just a heading\n\nSome text.\n")
        self.assertIn("NO_FRONT_MATTER", self.codes())


class TestCurrency(LibraryCase):
    def test_overdue_and_due_soon(self):
        self.write("a.md", policy_text(reviewed="2025-06-30", approved="2025-06-30",
                                       history="| 1.0 | 2025-06-30 | Owner | First |"))
        self.write("b.md", policy_text(pid="POL-BB-001", reviewed="2025-11-20", approved="2025-11-20",
                                       history="| 1.0 | 2025-11-20 | Owner | First |"))
        findings, _ = self.lint()
        by = {f.policy_id: f for f in findings}
        self.assertEqual(by["POL-AA-001"].code, "REVIEW_OVERDUE")
        self.assertIn("117 days overdue", by["POL-AA-001"].message)
        self.assertEqual(by["POL-BB-001"].code, "REVIEW_DUE_SOON")

    def test_explicit_next_review_wins(self):
        p = parse_policy(self.write("a.md", policy_text(more_meta="next_review: 2026-12-01")), self.root)
        self.assertEqual(next_review_date(p, LintConfig(as_of=AS_OF)), date(2026, 12, 1))

    def test_custom_cycle(self):
        self.write("a.md", policy_text(cycle="6"))      # reviewed 2026-03-01 + 6 months = 2026-09-01
        self.assertIn("REVIEW_OVERDUE", self.codes())

    def test_stale_draft_and_future_date(self):
        self.write("a.md", policy_text(status="draft", approved="", reviewed="", version="0.2",
                                       history="| 0.1 | 2026-01-10 | Owner | Draft |\n| 0.2 | 2026-02-01 | Owner | Edits |"))
        self.write("b.md", policy_text(pid="POL-BB-001", reviewed="2027-01-01"))
        codes = self.codes()
        self.assertIn("STALE_DRAFT", codes)
        self.assertIn("FUTURE_DATE", codes)


class TestVersions(LibraryCase):
    def test_version_drift_and_unapproved_change(self):
        self.write("a.md", policy_text(history="| 1.0 | 2026-03-01 | Owner | First |\n"
                                               "| 1.1 | 2026-07-03 | Owner | Quiet edit |"))
        codes = self.codes()
        self.assertIn("VERSION_DRIFT", codes)
        self.assertIn("UNAPPROVED_CHANGE", codes)

    def test_out_of_order_history_uses_highest_version(self):
        self.write("a.md", policy_text(version="1.2", history="| 1.0 | 2025-01-01 | Owner | a |\n"
                                                              "| 1.2 | 2026-03-01 | Owner | c |\n"
                                                              "| 1.1 | 2025-06-01 | Owner | b |"))
        codes = self.codes()
        self.assertIn("HISTORY_ORDER", codes)
        self.assertNotIn("VERSION_DRIFT", codes)

    def test_missing_history_and_bad_version(self):
        text = policy_text(version="final").split("## Revision history")[0]
        self.write("a.md", text)
        codes = self.codes()
        self.assertIn("NO_REVISION_HISTORY", codes)
        self.assertIn("BAD_VERSION", codes)


class TestReferences(LibraryCase):
    def test_broken_reference_retired_draft_and_stale_pin(self):
        self.write("a.md", policy_text(version="2.0", history="| 2.0 | 2026-03-01 | Owner | x |",
                                       extra="See POL-ZZ-999, POL-RR-001, POL-DD-001 and POL-BB-001 v1.0."))
        self.write("b.md", policy_text(pid="POL-BB-001", version="1.3",
                                       history="| 1.3 | 2026-03-01 | Owner | x |"))
        self.write("r.md", policy_text(pid="POL-RR-001", status="retired"))
        self.write("d.md", policy_text(pid="POL-DD-001", status="draft", approved="", reviewed=""))
        codes = self.codes()
        for code in ("BROKEN_REFERENCE", "REFERENCE_TO_RETIRED", "REFERENCE_TO_DRAFT",
                     "STALE_PINNED_REFERENCE"):
            self.assertIn(code, codes)

    def test_links_and_anchors(self):
        self.write("a.md", policy_text(extra="[ok](b.md#purpose) [bad file](missing.md) "
                                             "[bad anchor](b.md#nope) [self](#scope) [web](https://example.org)"))
        self.write("b.md", policy_text(pid="POL-BB-001"))
        findings, _ = self.lint()
        codes = [f.code for f in findings]
        self.assertEqual(codes.count("BROKEN_LINK"), 1)
        self.assertEqual(codes.count("BROKEN_ANCHOR"), 1)

    def test_retired_documents_are_not_linted_for_references(self):
        self.write("r.md", policy_text(status="retired", extra="See POL-ZZ-999."))
        self.assertNotIn("BROKEN_REFERENCE", self.codes())


class TestTermsAndStructure(LibraryCase):
    def test_undefined_acronym_and_inline_definition(self):
        self.write("a.md", policy_text(extra="Use Privileged Access Management (PAM). The KMS holds keys. "
                                             "Staff MUST comply."))
        findings, _ = self.lint()
        undefined = [f.message for f in findings if f.code == "UNDEFINED_TERM"]
        self.assertEqual(len(undefined), 1)
        self.assertIn("KMS", undefined[0])

    def test_glossary_acronyms_and_conflicts(self):
        g = parse_glossary(self.write("glossary.md", "- **Security Incident**: An event that compromises CIA.\n"
                                                     "- **Key Management Service** (KMS): Cloud keys.\n"))
        self.write("a.md", policy_text(extra="The KMS holds keys.\n\n## Definitions\n\n"
                                             "- **Security Incident**: Any alert."))
        codes = self.codes(glossary=g)
        self.assertNotIn("UNDEFINED_TERM", codes)
        self.assertIn("CONFLICTING_DEFINITION", codes)

    def test_missing_section_and_placeholder(self):
        text = policy_text(extra="Call [Insert phone number]. Retention: TBD.").replace("## Exceptions", "## Other")
        self.write("a.md", text)
        codes = self.codes()
        self.assertIn("MISSING_SECTION", codes)
        self.assertEqual(codes.count("PLACEHOLDER_TEXT"), 2)

    def test_inline_suppression(self):
        self.write("a.md", policy_text(extra="<!-- policylint-disable UNDEFINED_TERM -->\nThe KMS holds keys."))
        findings, suppressed = self.lint()
        self.assertEqual([f.code for f in findings], [])
        self.assertEqual(suppressed, 1)


class TestSampleAndCli(unittest.TestCase):
    def run_cli(self, *args: str) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(list(args))
        return code, buf.getvalue()

    def test_sample_library_finds_planted_defects(self):
        with tempfile.TemporaryDirectory() as out:
            code, text = self.run_cli(str(SAMPLE / "policies"), "--owners", str(SAMPLE / "owners.csv"),
                                      "--as-of", "2026-10-25", "--out", out)
            self.assertEqual(code, 0)
            self.assertIn("Documents: 10", text)
            report = json.loads(Path(out, "report.json").read_text())
            found = {f["code"] for f in report["findings"]}
            for planted in ("VERSION_DRIFT", "UNAPPROVED_CHANGE", "REVIEW_OVERDUE", "BROKEN_REFERENCE",
                            "BROKEN_LINK", "BROKEN_ANCHOR", "DUPLICATE_ID", "OWNER_VACANT",
                            "SELF_APPROVED", "REFERENCE_TO_RETIRED", "STALE_PINNED_REFERENCE",
                            "CONFLICTING_DEFINITION", "UNDEFINED_TERM", "PLACEHOLDER_TEXT",
                            "MISSING_SECTION", "INVALID_CONTROL_REF", "STALE_DRAFT", "DUPLICATE_TERM"):
                self.assertIn(planted, found)
            self.assertEqual(report["summary"]["suppressed"], 2)
            self.assertTrue(Path(out, "report.md").read_text().startswith("# Policy library lint report"))

    def test_fail_on_and_github_format(self):
        code, text = self.run_cli(str(SAMPLE / "policies"), "--as-of", "2026-10-25",
                                  "--fail-on", "high", "--format", "github")
        self.assertEqual(code, 2)
        self.assertIn("::error file=", text)

    def test_bad_path(self):
        import contextlib
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["/nonexistent/folder"]), 1)


if __name__ == "__main__":
    unittest.main()
