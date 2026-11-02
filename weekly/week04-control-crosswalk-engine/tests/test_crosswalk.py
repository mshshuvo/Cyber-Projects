"""Unit tests for the control crosswalk engine. Run from the project folder: python -m unittest -v"""
from __future__ import annotations

import csv
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from pathlib import Path

from crosswalk.catalog import CIS_IG1, FRAMEWORKS, framework_key, hint_for_unknown, normalize_id
from crosswalk.cli import main
from crosswalk.engine import (DEFICIENT, EFFECTIVE, EXCEPTION, EXCEPTIONS, EXCLUDED, FAILED, NOT_TESTED,
                              PARTIAL, REQ_NO_EVIDENCE, REQ_STALE, SATISFIED, STALE, UNMAPPED, UNTESTED,
                              assess, control_state, equivalents, evidence_state)
from crosswalk.model import Evidence, load_dataset
from crosswalk.report import _at_risk, json_report, markdown_report, matrix_csv

AS_OF = date(2026, 11, 1)
SAMPLE = Path(__file__).resolve().parents[1] / "sample_data"


def ev(result="pass", collected="2026-10-01", valid="2027-01-01", controls=("C1",)) -> Evidence:
    return Evidence("EV-X", "x", list(controls), result,
                    date.fromisoformat(collected) if collected else None,
                    date.fromisoformat(valid) if valid else None)


class Fixture:
    """Write a small dataset to a temp folder and load it."""

    def __init__(self, controls, mappings, evidence, scope=None):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.root = root
        self._write(root / "controls.csv", ["control_id", "title", "domain", "owner", "frequency"], controls)
        self._write(root / "mappings.csv", ["control_id", "framework", "requirement_id", "strength", "rationale"],
                    mappings)
        self._write(root / "evidence.csv", ["evidence_id", "title", "controls", "type", "owner", "collected_on",
                                            "valid_until", "result", "tested_by", "notes"], evidence)
        self.scope = None
        if scope is not None:
            self.scope = root / "scope.json"
            self.scope.write_text(json.dumps(scope), encoding="utf-8")

    @staticmethod
    def _write(path, header, rows):
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(header)
            w.writerows(rows)

    def load(self):
        r = self.root
        return load_dataset(r / "controls.csv", r / "mappings.csv", r / "evidence.csv", self.scope)

    def close(self):
        self.tmp.cleanup()


def ctl(cid, owner="Owner"):
    return [cid, f"Control {cid}", "Domain", owner, "Annual"]


def evrow(eid, controls, result="pass", collected="2026-10-01", valid="2027-01-01", notes=""):
    return [eid, f"Evidence {eid}", controls, "Report", "Owner", collected, valid, result, "IA", notes]


ISO_ONLY = {"frameworks": {"ISO27001": {"include": ["A.5.15", "A.5.18", "A.8.5", "A.8.15"]}}}


class CatalogTests(unittest.TestCase):
    def test_catalog_sizes(self):
        self.assertEqual(len([r for r in FRAMEWORKS["ISO27001"].requirements if r.startswith("A.")]), 93)
        self.assertEqual(len(FRAMEWORKS["CSF2"].requirements), 106)
        self.assertEqual(len(FRAMEWORKS["CIS8"].requirements), 153)
        self.assertEqual(len(FRAMEWORKS["CIS8"].group_members("ig1")), len(CIS_IG1))
        self.assertNotIn("ID.AM-06", FRAMEWORKS["CSF2"].requirements)  # withdrawn in 2.0

    def test_normalize_ids(self):
        self.assertEqual(normalize_id("CSF2", "pr.aa-1"), "PR.AA-01")
        self.assertEqual(normalize_id("CIS8", "CIS 5.1"), "5.1")
        self.assertEqual(normalize_id("ISO27001", "a8.15"), "A.8.15")
        self.assertEqual(normalize_id("ISO27001", "8.15"), "8.15")  # no guessing clause vs Annex A
        self.assertEqual(normalize_id("SOC2", "cc6.1"), "CC6.1")

    def test_framework_aliases(self):
        self.assertEqual(framework_key("nist-csf"), "CSF2")
        self.assertEqual(framework_key("CIS v8"), "CIS8")
        self.assertEqual(framework_key("iso"), "ISO27001")
        self.assertIsNone(framework_key("hipaa"))

    def test_hints_for_legacy_ids(self):
        self.assertIn("2013", hint_for_unknown("ISO27001", "A.12.4.1"))
        self.assertIn("A.8.9", hint_for_unknown("ISO27001", "8.9"))
        self.assertIn("CSF 1.1", hint_for_unknown("CSF2", "PR.AC-07"))
        self.assertIn("5.1-5.6", hint_for_unknown("CIS8", "5.7"))
        self.assertIn("1-18", hint_for_unknown("CIS8", "19.1"))


class EvidenceStateTests(unittest.TestCase):
    def test_states(self):
        self.assertEqual(evidence_state(ev(), AS_OF), EFFECTIVE)
        self.assertEqual(evidence_state(ev("pass_with_exceptions"), AS_OF), EXCEPTION)
        self.assertEqual(evidence_state(ev("fail"), AS_OF), FAILED)
        self.assertEqual(evidence_state(ev("not_tested"), AS_OF), UNTESTED)
        self.assertEqual(evidence_state(ev(valid="2026-10-31"), AS_OF), STALE)
        self.assertEqual(evidence_state(ev(valid="2026-11-01"), AS_OF), EFFECTIVE)  # valid through the day
        self.assertEqual(evidence_state(ev(collected="2026-11-20"), AS_OF), UNTESTED)
        self.assertEqual(evidence_state(ev(collected=""), AS_OF), UNTESTED)

    def test_stale_failure_does_not_count_as_failure(self):
        self.assertEqual(evidence_state(ev("fail", valid="2026-01-01"), AS_OF), STALE)

    def test_control_state_worst_current_result_wins(self):
        self.assertEqual(control_state([EFFECTIVE, FAILED]), FAILED)
        self.assertEqual(control_state([EFFECTIVE, EXCEPTION]), EXCEPTION)
        self.assertEqual(control_state([STALE, EFFECTIVE]), EFFECTIVE)  # newer evidence supersedes
        self.assertEqual(control_state([STALE, UNTESTED]), STALE)
        self.assertEqual(control_state([]), "No evidence")


class EngineTests(unittest.TestCase):
    def run_case(self, mappings, evidence, controls=("C1", "C2"), scope=ISO_ONLY):
        fx = Fixture([ctl(c) for c in controls], mappings, evidence, scope)
        try:
            data = fx.load()
            return data, assess(data, AS_OF)
        finally:
            fx.close()

    def status(self, a, rid, fw="ISO27001"):
        return a.result(fw, rid).status

    def test_full_effective_satisfies(self):
        _, a = self.run_case([["C1", "ISO", "A.8.15", "full", ""]], [evrow("E1", "C1")])
        self.assertEqual(self.status(a, "A.8.15"), SATISFIED)
        self.assertEqual(self.status(a, "A.8.5"), UNMAPPED)

    def test_partial_never_satisfies(self):
        _, a = self.run_case([["C1", "ISO", "A.8.15", "partial", ""], ["C2", "ISO", "A.8.15", "partial", ""]],
                             [evrow("E1", "C1"), evrow("E2", "C2")])
        self.assertEqual(self.status(a, "A.8.15"), PARTIAL)
        self.assertEqual(a.coverage("ISO27001"), 0.0)

    def test_any_failed_mapped_control_makes_deficient(self):
        _, a = self.run_case([["C1", "ISO", "A.5.18", "full", ""], ["C2", "ISO", "A.5.18", "partial", ""]],
                             [evrow("E1", "C1"), evrow("E2", "C2", "fail")])
        self.assertEqual(self.status(a, "A.5.18"), DEFICIENT)
        self.assertIn("C2", a.result("ISO27001", "A.5.18").reason)

    def test_exceptions_stale_untested_no_evidence(self):
        _, a = self.run_case(
            [["C1", "ISO", "A.8.5", "full", ""], ["C2", "ISO", "A.8.15", "full", ""],
             ["C3", "ISO", "A.5.15", "full", ""], ["C4", "ISO", "A.5.18", "full", ""]],
            [evrow("E1", "C1", "pass_with_exceptions"), evrow("E2", "C2", valid="2026-06-30"),
             evrow("E3", "C3", "not_tested")],
            controls=("C1", "C2", "C3", "C4"))
        self.assertEqual(self.status(a, "A.8.5"), EXCEPTIONS)
        self.assertEqual(self.status(a, "A.8.15"), REQ_STALE)
        self.assertEqual(self.status(a, "A.5.15"), NOT_TESTED)
        self.assertEqual(self.status(a, "A.5.18"), REQ_NO_EVIDENCE)
        self.assertAlmostEqual(a.coverage("ISO27001"), 25.0)

    def test_partial_effective_with_stale_full(self):
        _, a = self.run_case([["C1", "ISO", "A.8.15", "full", ""], ["C2", "ISO", "A.8.15", "partial", ""]],
                             [evrow("E1", "C1", valid="2026-01-01"), evrow("E2", "C2")])
        r = a.result("ISO27001", "A.8.15")
        self.assertEqual(r.status, PARTIAL)
        self.assertIn("stale", r.reason)

    def test_exclusions(self):
        scope = {"frameworks": {"ISO27001": {"include": ["A.7.4", "A.5.32", "A.8.15"],
                                             "exclude": {"A.7.4": "Cloud only", "A.5.32": ""}}}}
        data, a = self.run_case([["C1", "ISO", "A.7.4", "full", ""]], [evrow("E1", "C1")], scope=scope)
        self.assertEqual(self.status(a, "A.7.4"), EXCLUDED)
        codes = {f.code for f in a.findings}
        self.assertIn("EXCLUSION_NOT_JUSTIFIED", codes)
        self.assertIn("EXCLUDED_BUT_OPERATING", codes)
        self.assertAlmostEqual(a.coverage("ISO27001"), 0.0)  # A.8.15 unmapped; exclusions not in denominator

    def test_test_once_ratio_and_equivalents(self):
        scope = {"frameworks": {"ISO27001": {"include": ["A.8.15"]}, "SOC2": {"include": ["CC7.2"]},
                                "CIS8": {"include": ["8.2", "8.3"]}}}
        data, a = self.run_case([["C1", "ISO", "A.8.15", "full", ""], ["C1", "SOC2", "CC7.2", "partial", ""],
                                 ["C1", "CIS", "8.2", "full", ""], ["C1", "CIS", "8.3", "full", ""]],
                                [evrow("E1", "C1")], scope=scope)
        self.assertEqual(a.impacts[0].total, 4)
        self.assertEqual(a.test_once_ratio, 4.0)
        self.assertEqual(equivalents(data, "ISO27001", "A.8.15"), {"SOC2": {"CC7.2"}, "CIS8": {"8.2", "8.3"}})

    def test_blast_radius_of_failed_evidence(self):
        scope = {"frameworks": {"ISO27001": {"include": ["A.5.18"]}, "SOC2": {"include": ["CC6.3"]}}}
        _, a = self.run_case([["C1", "ISO", "A.5.18", "full", ""], ["C1", "SOC2", "CC6.3", "partial", ""]],
                             [evrow("E1", "C1", "fail")], scope=scope)
        self.assertEqual(_at_risk(a, a.impacts[0]), {"ISO27001": ["A.5.18"], "SOC2": ["CC6.3"]})


class ValidationTests(unittest.TestCase):
    def test_bad_inputs_become_findings(self):
        fx = Fixture(
            [ctl("C1"), ctl("C1"), ctl("C2", owner=""), ctl("C3")],
            [["C1", "ISO", "A.12.4.1", "full", ""], ["C1", "ISO", "A.8.15", "full", ""],
             ["C1", "iso", "a.8.15", "full", ""], ["C1", "HIPAA", "164.312", "full", ""],
             ["C1", "CSF", "PR.AA-01", "strong", ""], ["C9", "CIS", "5.1", "full", ""]],
            [evrow("E1", "C1;C7"), evrow("E1", "C1"), evrow("E2", "C1", "maybe"),
             evrow("E3", "C1", collected="01/10/2026"), evrow("E4", ""),
             evrow("E5", "C1", collected="2026-10-01", valid="2026-09-01")])
        try:
            data = fx.load()
        finally:
            fx.close()
        codes = [f.code for f in data.findings]
        for code in ("DUPLICATE_CONTROL", "CONTROL_NO_OWNER", "UNKNOWN_REQUIREMENT", "DUPLICATE_MAPPING",
                     "UNKNOWN_FRAMEWORK", "BAD_STRENGTH", "UNKNOWN_CONTROL", "DUPLICATE_EVIDENCE", "BAD_RESULT",
                     "BAD_DATE", "EVIDENCE_UNLINKED", "CONTROL_UNMAPPED", "CONTROL_NO_EVIDENCE"):
            self.assertIn(code, codes, code)
        self.assertEqual(codes.count("UNKNOWN_CONTROL"), 2)  # C9 in mappings, C7 in evidence
        strengths = {m.req_id: m.strength for m in data.mappings}
        self.assertEqual(strengths["PR.AA-01"], "partial")  # unknown strength downgraded, never upgraded

    def test_no_scope_means_everything(self):
        fx = Fixture([ctl("C1")], [["C1", "ISO", "A.8.15", "full", ""]], [evrow("E1", "C1")])
        try:
            a = assess(fx.load(), AS_OF)
        finally:
            fx.close()
        self.assertEqual(len(a.results["CIS8"]), 153)
        self.assertEqual(len(a.results["ISO27001"]), 123)


class SampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = load_dataset(SAMPLE / "controls.csv", SAMPLE / "mappings.csv", SAMPLE / "evidence.csv",
                                SAMPLE / "scope.json")
        cls.a = assess(cls.data, AS_OF)

    def test_planted_defects_found(self):
        msgs = " ".join(f.message for f in self.a.findings)
        for needle in ("A.12.4.1", "PR.AC-7", "'5.7'", "'8.9'", "CTL-DLP-01", "CTL-LEG-01", "A.5.32", "A.7.4"):
            self.assertIn(needle, msgs, needle)

    def test_failed_access_review_hits_all_four_frameworks(self):
        imp = next(i for i in self.a.impacts if i.evidence.evidence_id == "EV-012")
        self.assertEqual(imp.state, FAILED)
        self.assertEqual(set(_at_risk(self.a, imp)), {"ISO27001", "SOC2", "CSF2", "CIS8"})
        self.assertEqual(self.a.result("SOC2", "CC6.3").status, DEFICIENT)

    def test_scope_groups(self):
        self.assertEqual(len(self.a.results["CIS8"]), 56)
        self.assertEqual(len(self.a.results["SOC2"]), 38)

    def test_renderers(self):
        md = markdown_report(self.a)
        self.assertIn("## Evidence problems: blast radius", md)
        self.assertIn("EV-012", md)
        js = json.loads(json_report(self.a))
        self.assertEqual(set(js["frameworks"]), {"ISO27001", "SOC2", "CSF2", "CIS8"})
        rows = list(csv.DictReader(io.StringIO(matrix_csv(self.a))))
        self.assertEqual(len(rows), 120 + 3 + 38 + 106 + 56)
        a815 = next(r for r in rows if r["requirement_id"] == "A.8.15")
        self.assertIn("CIS8 8.1,8.2,8.3", a815["equivalents_in_other_frameworks"])


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(list(args))
        return rc, out.getvalue(), err.getvalue()

    def test_assess_writes_reports_and_gates(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc, out, _ = self.run_cli("assess", "--data", str(SAMPLE), "--as-of", "2026-11-01", "--out", tmp)
            self.assertEqual(rc, 0)
            self.assertIn("Test once, satisfy many", out)
            for name in ("report.md", "report.json", "matrix.csv"):
                self.assertTrue((Path(tmp) / name).exists())
        rc, _, err = self.run_cli("assess", "--data", str(SAMPLE), "--as-of", "2026-11-01", "--fail-under", "80")
        self.assertEqual(rc, 2)
        self.assertIn("GATE", err)
        rc, _, _ = self.run_cli("assess", "--data", str(SAMPLE), "--as-of", "2026-11-01", "--strict")
        self.assertEqual(rc, 2)

    def test_lookup_and_evidence(self):
        rc, out, _ = self.run_cli("lookup", "csf", "pr.aa-5", "--data", str(SAMPLE), "--as-of", "2026-11-01")
        self.assertEqual(rc, 0)
        self.assertIn("PR.AA-05", out)
        self.assertIn("CTL-IAM-02", out)
        rc, out, _ = self.run_cli("evidence", "ev-012", "--data", str(SAMPLE), "--as-of", "2026-11-01")
        self.assertEqual(rc, 0)
        self.assertIn("Deficient", out)
        rc, _, _ = self.run_cli("evidence", "EV-999", "--data", str(SAMPLE))
        self.assertEqual(rc, 1)
        rc, _, _ = self.run_cli("lookup", "iso", "A.99.1", "--data", str(SAMPLE))
        self.assertEqual(rc, 1)

    def test_missing_inputs(self):
        rc, _, err = self.run_cli("assess")
        self.assertEqual(rc, 1)
        self.assertIn("--data", err)
        rc, _, _ = self.run_cli("assess", "--data", "/nonexistent")
        self.assertEqual(rc, 1)

    def test_groups(self):
        rc, out, _ = self.run_cli("groups")
        self.assertEqual(rc, 0)
        self.assertIn("ig1", out)


if __name__ == "__main__":
    unittest.main()
