"""Unit tests for soa_auditor. Run from the project folder: python -m unittest -v"""
from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from datetime import date
from pathlib import Path

from soa_auditor.catalog import ANNEX_A
from soa_auditor.checks import (
    AuditConfig, check_evidence, check_hygiene, check_justifications,
    check_risk_alignment, check_structure, readiness_score, run_all,
)
from soa_auditor.cli import main
from soa_auditor.models import Evidence, Risk, SoAEntry
from soa_auditor.report import coverage_by_theme

CFG = AuditConfig(as_of=date(2026, 10, 12))
SAMPLE = Path(__file__).resolve().parents[1] / "sample_data"


def entry(cid: str, applicable: bool = True, status: str = "implemented",
          justification: str = "Treats risk R-1 and contractual requirements.",
          evidence: list[str] | None = None, owner: str = "CISO",
          reviewed: date | None = date(2026, 6, 1)) -> SoAEntry:
    return SoAEntry(row=2, control_id=cid, control_name=ANNEX_A.get(cid, "?"),
                    applicable=applicable, justification=justification, status=status,
                    evidence_refs=["EV-1"] if evidence is None else evidence,
                    owner=owner, last_reviewed=reviewed)


def full_clean_soa() -> list[SoAEntry]:
    return [entry(cid, evidence=[f"EV-{cid}"]) for cid in ANNEX_A]


def checks(findings) -> set[str]:
    return {f.check for f in findings}


class StructureTests(unittest.TestCase):
    def test_complete_soa_has_no_structure_findings(self):
        self.assertEqual(check_structure(full_clean_soa()), [])

    def test_missing_control_detected(self):
        soa = [e for e in full_clean_soa() if e.control_id != "8.17"]
        f = check_structure(soa)
        self.assertEqual([(x.check, x.ref) for x in f], [("MISSING_CONTROL", "8.17")])

    def test_duplicate_and_legacy_ids(self):
        soa = full_clean_soa() + [entry("5.15"), entry("12.6.1")]
        found = checks(check_structure(soa))
        self.assertIn("DUPLICATE_CONTROL", found)
        self.assertIn("UNKNOWN_CONTROL", found)


class JustificationTests(unittest.TestCase):
    def test_exclusion_without_justification_is_high(self):
        f = check_justifications([entry("7.4", applicable=False, justification="")])
        self.assertEqual(f[0].check, "EXCLUSION_NO_JUSTIFICATION")
        self.assertEqual(f[0].severity, "High")

    def test_hard_to_exclude_and_weak_justification(self):
        found = checks(check_justifications([entry("8.8", applicable=False, justification="Vendor does it")]))
        self.assertEqual(found, {"WEAK_EXCLUSION_JUSTIFICATION", "UNUSUAL_EXCLUSION"})

    def test_well_justified_exclusion_passes(self):
        e = entry("8.30", applicable=False,
                  justification="All software development is performed in-house by employees.")
        self.assertEqual(check_justifications([e]), [])


class EvidenceTests(unittest.TestCase):
    def test_implemented_without_evidence(self):
        f = check_evidence([entry("5.7", evidence=[])], None, CFG)
        self.assertEqual(checks(f), {"NO_EVIDENCE"})

    def test_expired_missing_and_mismatched_evidence(self):
        log = {
            "EV-OLD": Evidence("EV-OLD", "8.13", "Backup test", date(2025, 6, 1), date(2026, 6, 30)),
            "EV-X": Evidence("EV-X", "5.1", "Policy", date(2026, 1, 1), None),
        }
        soa = [entry("8.13", evidence=["EV-OLD"]), entry("5.23", evidence=["EV-404"]),
               entry("8.1", evidence=["EV-X"])]
        found = checks(check_evidence(soa, log, CFG))
        self.assertEqual(found, {"EVIDENCE_EXPIRED", "EVIDENCE_NOT_FOUND", "EVIDENCE_MISMATCH"})


class HygieneTests(unittest.TestCase):
    def test_owner_and_review_age(self):
        soa = [entry("8.23", owner=""), entry("6.1", reviewed=date(2025, 3, 14)),
               entry("7.1", reviewed=None)]
        self.assertEqual(checks(check_hygiene(soa, CFG)),
                         {"NO_OWNER", "STALE_REVIEW", "NEVER_REVIEWED"})


class RiskAlignmentTests(unittest.TestCase):
    def test_risk_relies_on_excluded_or_missing_control(self):
        soa = [entry("8.11", applicable=False, justification="Not needed for our environment at all.")]
        risks = [Risk("R-1", "Test data", 3, 4, "mitigate", ["8.11", "7.12"])]
        found = checks(check_risk_alignment(soa, risks, CFG))
        self.assertEqual(found, {"RISK_RELIES_ON_EXCLUDED", "RISK_CONTROL_NOT_IN_SOA"})

    def test_high_risk_with_only_planned_controls(self):
        soa = [entry("8.12", status="planned"), entry("8.24", status="planned")]
        risks = [Risk("R-4", "PII leak", 3, 5, "mitigate", ["8.12", "8.24"])]
        self.assertIn("HIGH_RISK_UNTREATED", checks(check_risk_alignment(soa, risks, CFG)))

    def test_accepted_high_risk_and_unmapped_mitigation(self):
        risks = [Risk("R-9", "Legacy", 4, 4, "accept", []), Risk("R-8", "Fraud", 2, 5, "mitigate", [])]
        found = checks(check_risk_alignment([], risks, CFG))
        self.assertEqual(found, {"HIGH_RISK_ACCEPTED", "RISK_NO_CONTROLS"})

    def test_orphan_gap(self):
        soa = [entry("5.30", status="planned", justification="")]
        self.assertIn("ORPHAN_GAP", checks(check_risk_alignment(soa, [], CFG)))

    def test_no_risk_register_means_no_alignment_findings(self):
        self.assertEqual(check_risk_alignment(full_clean_soa(), None, CFG), [])


class ScoringAndCoverageTests(unittest.TestCase):
    def test_clean_soa_scores_100(self):
        log = {f"EV-{c}": Evidence(f"EV-{c}", c, "", None, None) for c in ANNEX_A}
        self.assertEqual(readiness_score(run_all(full_clean_soa(), [], log, CFG)), 100)

    def test_coverage_counts(self):
        soa = full_clean_soa()
        soa[0].status = "planned"            # 5.1
        soa[-1].applicable = False           # 8.34
        cov = coverage_by_theme(soa)
        self.assertEqual(cov["Organizational"]["implemented"], 36)
        self.assertEqual(cov["Technological"]["excluded"], 1)
        self.assertEqual(sum(t["in_catalog"] for t in cov.values()), 93)


class SampleDataEndToEnd(unittest.TestCase):
    def test_sample_run_finds_planted_defects(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["--soa", str(SAMPLE / "soa.csv"),
                         "--risks", str(SAMPLE / "risk_register.csv"),
                         "--evidence", str(SAMPLE / "evidence.csv"),
                         "--as-of", "2026-10-12", "--fail-on-high"])
        out = buf.getvalue()
        self.assertEqual(code, 2)  # High findings exist, so CI mode fails
        for expected in ("MISSING_CONTROL", "RISK_RELIES_ON_EXCLUDED", "EXCLUSION_NO_JUSTIFICATION"):
            self.assertIn(expected, out)


if __name__ == "__main__":
    unittest.main()
