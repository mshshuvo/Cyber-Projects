"""Unit tests for audit_sampling. Run from the project folder: python -m unittest -v"""
from __future__ import annotations

import csv
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from pathlib import Path

from audit_sampling.cli import main
from audit_sampling.population import load_population
from audit_sampling.sampler import Manifest, allocate, draw_sample, rank_key, reperform, select
from audit_sampling.stats import (attribute_sample_size, binom_cdf, frequency_sample_size,
                                  hypergeom_cdf, supports_reliance, upper_deviation_limit)
from audit_sampling.tracker import (EFFECTIVE, INCOMPLETE, NOT_EFFECTIVE, TrackerRow,
                                    evaluate, load_tracker, write_tracker)

SAMPLE = Path(__file__).resolve().parents[1] / "sample_data"
AS_OF = date(2026, 10, 16)


def write_csv(folder: Path, name: str, header: list[str], rows: list[list]) -> Path:
    path = folder / name
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)
    return path


def simple_population(folder: Path, n: int = 200) -> Path:
    rows = [[f"T-{i:04d}", f"2026-{1 + i % 9:02d}-15", ["High", "Low"][i % 3 == 0]]
            for i in range(n)]
    return write_csv(folder, "pop.csv", ["id", "date", "tier"], rows)


def tested_rows(manifest: Manifest, exceptions: int = 0, untested: int = 0) -> list[TrackerRow]:
    rows = []
    for n, sel in enumerate(manifest.selected):
        done = n < len(manifest.selected) - untested
        rows.append(TrackerRow(
            line=n + 2, sample_no=str(n + 1), item_id=sel["item_id"], stratum=sel["stratum"],
            status="tested" if done else "not started",
            result=("exception" if n < exceptions else "pass") if done else "",
            evidence_ref=f"EV-{n}" if done else "", requested_on=None, received_on=None,
            tester="Auditor A" if done else "", notes="failed" if n < exceptions else ""))
    return rows


class TestStats(unittest.TestCase):
    def test_matches_aicpa_attribute_tables(self):
        # Published AICPA statistical sample sizes for tests of controls.
        cases = {(0.95, 0.05, 0.0): (59, 0), (0.95, 0.05, 0.01): (93, 1),
                 (0.95, 0.05, 0.0125): (124, 2), (0.90, 0.05, 0.0): (45, 0),
                 (0.95, 0.10, 0.0): (29, 0), (0.90, 0.10, 0.0): (22, 0),
                 (0.95, 0.10, 0.01): (46, 1)}
        for (c, t, e), (n, k) in cases.items():
            with self.subTest(confidence=c, tolerable=t, expected=e):
                s = attribute_sample_size(c, t, e)
                self.assertEqual((s.n, s.allowed_deviations), (n, k))

    def test_finite_population_needs_fewer_items(self):
        big = attribute_sample_size(0.95, 0.05)
        small = attribute_sample_size(0.95, 0.05, population=410)
        self.assertLess(small.n, big.n)
        self.assertEqual(small.method, "attribute-hypergeometric")

    def test_tiny_population_means_test_all(self):
        s = attribute_sample_size(0.95, 0.05, population=12)
        self.assertTrue(s.test_all)
        self.assertEqual(s.n, 12)

    def test_invalid_rates_rejected(self):
        with self.assertRaises(ValueError):
            attribute_sample_size(0.95, 0.05, 0.06)     # expected >= tolerable
        with self.assertRaises(ValueError):
            attribute_sample_size(1.0, 0.05)
        with self.assertRaises(ValueError):
            attribute_sample_size(0.95, 0.0)

    def test_distributions(self):
        self.assertAlmostEqual(binom_cdf(0, 59, 0.05), 0.95 ** 59, places=12)
        self.assertEqual(binom_cdf(5, 5, 0.3), 1.0)
        # Hypergeometric: 2 defects in 10, draw 3, P(no defects) = C(8,3)/C(10,3) = 56/120.
        self.assertAlmostEqual(hypergeom_cdf(0, 10, 2, 3), 56 / 120, places=12)
        # Converges to the binomial for very large populations.
        self.assertAlmostEqual(hypergeom_cdf(1, 1_000_000, 50_000, 93), binom_cdf(1, 93, 0.05), places=4)

    def test_frequency_guide(self):
        self.assertEqual(frequency_sample_size("weekly", "higher").n, 15)
        self.assertEqual(frequency_sample_size("daily", "lower").n, 20)
        self.assertEqual(frequency_sample_size("monthly", "moderate").n, 4)
        q = frequency_sample_size("quarterly", "higher", population=2)
        self.assertTrue(q.test_all)
        self.assertEqual(q.n, 2)
        with self.assertRaises(ValueError):
            frequency_sample_size("hourly")

    def test_upper_limit_and_reliance(self):
        # Zero deviations in 59 rules out 5% at 95%.
        self.assertLessEqual(upper_deviation_limit(0, 59, 0.95), 0.05)
        self.assertTrue(supports_reliance(0, 59, 0.95, 0.05))
        self.assertFalse(supports_reliance(0, 58, 0.95, 0.05))
        self.assertFalse(supports_reliance(2, 93, 0.95, 0.05))
        self.assertGreater(upper_deviation_limit(2, 44, 0.95, 410), 0.10)
        self.assertEqual(upper_deviation_limit(3, 3, 0.95), 1.0)


class TestPopulation(unittest.TestCase):
    def test_quality_issues(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = write_csv(Path(tmp), "p.csv", ["ID", "Date"], [
                ["A1", "2026-02-01"], ["A1", "2026-02-02"], ["", "2026-02-03"],
                ["A2", "2025-12-31"], ["A3", "not a date"], ["A4", "2026-03-01"]])
            pop = load_population(p, "id", "date", date(2026, 1, 1), date(2026, 9, 30),
                                  expected_count=5)
        checks = {i.check for i in pop.issues}
        self.assertEqual(checks, {"DUPLICATE_ID", "BLANK_ID", "OUT_OF_PERIOD",
                                  "UNREADABLE_DATE", "COUNT_MISMATCH"})
        self.assertEqual(pop.ids, ["A1", "A4"])
        self.assertEqual(len(pop.blocking), 3)

    def test_missing_column(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = write_csv(Path(tmp), "p.csv", ["x"], [["1"]])
            with self.assertRaises(ValueError):
                load_population(p, "id")


class TestSampler(unittest.TestCase):
    def test_selection_is_deterministic_and_order_independent(self):
        ids = [f"X{i}" for i in range(500)]
        a = select(ids, 25, "seed-1")
        b = select(list(reversed(ids)), 25, "seed-1")
        self.assertEqual(a, b)
        self.assertEqual(len(set(a)), 25)
        self.assertNotEqual(a, select(ids, 25, "seed-2"))
        # Re-performable by hand: the first pick has the lowest hash key.
        self.assertEqual(a[0], min(ids, key=lambda i: rank_key("seed-1", i)))

    def test_selection_never_exceeds_population(self):
        self.assertEqual(len(select(["a", "b"], 10, "s")), 2)

    def test_allocation(self):
        alloc = allocate({"High": 60, "Medium": 140, "Low": 200}, 44)
        self.assertEqual(sum(alloc.values()), 44)
        self.assertGreaterEqual(min(alloc.values()), 1)
        self.assertLess(alloc["High"], alloc["Low"])
        capped = allocate({"tiny": 1, "big": 99}, 30)
        self.assertEqual(capped, {"tiny": 1, "big": 29})
        self.assertEqual(sum(allocate({"a": 3, "b": 3}, 100).values()), 6)

    def test_draw_and_reperform(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = simple_population(Path(tmp))
            pop = load_population(path, "id")
            size = attribute_sample_size(0.95, 0.10, population=len(pop.frame))
            m = draw_sample(pop, size, "abc", "C-1", stratify_by="tier")
            self.assertEqual(len(m.selected), size.n)
            self.assertEqual(sum(m.allocation.values()), size.n)
            self.assertEqual(reperform(m, pop), [])
            # Round-trip through JSON.
            (Path(tmp) / "m.json").write_text(m.to_json())
            self.assertEqual(Manifest.load(Path(tmp) / "m.json").selected_ids, m.selected_ids)
            # Removing a row after the draw is detected.
            lines = path.read_text().splitlines()
            path.write_text("\n".join(lines[:-1]) + "\n")
            problems = reperform(m, load_population(path, "id"))
            self.assertTrue(any("fingerprint" in p for p in problems))


class TestTracker(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        pop = load_population(simple_population(Path(self.tmp.name)), "id")
        self.pop = pop
        self.stat = draw_sample(pop, attribute_sample_size(0.95, 0.10, 0.01, len(pop.frame)),
                                "s1", "C-1")
        self.freq = draw_sample(pop, frequency_sample_size("weekly", "higher", len(pop.frame)),
                                "s1", "C-2")

    def tearDown(self):
        self.tmp.cleanup()

    def test_effective_when_within_allowed(self):
        ev = evaluate(tested_rows(self.stat, exceptions=1), self.stat, AS_OF)
        self.assertEqual(ev.conclusion, EFFECTIVE)
        self.assertEqual(ev.issues, [])
        self.assertLessEqual(ev.upper_limit, 0.10)

    def test_not_effective_stops_early(self):
        ev = evaluate(tested_rows(self.stat, exceptions=2, untested=10), self.stat, AS_OF)
        self.assertEqual(ev.conclusion, NOT_EFFECTIVE)

    def test_incomplete(self):
        ev = evaluate(tested_rows(self.stat, untested=3), self.stat, AS_OF)
        self.assertEqual(ev.conclusion, INCOMPLETE)
        self.assertEqual(ev.tested, len(self.stat.selected) - 3)

    def test_judgmental_sample_tolerates_no_exceptions(self):
        self.assertEqual(evaluate(tested_rows(self.freq), self.freq, AS_OF).conclusion, EFFECTIVE)
        ev = evaluate(tested_rows(self.freq, exceptions=1), self.freq, AS_OF)
        self.assertEqual(ev.conclusion, NOT_EFFECTIVE)
        self.assertIsNone(ev.upper_limit)

    def test_tracker_issues(self):
        rows = tested_rows(self.stat)
        rows[0].evidence_ref = ""
        rows[1].result = "exception"
        rows[1].notes = ""
        rows[2].status, rows[2].result = "tested", ""
        rows[3].status, rows[3].result = "requested", ""
        rows[3].requested_on = date(2026, 9, 1)
        rows[4].item_id = "NOT-SELECTED"
        rows.append(rows[5])
        checks = {i.check for i in evaluate(rows, self.stat, AS_OF).issues}
        self.assertTrue({"NO_EVIDENCE_REF", "EXCEPTION_NOT_DESCRIBED", "TESTED_NO_RESULT",
                         "EVIDENCE_OVERDUE", "NOT_IN_SAMPLE", "SAMPLE_ITEM_MISSING",
                         "DUPLICATE_TRACKER_ROW"} <= checks)
        # The substituted item is not counted as a test.
        self.assertEqual(evaluate(rows, self.stat, AS_OF).conclusion, INCOMPLETE)

    def test_write_and_load_tracker(self):
        path = Path(self.tmp.name) / "t.csv"
        write_tracker(path, self.stat, self.pop)
        rows = load_tracker(path)
        self.assertEqual([r.item_id for r in rows], self.stat.selected_ids)
        self.assertTrue(all(r.status == "not started" for r in rows))


class TestCLI(unittest.TestCase):
    def run_cli(self, *argv: str) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue() + err.getvalue()

    def test_size(self):
        code, text = self.run_cli("size", "--confidence", "95%", "--tolerable", "5%")
        self.assertEqual(code, 0)
        self.assertIn("Sample size:         59", text)

    def test_sample_evaluation_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, text = self.run_cli(
                "evaluate", "--manifest", str(SAMPLE / "manifest.json"),
                "--tracker", str(SAMPLE / "evidence_tracker.csv"),
                "--population", str(SAMPLE / "change_tickets.csv"),
                "--date-column", "deployed_on", "--period-start", "2026-01-01",
                "--period-end", "2026-09-30", "--as-of", "2026-10-16",
                "--out", tmp, "--fail-on-ineffective")
            self.assertEqual(code, 2)
            self.assertIn("CONCLUSION: NOT EFFECTIVE", text)
            self.assertIn("Re-performance: PASS", text)
            data = json.loads((Path(tmp) / "report.json").read_text())
            checks = {i["check"] for i in data["evaluation"]["issues"]}
            self.assertEqual(checks, {"NOT_IN_SAMPLE", "SAMPLE_ITEM_MISSING",
                                      "NO_EVIDENCE_REF", "EVIDENCE_OVERDUE"})
            self.assertEqual(data["evaluation"]["exceptions"], 2)

    def test_draw_refuses_bad_population(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = write_csv(Path(tmp), "p.csv", ["id"], [["A"], ["A"], ["B"]])
            code, text = self.run_cli("draw", "--population", str(p), "--id-column", "id",
                                      "--control-id", "C", "--sample-size", "2",
                                      "--out", str(Path(tmp) / "o"))
            self.assertEqual(code, 3)
            self.assertIn("DUPLICATE_ID", text)

    def test_draw_writes_manifest_and_tracker(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = simple_population(Path(tmp), 60)
            code, _ = self.run_cli("draw", "--population", str(p), "--id-column", "id",
                                   "--control-id", "C", "--frequency", "daily",
                                   "--seed", "x", "--out", str(Path(tmp) / "o"))
            self.assertEqual(code, 0)
            m = Manifest.load(Path(tmp) / "o" / "manifest.json")
            self.assertEqual(len(m.selected), 30)
            self.assertTrue((Path(tmp) / "o" / "tracker.csv").exists())


if __name__ == "__main__":
    unittest.main()
