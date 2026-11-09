"""Unit tests for the cardholder data discovery scanner. Run from the project folder: python -m unittest -v

All card numbers are published test PANs. Nothing here is real cardholder data.
"""
from __future__ import annotations

import gzip
import io
import json
import os
import sqlite3
import stat
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from pathlib import Path

from chd_scan.cards import (PanFingerprinter, brand_of, is_degenerate, is_probable_pan, luhn_check_digit, luhn_valid,
                            mask_pan, max_visible)
from chd_scan.cli import main
from chd_scan.detectors import (CVV, MASK_EXPOSED, PAN, PIN, TRACK, find_masked, find_pans, redact_line, scan_line)
from chd_scan.extract import Extractor, Limits, xml_to_text
from chd_scan.report import findings_csv, json_report, markdown_report
from chd_scan.scanner import Suppression, classify_location, load_suppressions, scan

HERE = Path(__file__).resolve().parents[1]
SAMPLE = HERE / "sample_data"
VISA, MC, AMEX, DISC = "4111111111111111", "5555555555554444", "378282246310005", "6011111111111117"
ALL_TEST = [VISA, MC, AMEX, DISC, "3530111333300000", "36227206271667", "6200000000000005", "4222222222222"]


def kinds(line: str) -> list[str]:
    return [h.kind for h in scan_line(line)[0]]


class TestCards(unittest.TestCase):
    def test_luhn(self):
        for pan in ALL_TEST:
            self.assertTrue(luhn_valid(pan), pan)
        self.assertFalse(luhn_valid("4111111111111112"))
        self.assertFalse(luhn_valid("41111x1111111111"))
        self.assertEqual(luhn_check_digit("411111111111111"), "1")

    def test_brands(self):
        self.assertEqual(brand_of(VISA), "Visa")
        self.assertEqual(brand_of("2223003122003222"), "Mastercard")
        self.assertEqual(brand_of(AMEX), "American Express")
        self.assertEqual(brand_of(DISC), "Discover")
        self.assertEqual(brand_of("3530111333300000"), "JCB")
        self.assertEqual(brand_of("36227206271667"), "Diners Club")
        self.assertEqual(brand_of("6200000000000005"), "UnionPay")
        self.assertIsNone(brand_of("9999999999999995"))
        self.assertIsNone(brand_of("37828224631000"), "Amex must be 15 digits")

    def test_degenerate_and_probable(self):
        self.assertTrue(is_degenerate("0000000000000000"))
        self.assertTrue(is_degenerate("1234567890123456"))
        self.assertFalse(is_degenerate(VISA))
        self.assertEqual(is_probable_pan(VISA), (True, "Visa"))
        self.assertFalse(is_probable_pan("1234567890123452")[0])  # Luhn-valid, no brand

    def test_masking_rules(self):
        self.assertEqual(mask_pan(VISA), "411111******1111")
        self.assertEqual(mask_pan(AMEX), "378282*****0005")
        self.assertEqual(max_visible(16), (8, 4))
        self.assertEqual(max_visible(15), (6, 4))

    def test_fingerprint_keyed(self):
        a, b = PanFingerprinter(b"k1"), PanFingerprinter(b"k2")
        self.assertEqual(a.fingerprint(VISA), a.fingerprint(VISA))
        self.assertNotEqual(a.fingerprint(VISA), b.fingerprint(VISA))


class TestDetectors(unittest.TestCase):
    def test_pan_formats(self):
        for text in (VISA, "4111 1111 1111 1111", "4111-1111-1111-1111", "3782 822463 10005", f'"pan":"{MC}"'):
            hits = find_pans(text)
            self.assertEqual(len(hits), 1, text)
            self.assertNotIn(VISA, hits[0].masked)

    def test_pan_followed_by_other_numbers(self):
        hits = find_pans("card 4111 1111 1111 1111 1229 and 4111 1111 1111 1111 123")
        self.assertEqual([h.masked for h in hits], ["411111******1111"] * 2)

    def test_false_positive_controls(self):
        for text in ("ORD4111111111111111X", "4111111111111112", "id=1234567890123452", "3.14159265358979323846",
                     "4111-1111 1111-1111", "1736452810000", "0000000000000000", "phone 1-800-555-0199"):
            self.assertEqual(find_pans(text), [], text)

    def test_confidence_from_context(self):
        self.assertEqual(find_pans(f"card number {VISA}")[0].confidence, "high")
        self.assertEqual(find_pans(f"ref {VISA}")[0].confidence, "medium")
        self.assertEqual(find_pans(f"ref {VISA}", context_hint=True)[0].confidence, "high")

    def test_track_data(self):
        self.assertEqual(kinds(f";{VISA}=29121010000000000000?"), [TRACK])
        self.assertEqual(kinds(f"%B{VISA}^SAMPLE/ALEX^2901101000000000000?"), [TRACK])
        self.assertEqual(kinds(f"{VISA}=29131010000"), [PAN], "month 13: not track data, still a PAN")

    def test_cvv_labels(self):
        self.assertEqual(kinds('{"cvv":"123"}'), [CVV])
        self.assertEqual(kinds("<cvc2>4567</cvc2>"), [CVV])
        self.assertEqual(kinds("security code: 921"), [CVV])
        self.assertEqual(kinds("cid=4821"), [], "weak label alone does not count")
        self.assertIn(CVV, kinds(f"cid=4821 card={MC}"))

    def test_pin(self):
        self.assertEqual(kinds("pin_block=8F3A21C0D94B7E15"), [PIN])
        self.assertEqual(kinds("push pin: 1234"), [])

    def test_masking(self):
        hits, ok = find_masked("411111******1111 41111111****1111 4111111111**1111 378282*****0005")
        self.assertEqual(ok, 3)
        self.assertEqual([h.kind for h in hits], [MASK_EXPOSED])
        self.assertIn("first 10", hits[0].detail)

    def test_sad_values_never_kept(self):
        hits, _ = scan_line('{"cvc":"472","card":"4242424242424242"}')
        for h in hits:
            self.assertNotIn("472", h.masked + h.detail)
            self.assertNotIn("4242424242424242", h.masked + h.detail)

    def test_redact(self):
        out = redact_line(f'pan={VISA} cvv2=123 <cvv>456</cvv> ;{MC}=28121010000000000000?')
        self.assertNotIn(VISA, out)
        self.assertNotIn(MC, out)
        self.assertNotIn("123", out)
        self.assertNotIn("456", out)
        self.assertIn("411111******1111", out)


class TestExtract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_office_runs_rejoined(self):
        self.assertIn("4111 1111", xml_to_text("<w:p><w:r><w:t>4111</w:t></w:r><w:r><w:t> 1111</w:t></w:r></w:p>"))
        self.assertEqual(xml_to_text("<row><c><v>1</v></c><c><v>2</v></c></row>").strip(), "1\t2")

    def test_gzip_zip_nested_and_sqlite(self):
        with gzip.open(self.root / "a.log.gz", "wb") as gz:
            gz.write(f"card={VISA}\n".encode())
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("deep.txt", f"card={MC}\n")
        with zipfile.ZipFile(self.root / "b.zip", "w") as z:
            z.writestr("inner.zip", inner.getvalue())
        con = sqlite3.connect(self.root / "c.db")
        con.execute("CREATE TABLE t (lane TEXT, pan TEXT)")
        con.execute("INSERT INTO t VALUES ('014-03', ?)", (AMEX,))
        con.commit()
        con.close()
        r = scan(self.root, date(2026, 11, 8))
        paths = {f.path for f in r.findings}
        self.assertEqual(paths, {"a.log.gz", "b.zip!inner.zip!deep.txt", "c.db"})
        self.assertEqual(r.unique_pans, 3)

    def test_depth_limit_and_encrypted_gap(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("x.txt", VISA)
        with zipfile.ZipFile(self.root / "b.zip", "w") as z:
            z.writestr("inner.zip", inner.getvalue())
        res = Extractor(Limits(max_archive_depth=1)).walk(self.root)
        self.assertTrue(any("nested archive" in g.reason for g in res.gaps))
        res = Extractor().walk(SAMPLE / "fileshare" / "archive")
        self.assertTrue(any("encrypted" in g.reason for g in res.gaps))

    def test_size_limit_is_a_gap(self):
        (self.root / "big.txt").write_text("x" * 2048)
        res = Extractor(Limits(max_file_bytes=1024)).walk(self.root)
        self.assertEqual(res.documents, [])
        self.assertEqual(len(res.gaps), 1)

    def test_csv_cvv_column(self):
        (self.root / "cb.csv").write_text(f"order,card_number,cvv2\nA1,{VISA},123\nA2,{MC},4567\n")
        r = scan(self.root, date(2026, 11, 8))
        self.assertEqual(sum(f.kind == CVV for f in r.findings), 2)
        pans = [f for f in r.findings if f.kind == PAN]
        self.assertTrue(all(f.severity == "High" and "with SAD" in f.detail for f in pans))


class TestSuppressionsAndScan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "qa").mkdir()
        (self.root / "qa" / "cards.txt").write_text(f"card {VISA}\ncvv=123 card {MC}\n")

    def tearDown(self):
        self.tmp.cleanup()

    def sup(self, expires="2027-01-01", **kw):
        return Suppression("qa/*", "QA fixtures", "CISO", date.fromisoformat(expires) if expires else None, **kw)

    def test_active_suppression_hides_pan_not_sad(self):
        s = self.sup()
        r = scan(self.root, date(2026, 11, 8), [s])
        self.assertEqual([f.kind for f in r.findings], [CVV])
        self.assertIn("cannot be excepted", r.findings[0].detail)
        self.assertEqual(len(r.suppressed), 2)

    def test_expired_suppression_resurfaces(self):
        r = scan(self.root, date(2026, 11, 8), [self.sup("2026-06-30")])
        self.assertEqual(len(r.suppressed), 0)
        self.assertIn("SUPPRESSION_EXPIRED", [n.code for n in r.notes])

    def test_invalid_and_unused(self):
        path = self.root.parent / f"{self.root.name}-sup.json"
        path.write_text(json.dumps({"suppressions": [{"path": "qa/*", "reason": "x", "expires": "2027-01-01"},
                                                     {"path": "none/*", "reason": "y", "approved_by": "z",
                                                      "expires": "2027-01-01"}]}))
        try:
            r = scan(self.root, date(2026, 11, 8), load_suppressions(path))
        finally:
            path.unlink()
        codes = [n.code for n in r.notes]
        self.assertIn("SUPPRESSION_INVALID", codes)
        self.assertIn("SUPPRESSION_UNUSED", codes)
        self.assertEqual(len(r.suppressed), 0)

    def test_ignore_test_pans(self):
        r = scan(self.root, date(2026, 11, 8), ignore_test_pans=True)
        self.assertEqual([f.kind for f in r.findings], [CVV])

    def test_location_classes(self):
        self.assertEqual(classify_location("app_logs/api.log.1.gz").key, "log")
        self.assertEqual(classify_location("db_exports/x.sql").key, "db_export")
        self.assertEqual(classify_location("archive/a.zip!r.csv").key, "archive")
        self.assertEqual(classify_location("support/t.json").key, "support")
        self.assertEqual(classify_location("misc/notes.txt").key, "other")


class TestSampleRun(unittest.TestCase):
    """End-to-end over the bundled synthetic file share."""

    @classmethod
    def setUpClass(cls):
        cls.r = scan(SAMPLE / "fileshare", date(2026, 11, 8), load_suppressions(SAMPLE / "suppressions.json"),
                     fingerprinter=PanFingerprinter(b"test"))

    def test_expected_locations(self):
        worst = {f.path: f.worst for f in self.r.files}
        self.assertEqual(worst["finance/chargebacks_2026Q3.csv"], "Critical")
        self.assertEqual(worst["pos/store014_terminal_trace.txt"], "Critical")
        self.assertEqual(worst["app_logs/checkout-api.log.1.gz"], "Critical")
        self.assertIn("hr/corporate_card_request_form.docx", worst)
        self.assertIn("pos/offline_queue.db", worst)
        self.assertIn("legacy/crm_export_2023.csv", worst)  # expired exception

    def test_no_false_positives_in_bait_file(self):
        self.assertFalse(any(f.path.startswith("marketing/") or f.path.startswith("assets/") for f in self.r.findings))

    def test_qa_suppressed(self):
        self.assertFalse(any(f.path.startswith("qa/") for f in self.r.findings))
        self.assertTrue(all(f.path.startswith("qa/") for f in self.r.suppressed))

    def test_reports_never_contain_full_pan_or_cvv(self):
        blob = json_report(self.r) + markdown_report(self.r) + findings_csv(self.r)
        for pan in ALL_TEST + ["4012888888881881", "4242424242424242", "5105105105105100", "2223003122003222"]:
            self.assertNotIn(pan, blob)
        for cvv in ('"472"', "cvc=472", ",7781,"):
            self.assertNotIn(cvv, blob)

    def test_cli_gate_and_private_files(self):
        with tempfile.TemporaryDirectory() as out:
            buf_out, buf_err = io.StringIO(), io.StringIO()
            with redirect_stdout(buf_out), redirect_stderr(buf_err):
                rc = main(["scan", str(SAMPLE / "fileshare"), "--suppressions", str(SAMPLE / "suppressions.json"),
                           "--as-of", "2026-11-08", "--out", out, "--fail-on", "critical"])
            self.assertEqual(rc, 2)
            self.assertIn("Authorised use only", buf_err.getvalue())
            mode = stat.S_IMODE(os.stat(Path(out) / "report.json").st_mode)
            self.assertEqual(mode & 0o077, 0, "reports must not be group/world readable")


if __name__ == "__main__":
    unittest.main()
