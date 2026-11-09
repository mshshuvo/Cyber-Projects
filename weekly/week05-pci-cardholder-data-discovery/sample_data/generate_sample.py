"""Generate the synthetic file share for Northbay Outfitters Ltd. (fictional).

Every card number here is a PUBLISHED TEST PAN from card-network or processor developer
documentation (4111 1111 1111 1111 and friends). They pass Luhn and brand checks but belong
to no cardholder. Names, ids, amounts, CVVs and PIN blocks are invented.

    python sample_data/generate_sample.py      # rewrites sample_data/fileshare/ and suppressions.json

Planted on purpose: CVV in a chargeback spreadsheet, card bodies in debug logs (including a
rotated .gz), track data and a PIN block in a POS trace, PANs in a SQLite offline queue, a
customer pasting a card into a support ticket, a SQL backup, an old ZIP export, a Word form,
over-exposed masking, an encrypted ZIP member, a false-positive bait file, and an exceptions
register with valid, expired, unused and invalid entries.
"""
from __future__ import annotations

import gzip
import io
import json
import shutil
import sqlite3
import struct
import zipfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE / "fileshare"
FIXED_ZIP_TIME = (2026, 10, 30, 9, 0, 0)

VISA, VISA2, VISA3, VISA4 = "4111111111111111", "4012888888881881", "4242424242424242", "4000056655665556"
MC, MC2, MC3 = "5555555555554444", "5105105105105100", "2223003122003222"
AMEX, AMEX2 = "378282246310005", "371449635398431"
DISC, DISC2 = "6011111111111117", "6011000990139424"
JCB, DINERS, UPAY = "3530111333300000", "36227206271667", "6200000000000005"


def write(rel: str, text: str) -> None:
    p = ROOT / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8", newline="\n")


def g4(pan: str, sep: str = " ") -> str:
    """Format a PAN in groups of four."""
    return sep.join(pan[i:i + 4] for i in range(0, len(pan), 4))


def zip_bytes(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(zipfile.ZipInfo(name, FIXED_ZIP_TIME), data, zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def mark_encrypted(data: bytes, member: str) -> bytes:
    """Set the 'encrypted' flag on one member (stdlib cannot write encrypted ZIPs).

    The scanner only needs to see the flag to report a coverage gap; it never tries to read
    the member, so its bytes stay as written.
    """
    b = bytearray(data)
    name = member.encode()
    for sig, flag_off, name_len_off, name_off in ((b"PK\x03\x04", 6, 26, 30), (b"PK\x01\x02", 8, 28, 46)):
        i = b.find(sig)
        while i != -1:
            (n,) = struct.unpack_from("<H", b, i + name_len_off)
            if bytes(b[i + name_off:i + name_off + n]) == name:
                (flags,) = struct.unpack_from("<H", b, i + flag_off)
                struct.pack_into("<H", b, i + flag_off, flags | 0x1)
            i = b.find(sig, i + 4)
    return bytes(b)


def docx_bytes(paragraphs: list[list[str]]) -> bytes:
    """Minimal Word document. Each paragraph is a list of runs (Word splits text unpredictably)."""
    ns = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    body = "".join("<w:p>" + "".join(f'<w:r><w:t xml:space="preserve">{r}</w:t></w:r>' for r in runs) + "</w:p>"
                   for runs in paragraphs)
    return zip_bytes({
        "[Content_Types].xml": b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                               b'<Default Extension="xml" ContentType="application/xml"/>'
                               b'<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>',
        "word/document.xml": f'<?xml version="1.0"?><w:document {ns}><w:body>{body}</w:body></w:document>'.encode(),
    })


def tiny_png() -> bytes:
    def chunk(t: bytes, d: bytes) -> bytes:
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + bytes([30, 90, 160]) * 16 for _ in range(16))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 16, 16, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def build() -> None:
    if ROOT.exists():
        shutil.rmtree(ROOT)

    # 1. Finance: chargeback evidence spreadsheet that kept the CVV2 column (Critical).
    write("finance/chargebacks_2026Q3.csv",
          "case_id,order_id,card_number,exp,cvv2,amount_cad,reason_code\n"
          f"CB-26-0412,NB-118204,{VISA},11/28,123,149.99,10.4\n"
          f"CB-26-0419,NB-118377,{MC},07/27,456,89.50,4837\n"
          f"CB-26-0433,NB-118902,{AMEX},03/29,7781,412.00,F29\n"
          f"CB-26-0440,NB-119015,{DISC},09/28,301,64.25,UA02\n"
          f"CB-26-0451,NB-119240,{VISA2},01/29,918,230.10,13.1\n")

    # 2. Finance: settlement report, masked, but a legacy export shows too many digits.
    write("finance/settlement_2026-10.csv",
          "settlement_id,batch,card_masked,amount_cad,auth_code\n"
          "STL-2026-10-001,0412,411111******1111,149.99,A1B2C3\n"
          "STL-2026-10-002,0412,555555******4444,89.50,D4E5F6\n"
          "STL-2026-10-003,0413,378282*****0005,412.00,G7H8J9\n"
          "STL-2026-10-004,0413,4012888888**1881,230.10,K1L2M3\n"
          "STL-2026-10-005,0414,6011 1111 11** 1117,64.25,N4P5Q6\n"
          "STL-2026-10-006,0414,5105****5100,18.00,R7S8T9\n")

    # 3. App logs: DEBUG left on in production writes the full payment request.
    log = [
        '2026-10-28T14:02:11Z INFO  checkout-api order=NB-120118 status=created amount=72.40',
        '2026-10-28T14:02:12Z DEBUG checkout-api POST /v2/payments body={"order":"NB-120118","card":{"number":"%s","exp":"08/28","cvc":"472"},"amount":72.40}' % VISA3,
        '2026-10-28T14:02:12Z INFO  checkout-api payment approved order=NB-120118 card=424242******4242 auth=OK3392',
        '2026-10-28T14:07:40Z INFO  checkout-api order=NB-120131 status=created amount=19.99',
        '2026-10-28T14:07:41Z DEBUG checkout-api POST /v2/payments body={"order":"NB-120131","card":{"number":"%s","exp":"02/30","cvc":"085"},"amount":19.99}' % MC3,
        '2026-10-28T14:07:41Z WARN  checkout-api gateway retry order=NB-120131 attempt=2 trace=7f3a9c1e5b2d4f60',
        '2026-10-28T14:11:03Z ERROR checkout-api tokenisation timeout, falling back to direct auth pan=%s exp=0529' % JCB,
        '2026-10-28T14:15:22Z INFO  checkout-api healthcheck ok latency_ms=41 build=2026.10.27-1736452810000',
    ]
    write("app_logs/checkout-api.log", "\n".join(log) + "\n")
    rotated = "\n".join([
        '2026-10-21T09:41:05Z DEBUG checkout-api POST /v2/payments body={"order":"NB-117650","card":{"number":"%s","exp":"10/27","cvc":"619"},"amount":310.00}' % VISA4,
        '2026-10-21T09:41:06Z INFO  checkout-api payment approved order=NB-117650 card=400005******5556',
    ]) + "\n"
    p = ROOT / "app_logs/checkout-api.log.1.gz"
    with gzip.GzipFile(p, "wb", mtime=0) as gz:
        gz.write(rotated.encode())

    # 4. POS: terminal trace captured during a support call: track 2, track 1 and a PIN block.
    write("pos/store014_terminal_trace.txt",
          "== Store 014 lane 3 diagnostic trace (vendor support case VS-55120) ==\n"
          "10:14:02 READ  swipe ok\n"
          f"10:14:02 RAW   ;{MC2}=28121010000000000000?\n"
          "10:14:03 PINPAD pin_block=8F3A21C0D94B7E15 ksn=FFFF9876543210E00001\n"
          f"10:21:47 RAW   %B{VISA2}^SAMPLE/ALEX^2901101000000000000000000?\n"
          "10:21:48 HOST  approved 00 stan=004417 rrn=630114417702\n"
          "10:30:00 READ  chip ok AID=A0000000031010 (no track data written)\n")

    # 5. POS: offline store-and-forward queue in SQLite (binary file).
    db = ROOT / "pos/offline_queue.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE pending_auth (id INTEGER PRIMARY KEY, lane TEXT, pan TEXT, exp TEXT, amount_cents INTEGER)")
    con.executemany("INSERT INTO pending_auth (lane, pan, exp, amount_cents) VALUES (?,?,?,?)",
                    [("014-03", UPAY, "2811", 4599), ("014-01", DINERS, "2704", 1250), ("014-02", AMEX2, "2908", 22014)])
    con.commit()
    con.execute("VACUUM")
    con.close()

    # 6. Support: customers paste card numbers into tickets.
    tickets = [
        {"ticket": "SUP-88213", "channel": "email", "subject": "Double charge?",
         "body": f"Hi, I think I was charged twice. My card is {g4(MC)} exp 08/28. Please refund one."},
        {"ticket": "SUP-88240", "channel": "chat", "subject": "Payment failing",
         "body": f"tried my amex 3782-822463-10005 three times, security code: 9921, still failing"},
        {"ticket": "SUP-88251", "channel": "email", "subject": "Order status",
         "body": "Order NB-119987, tracking 1Z999AA10123456784. Phone 902-555-0143."},
    ]
    write("support/ticket_export_2026-10.json", json.dumps(tickets, indent=2) + "\n")

    # 7. Database export: an old orders table from before tokenisation went live.
    write("db_exports/orders_2025_backup.sql",
          "-- orders table backup taken 2025-03-02 before tokenisation migration (fictional)\n"
          "CREATE TABLE orders (id INT, customer VARCHAR(40), cc_number VARCHAR(19), cc_exp CHAR(7), total DECIMAL(9,2));\n"
          f"INSERT INTO orders VALUES (90114,'cust-20871','{DISC2}','2027-03',88.20);\n"
          f"INSERT INTO orders VALUES (90115,'cust-20872','{VISA}','2026-12',41.00);\n"
          f"INSERT INTO orders VALUES (90116,'cust-20873','{g4(MC2, '-')}','2028-06',129.95);\n")

    # 8. Archive: an old refunds export, nested inside a ZIP with a notes file.
    refunds = ("refund_id,card,amount\n"
               f"RF-2024-1101,{JCB},55.00\n"
               f"RF-2024-1102,{DISC},12.49\n").encode()
    (ROOT / "archive").mkdir(parents=True, exist_ok=True)
    (ROOT / "archive/2024_q4_refunds.zip").write_bytes(zip_bytes({
        "refunds_2024q4.csv": refunds,
        "README.txt": b"Exported for year-end reconciliation. Delete after audit.\n",
    }))
    handover = zip_bytes({"handover/notes.txt": b"vendor handover notes\n",
                          "handover/customer_cards.xlsx": b"(encrypted payload placeholder)"})
    (ROOT / "archive/vendor_handover_2025.zip").write_bytes(mark_encrypted(handover, "handover/customer_cards.xlsx"))

    # 9. HR: corporate card request form in Word, with the number split across runs.
    (ROOT / "hr").mkdir(parents=True, exist_ok=True)
    (ROOT / "hr/corporate_card_request_form.docx").write_bytes(docx_bytes([
        ["Corporate Card Request (fictional)"],
        ["Employee: E-1043   Cost centre: 4410"],
        ["Card number: ", "5105 1051", " 0510 5100"],
        ["Monthly limit: 5,000 CAD"],
    ]))

    # 10. False-positive bait: should produce no findings at all.
    write("marketing/campaign_metrics.md",
          "# Q3 campaign metrics (fictional)\n\n"
          "- Call centre: 1-800-555-0199, 902 555 0143\n"
          "- Tracking sample: 1Z999AA10123456784; ISBN 978-0-306-40615-7\n"
          "- Event ids: 1736452810000, 1736452811234 (Unix ms)\n"
          "- Coupon batch 9999 9999 9999 9995 and invoice 1234567890123452\n"
          "- Reference 4111111111111112 (fails Luhn), 0000000000000000, 1234567890123456\n"
          "- Pi to 20 places: 3.14159265358979323846\n"
          "- Customer id cid=4821, push pin: 1234 (no card on the line)\n"
          "- Order id ORD4111111111111111X (embedded in an id)\n")

    # 11. QA fixtures: published test cards, covered by a valid documented exception.
    write("qa/fixtures/payment_test_cards.json", json.dumps({"cards": [
        {"brand": "visa", "number": VISA}, {"brand": "mastercard", "number": MC},
        {"brand": "amex", "number": AMEX}]}, indent=2) + "\n")

    # 12. Legacy CRM export: its exception expired in June, so findings come back.
    write("legacy/crm_export_2023.csv",
          "customer_ref,card_on_file,updated\n"
          f"C-1001,{VISA3},2023-04-11\n"
          f"C-1002,{AMEX2},2023-05-02\n")

    # 13. Binary noise.
    (ROOT / "assets").mkdir(parents=True, exist_ok=True)
    (ROOT / "assets/logo.png").write_bytes(tiny_png())

    # Exceptions register: valid, expired, unused, invalid.
    (HERE / "suppressions.json").write_text(json.dumps({"suppressions": [
        {"path": "qa/fixtures/*", "kinds": ["PAN"], "reason": "QA fixtures contain published test PANs only; "
         "verified by QA lead, environment segmented from CDE", "approved_by": "ISO / CISO delegate",
         "ticket": "RISK-2026-031", "expires": "2027-06-30"},
        {"path": "legacy/*", "reason": "Legacy CRM decommissioning in progress", "approved_by": "Head of IT",
         "ticket": "RISK-2025-114", "expires": "2026-06-30"},
        {"path": "tokenization/*", "reason": "Token vault migration exports", "approved_by": "ISO",
         "ticket": "RISK-2026-007", "expires": "2027-01-31"},
        {"path": "reports/*", "reason": "Finance said it's fine", "expires": "2027-12-31"},
    ]}, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    build()
    files = sorted(p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*") if p.is_file())
    print(f"Wrote {len(files)} files under {ROOT.relative_to(HERE.parent)}/ and suppressions.json")
