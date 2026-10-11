"""
Ledger hash-chain test — this one runs fully in-sandbox (pure Python +
sqlite3, no PQC needed) so it's proven here, not just written.

The important part isn't that appending/reading works (that's the easy
part) — it's proving the tamper-evidence claim for real: directly edit a
row in the SQLite file (bypassing ledger.py entirely, exactly like a
privileged admin with direct DB access would), then show
verify_chain_integrity() catches it.

Run: python tests/test_part5_ledger.py
"""

import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from validator import ledger

DB_PATH = "test_ledger.db"


def main():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    ledger.init_db(DB_PATH)

    print("=== Appending 3 entries ===")
    entries = [
        ("wm-aaa111", b'{"doc_id":"briefing-001","recipient_id":"nitin"}', b"\x01\x02fake-sig-1"),
        ("wm-bbb222", b'{"doc_id":"briefing-001","recipient_id":"ashish"}', b"\x03\x04fake-sig-2"),
        ("wm-ccc333", b'{"doc_id":"briefing-002","recipient_id":"nitin"}', b"\x05\x06fake-sig-3"),
    ]
    hashes = []
    for wm_id, record, sig in entries:
        h = ledger.append_entry(DB_PATH, wm_id, record, sig)
        hashes.append(h)
        print(f"  committed {wm_id} -> entry_hash {h[:16]}...")

    print("\n=== Lookup by watermark_id ===")
    found = ledger.get_by_watermark_id(DB_PATH, "wm-bbb222")
    print(f"  found: {found is not None}")
    print(f"  record_json: {found['record_json']}")

    not_found = ledger.get_by_watermark_id(DB_PATH, "wm-does-not-exist")
    print(f"  nonexistent watermark_id correctly returns None: {not_found is None}")

    print("\n=== Chain integrity check (before tampering) ===")
    ok, msg = ledger.verify_chain_integrity(DB_PATH)
    print(f"  {ok}: {msg}")

    print("\n=== Simulating a privileged admin directly editing the DB ===")
    print("  (bypassing ledger.py entirely -- editing the SQLite file directly)")
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "UPDATE ledger SET record_json = ? WHERE watermark_id = ?",
        ('{"doc_id":"briefing-001","recipient_id":"ashish-FRAMED"}', "wm-bbb222"),
    )
    conn.commit()
    conn.close()
    print("  tampered: changed recipient_id on wm-bbb222's record directly in the DB file")

    print("\n=== Chain integrity check (after tampering) ===")
    ok2, msg2 = ledger.verify_chain_integrity(DB_PATH)
    print(f"  {ok2}: {msg2}")

    print("\n=== RESULT ===")
    all_ok = (
        found is not None
        and not_found is None
        and ok is True
        and ok2 is False
    )
    if all_ok:
        print("Ledger fully working: append/lookup correct, and direct DB "
              "tampering was successfully detected by the hash chain.")
    else:
        print("Something didn't match expectations -- see output above.")

    os.remove(DB_PATH)


if __name__ == "__main__":
    main()
