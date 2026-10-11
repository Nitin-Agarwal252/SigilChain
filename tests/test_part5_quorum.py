"""
Validator quorum end-to-end check. Requires the three Compose validators
and their shared etcd/Raft log to be running first.

    docker compose up -d
    docker compose run --rm cli python tests/test_part5_quorum.py

What this proves: a signed record enters one ordered etcd/Raft log and is
endorsed by distinct validator signing keys; bad recipient signatures are
rejected. Raft is crash-fault consensus, not Byzantine consensus.
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import httpx

import config
from crypto.keys import load_identity, generate_identity, register_identity, lookup_identity
from crypto.sign import build_record, sign_record

NODE_URLS = config.NODE_URLS


def ensure_identity(recipient_id: str) -> dict:
    try:
        load_identity(recipient_id)
    except FileNotFoundError:
        pub = generate_identity(recipient_id)
        register_identity(pub)
    return lookup_identity(recipient_id)


def check_nodes_reachable():
    print("=== Checking all 3 nodes are reachable ===")
    all_up = True
    headers = {config.API_KEY_HEADER: config.API_KEY} if config.API_KEY else {}
    for url in NODE_URLS:
        try:
            r = httpx.get(f"{url}/chain-integrity", headers=headers, timeout=3.0)
            r.raise_for_status()
            print(f"  {url} -- UP ({r.json()})")
        except httpx.HTTPError as e:
            print(f"  {url} -- NOT REACHABLE ({e})")
            all_up = False
    if not all_up:
        print("\nOne or more nodes aren't reachable. Make sure all 3 uvicorn "
              "processes from the docstring above are running, then re-run this script.")
        sys.exit(1)
    print()


def main():
    check_nodes_reachable()

    from agent.quorum_client import submit_to_quorum, check_watermark

    nitin_pub = ensure_identity("nitin")
    nitin_private = load_identity("nitin")

    watermark_id = f"wm-quorum-test-{int(time.time())}"
    record_bytes = build_record(
        doc_id="briefing-quorum-test",
        recipient_id="nitin",
        watermark_id=watermark_id,
        marked_pdf_bytes=b"fake marked pdf bytes for quorum test",
    )
    signature = sign_record(record_bytes, nitin_private["sig_alg"], bytes.fromhex(nitin_private["sig_secret"]))

    print(f"=== Submitting watermark_id={watermark_id} to all 3 nodes ===")
    result = submit_to_quorum(NODE_URLS, watermark_id, record_bytes, signature, "nitin", required=config.QUORUM_REQUIRED)
    print(f"  committed:   {result['committed']}  (expect True -- 2-of-3 should accept)")
    print(f"  accepted by: {[a['url'] for a in result['accepted_by']]}")
    print(f"  rejected by: {result['rejected_by']}")
    print(f"  unreachable: {result['unreachable']}")

    print(f"\n=== Querying all 3 nodes for watermark_id={watermark_id} ===")
    views = check_watermark(NODE_URLS, watermark_id)
    for v in views:
        print(f"  {v['url']}: found={v.get('found')}  entry_hash={str(v.get('entry_hash'))[:16]}...")

    print("\n=== Confirming a BAD signature is rejected by every node ===")
    bad_signature = b"\x00" * len(signature)
    # Keep the signed record's indexed ID unchanged so validators reach and
    # reject the deliberately malformed recipient signature itself.
    bad_watermark_id = watermark_id
    bad_result = submit_to_quorum(NODE_URLS, bad_watermark_id, record_bytes, bad_signature, "nitin", required=config.QUORUM_REQUIRED)
    print(f"  committed: {bad_result['committed']}  (expect False)")
    print(f"  rejected by: {[r['url'] for r in bad_result['rejected_by']]}  (expect all 3)")

    print("\n=== Chain integrity on all 3 nodes (should still be intact) ===")
    headers = {config.API_KEY_HEADER: config.API_KEY} if config.API_KEY else {}
    for url in NODE_URLS:
        r = httpx.get(f"{url}/chain-integrity", headers=headers, timeout=3.0).json()
        print(f"  {url}: {r}")

    print("\n=== RESULT ===")
    ok = (
        result["committed"] is True
        and len(result["accepted_by"]) == 3
        and all(v.get("found") and v.get("chain_valid") and v.get("validator_trusted") for v in views)
        and all(
            next((a["receipt_signature_hex"] for a in result["accepted_by"]
                  if a["validator_id"] == v.get("validator_id")), None)
            == v.get("receipt_signature_hex")
            for v in views
        )
        and bad_result["committed"] is False
        and len(bad_result["rejected_by"]) == 3
    )
    if ok:
        print("All configured nodes acknowledged the same Raft-committed event "
              "and rejected the bad signature. This demonstrates crash-fault "
              "consensus plus distinct validator receipts, not Byzantine consensus.")
    else:
        print("Something above didn't match expectations -- paste this full output back.")


if __name__ == "__main__":
    main()
