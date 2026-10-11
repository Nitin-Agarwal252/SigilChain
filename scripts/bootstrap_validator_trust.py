"""Pin validator signing keys after checking fingerprints out of band."""

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import config


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nodes", default=",".join(config.NODE_URLS),
                        help="Comma-separated validator base URLs")
    parser.add_argument("--out", default=config.VALIDATOR_TRUST_FILE,
                        help="Trusted key roster JSON path")
    args = parser.parse_args()
    headers = {config.API_KEY_HEADER: config.API_KEY} if config.API_KEY else {}
    trusted = {}
    try:
        with open(args.out, encoding="utf-8") as f:
            previous_roster = json.load(f)
        if not isinstance(previous_roster, dict):
            previous_roster = {}
    except (OSError, json.JSONDecodeError):
        previous_roster = {}

    for url in [item.strip().rstrip("/") for item in args.nodes.split(",") if item.strip()]:
        response = httpx.get(f"{url}/node-info", headers=headers, timeout=5)
        response.raise_for_status()
        data = response.json()
        validator_id = data["validator_id"]
        public_key = data["validator_public_key"]
        sig_alg = data.get("validator_sig_alg", "Ed25519")
        fingerprint = hashlib.sha256(bytes.fromhex(public_key)).hexdigest()
        if validator_id in trusted and trusted[validator_id] != public_key:
            raise ValueError(f"Duplicate validator ID with a different key at {url}")
        trusted[validator_id] = public_key
        print(f"{validator_id} ({sig_alg}) at {url}: {fingerprint}")

    if len(trusted) < config.QUORUM_REQUIRED:
        raise ValueError("Fetched fewer validator keys than the configured quorum requires.")
    typed = input("Compare fingerprints through a trusted channel. Type PIN to trust the current validator keys: ").strip()
    if typed != "PIN":
        print("Trust roster not written.")
        return 2

    parent = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(parent, exist_ok=True)
    if previous_roster and os.path.isfile(args.out) and previous_roster != trusted:
        backup_path = args.out + ".previous"
        shutil.copy2(args.out, backup_path)
        print(f"Previous trust roster backed up to {backup_path} for historical evidence verification.")
    fd, temp_path = tempfile.mkstemp(prefix=".validator-trust-", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(trusted, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, args.out)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
    print(f"Pinned {len(trusted)} validator keys in {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
