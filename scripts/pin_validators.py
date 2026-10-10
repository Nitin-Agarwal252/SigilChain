"""Fetch validator public keys; pin only after out-of-band fingerprint checks."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import httpx

from sigilchain import config
from sigilchain.identity import SIG_ALG


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nodes", default=",".join(config.NODE_URLS))
    parser.add_argument("--out", default=config.VALIDATOR_TRUST)
    args = parser.parse_args()
    headers = {config.API_KEY_HEADER: config.API_KEY} if config.API_KEY else {}
    gathered = {}
    for node in [part.strip().rstrip("/") for part in args.nodes.split(",") if part.strip()]:
        response = httpx.get(node + "/node-info", headers=headers, timeout=5.0)
        response.raise_for_status()
        info = response.json()
        if info.get("validator_sig_alg") != SIG_ALG:
            raise ValueError(f"{node} does not use the expected {SIG_ALG} signature algorithm.")
        fingerprint = hashlib.sha256(bytes.fromhex(info["validator_public_key"])).hexdigest()
        print(f"{info['validator_id']}: {fingerprint}")
        gathered[info["validator_id"]] = {"sig_alg": info["validator_sig_alg"],
            "public_key": info["validator_public_key"], "fingerprint": fingerprint}
    if len(gathered) < config.QUORUM_REQUIRED or len(gathered) != len([part for part in args.nodes.split(",") if part.strip()]):
        raise ValueError("Validator roster contains duplicate validator IDs or fewer nodes than the configured quorum.")
    print("Compare each fingerprint through an independent trusted channel.")
    if input("Type PIN to save this roster: ").strip() != "PIN":
        print("No keys pinned.")
        return 1
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(gathered, indent=2), encoding="utf-8")
    try:
        output.chmod(0o600)
    except OSError:
        pass
    print(f"Pinned {len(gathered)} validator keys in {output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
