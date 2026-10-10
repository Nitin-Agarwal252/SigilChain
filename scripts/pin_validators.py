"""Fetch validator keys and pin them after out-of-band fingerprint checks."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import httpx

from sigilchain import config
from sigilchain.identity import SIG_ALG


def _read_roster(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write_roster(path: Path, roster: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(roster, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nodes", default=",".join(config.NODE_URLS),
                        help="Comma-separated validator base URLs")
    parser.add_argument("--out", default=config.VALIDATOR_TRUST,
                        help="Path to the trusted validator roster JSON")
    args = parser.parse_args()

    nodes = [part.strip().rstrip("/") for part in args.nodes.split(",") if part.strip()]
    if not nodes:
        parser.error("provide at least one validator URL with --nodes")

    headers = {config.API_KEY_HEADER: config.API_KEY} if config.API_KEY else {}
    gathered: dict[str, dict[str, str]] = {}
    for node in nodes:
        response = httpx.get(f"{node}/node-info", headers=headers, timeout=5.0)
        response.raise_for_status()
        info = response.json()
        validator_id = str(info["validator_id"])
        sig_alg = str(info.get("validator_sig_alg", ""))
        if sig_alg != SIG_ALG:
            raise ValueError(f"{node} reports {sig_alg!r}; expected {SIG_ALG}.")
        public_key = str(info["validator_public_key"])
        fingerprint = hashlib.sha256(bytes.fromhex(public_key)).hexdigest()
        print(f"{validator_id} ({sig_alg}) at {node}: {fingerprint}")
        entry = {"sig_alg": sig_alg, "public_key": public_key, "fingerprint": fingerprint}
        if validator_id in gathered and gathered[validator_id] != entry:
            raise ValueError(f"Duplicate validator ID with different key material: {validator_id}")
        gathered[validator_id] = entry

    if len(gathered) < config.QUORUM_REQUIRED or len(gathered) != len(nodes):
        raise ValueError("Validator roster has duplicate IDs or fewer distinct validators than the configured quorum.")

    print("Compare each fingerprint with an independent trusted source before continuing.")
    print("Typing PIN records these keys for this installation; it does not independently verify their identity.")
    if input("Type PIN to save the roster: ").strip() != "PIN":
        print("Trust roster not written.")
        return 2

    output = Path(args.out)
    previous_roster = _read_roster(output)
    for validator_id, entry in gathered.items():
        previous = previous_roster.get(validator_id)
        if (isinstance(previous, dict)
                and (previous.get("public_key") != entry["public_key"]
                     or previous.get("sig_alg") != entry["sig_alg"])):
            older = previous.get("previous", []) if isinstance(previous, dict) else []
            entry["previous"] = [previous, *(item for item in older if isinstance(item, dict))]

    _write_roster(output, gathered)
    print(f"Pinned {len(gathered)} validator keys in {output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
