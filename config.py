"""
SigilChain — centralized configuration.

Before this module existed, validator node addresses were hardcoded
separately in agent/cli.py, trace_console/app.py, and
tests/test_part5_quorum.py; embedding parameters (delta, repeat) were
hardcoded separately in agent/cli.py and trace_console/app.py; and
storage paths were hardcoded in crypto/keys.py. Three independent copies
of the same numbers is exactly how a demo silently breaks the moment one
of them drifts -- this module is the fix: one place to read from, one
place to change.

Every value here can be overridden with an environment variable. The
defaults reproduce the original localhost demo setup exactly, so nothing
that already worked stops working. In Docker Compose, SIGILCHAIN_NODE_URLS
is set to the service names instead (see docker-compose.yml) -- that's
the only thing that actually changes between "3 terminals on localhost"
and "3 containers on a real network."
"""

import os
import json


def _env_list(name: str, default: list[str]) -> list[str]:
    raw = os.environ.get(name)
    if not raw:
        return default
    return [u.strip() for u in raw.split(",") if u.strip()]


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    return int(raw) if raw else default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    return float(raw) if raw else default


# --- Validator endpoints and receipt quorum ---
# Docker Compose sets SIGILCHAIN_NODE_URLS to http://validator1:8001,... --
# the service names resolve on the compose network. Local/manual runs use
# the localhost default below, matching the original demo setup.
NODE_URLS = _env_list("SIGILCHAIN_NODE_URLS", [
    "http://127.0.0.1:8001",
    "http://127.0.0.1:8002",
    "http://127.0.0.1:8003",
])
QUORUM_REQUIRED = _env_int("SIGILCHAIN_QUORUM_REQUIRED", 2)

# --- Storage paths ---
# Each validator still has a local SQLite path for its signed receipt cache.
# Compose additionally sets SIGILCHAIN_ETCD_ENDPOINTS so event ordering and
# commitment use the shared Raft log. With no etcd endpoints, standalone
# development uses local SQLite and has no distributed consensus.
IDENTITY_REGISTRY_DB = os.environ.get("SIGILCHAIN_IDENTITY_DB", "identity_registry.db")
LOCAL_KEYS_DIR = os.environ.get("SIGILCHAIN_KEYS_DIR", "local_keys")
LEDGER_DB = os.environ.get("SIGILCHAIN_LEDGER_DB", "node_ledger.db")
VALIDATOR_ID = os.environ.get(
    "SIGILCHAIN_VALIDATOR_ID",
    "validator-" + os.path.splitext(os.path.basename(LEDGER_DB))[0],
)
VALIDATOR_KEY_PATH = os.environ.get(
    "SIGILCHAIN_VALIDATOR_KEY_PATH",
    os.path.join("validator_keys", f"{VALIDATOR_ID}.json"),
)
VALIDATOR_TRUST_FILE = os.environ.get("SIGILCHAIN_VALIDATOR_TRUST_FILE", "validator_trust.json")
try:
    with open(VALIDATOR_TRUST_FILE, encoding="utf-8") as _trust_file:
        VALIDATOR_TRUSTED_KEYS = json.load(_trust_file)
except (OSError, json.JSONDecodeError):
    VALIDATOR_TRUSTED_KEYS = {}
REQUIRE_TRUSTED_VALIDATORS = os.environ.get("SIGILCHAIN_REQUIRE_TRUSTED_VALIDATORS", "1").lower() not in {
    "0", "false", "no"
}


def trusted_validator_keys() -> dict:
    """Reload the roster so a running console sees a newly pinned roster."""
    try:
        with open(VALIDATOR_TRUST_FILE, encoding="utf-8") as trust_file:
            roster = json.load(trust_file)
        return roster if isinstance(roster, dict) else {}
    except FileNotFoundError:
        return VALIDATOR_TRUSTED_KEYS
    except (OSError, json.JSONDecodeError):
        return {}


def validator_key_is_trusted(validator_id: str, public_key: str,
                             sig_alg: str | None = None) -> bool:
    """Match a validator key against current or retained historical pins.

    String entries are the legacy trust-roster format. Structured entries
    are emitted by the updated bootstrap script and retain old pins so
    already-issued receipts remain verifiable after a validator key rotates.
    """
    entry = trusted_validator_keys().get(validator_id)
    if isinstance(entry, str):
        return entry == public_key
    if not isinstance(entry, dict):
        return False
    candidates = [entry, *entry.get("previous", [])]
    return any(
        isinstance(candidate, dict)
        and candidate.get("public_key") == public_key
        and (not sig_alg or not candidate.get("sig_alg")
             or candidate.get("sig_alg") == sig_alg)
        for candidate in candidates
    )

# --- PDF rasterization ---
PDF_RENDER_DPI = _env_int("SIGILCHAIN_PDF_DPI", 150)

# --- Watermark embedding (Part 3) ---
# The embedder (agent/cli.py) and the extractor (trace_console/app.py)
# MUST agree on these two values, or extraction silently breaks -- they
# are not something to tune independently per file anymore.
WATERMARK_TRANSFORM = os.environ.get("SIGILCHAIN_WATERMARK_TRANSFORM", "dct").strip().lower()
if WATERMARK_TRANSFORM not in {"dct", "dwt-dct"}:
    raise ValueError("SIGILCHAIN_WATERMARK_TRANSFORM must be 'dct' or 'dwt-dct'.")
_default_embed_delta = 60.0 if WATERMARK_TRANSFORM == "dwt-dct" else 110.0
EMBED_DELTA = _env_float("SIGILCHAIN_EMBED_DELTA", _default_embed_delta)
EMBED_REPEAT = _env_int("SIGILCHAIN_EMBED_REPEAT", 40)

# Canonical page sizes (width, height in px at PDF_RENDER_DPI) the trace
# console tries when a leaked image doesn't decode at its own dimensions --
# i.e. a photo, or a screenshot taken at a different zoom/crop. This is
# what Part 7's recover_capture() warps toward. Extend this dict if your
# documents use a page size other than Letter or A4.
CANONICAL_PAGE_SIZES = {
    "letter": (1275, 1650),   # 8.5 x 11 in @ 150 DPI
    "a4": (1240, 1754),       # 210 x 297 mm @ 150 DPI
}

# --- Geometric correction (Part 7) tuning ---
# tiles=4, search_range=8 were the settings validated in
# tests/test_part7_geometric.py (0% bit error on synthetic photos at
# realistic tilt). Change only alongside re-running that test.
GEOMETRIC_CORRECTION_TILES = _env_int("SIGILCHAIN_GC_TILES", 4)
GEOMETRIC_CORRECTION_SEARCH_RANGE = _env_int("SIGILCHAIN_GC_SEARCH_RANGE", 8)

# --- API authentication ---
# A shared deployment-wide key, not a per-user credential -- the threat
# model here is "keep this off the open network / out of reach of anyone
# who isn't part of this deployment," not multi-tenant access control.
# Every validator node checks it on every endpoint; every client
# (agent/cli.py, trace_console/app.py, agent/quorum_client.py) attaches it
# automatically whenever it's set.
#
# Deliberately NOT required: if this is empty (the default), auth is off
# and every endpoint is open -- matching the original behavior exactly, so
# local/dev setups that never heard of this still work unchanged. Each
# validator node prints a loud warning on startup when this is the case,
# specifically so "I forgot to set this" doesn't go unnoticed. It is
# genuinely required before this touches any network you don't fully
# trust.
API_KEY = os.environ.get("SIGILCHAIN_API_KEY", "")
API_KEY_HEADER = "X-SigilChain-API-Key"
