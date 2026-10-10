"""Environment-backed settings shared by the CLI, validators, and console."""
from __future__ import annotations

import os


def csv_env(name: str, default: str = "") -> list[str]:
    value = os.environ.get(name, default)
    return [part.strip().rstrip("/") for part in value.split(",") if part.strip()]


NODE_URLS = csv_env("SIGILCHAIN_NODE_URLS", "http://127.0.0.1:8001,http://127.0.0.1:8002,http://127.0.0.1:8003")
QUORUM_REQUIRED = int(os.environ.get("SIGILCHAIN_QUORUM_REQUIRED", "2"))
IDENTITY_DB = os.environ.get("SIGILCHAIN_IDENTITY_DB", "identity_registry.db")
KEYS_DIR = os.environ.get("SIGILCHAIN_KEYS_DIR", "local_keys")
VALIDATOR_ID = os.environ.get("SIGILCHAIN_VALIDATOR_ID", "validator1")
VALIDATOR_KEY_PATH = os.environ.get("SIGILCHAIN_VALIDATOR_KEY_PATH", f"validator_keys/{VALIDATOR_ID}.json")
VALIDATOR_TRUST = os.environ.get("SIGILCHAIN_VALIDATOR_TRUST_FILE", "validator_trust.json")
ETCD_ENDPOINTS = csv_env("SIGILCHAIN_ETCD_ENDPOINTS")
API_KEY = os.environ.get("SIGILCHAIN_API_KEY", "")
API_KEY_PREVIOUS = os.environ.get("SIGILCHAIN_API_KEY_PREVIOUS", "")
API_KEY_HEADER = "X-SigilChain-API-Key"
PDF_DPI = int(os.environ.get("SIGILCHAIN_PDF_DPI", "150"))
WATERMARK_TRANSFORM = os.environ.get("SIGILCHAIN_WATERMARK_TRANSFORM", "dct").lower()
if WATERMARK_TRANSFORM not in {"dct", "dwt-dct"}:
    raise ValueError("SIGILCHAIN_WATERMARK_TRANSFORM must be dct or dwt-dct")
EMBED_DELTA = float(os.environ.get("SIGILCHAIN_EMBED_DELTA", "110" if WATERMARK_TRANSFORM == "dct" else "60"))
EMBED_REPEAT = int(os.environ.get("SIGILCHAIN_EMBED_REPEAT", "40"))
