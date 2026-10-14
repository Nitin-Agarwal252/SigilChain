"""
SigilChain — Trace Console (Part 6, revised).

Changes from the first version:
  - Reed-Solomon aware: unpacks via watermark.payload.unpack_from_embedding,
    matching whatever agent/cli.py used at embed time.
  - Accepts a PDF directly, not just a single image -- checks every page
    independently (useful if a leak is a whole compiled document rather
    than one screenshot, or mixes pages from different recipients' copies).
  - Visual styling matched to the deck's palette (dark background, red
    accent, monospace labels) rather than default Streamlit theming.

Still does NOT just trust the validator API: after fetching a record and
signature back, it independently reconstructs the exact signed bytes
(crypto.sign.serialize_record) and re-runs ML-DSA verification itself.

Run:
    streamlit run trace_console/app.py
"""

import base64
import json
import hashlib
import html
import os
import sys
from pathlib import Path

import numpy as np
import streamlit as st
from PIL import Image

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import config
if config.WATERMARK_TRANSFORM == "dwt-dct":
    from watermark.dwt_dct_watermark import extract_bits_with_confidence
else:
    from watermark.dct_watermark import extract_bits_with_confidence
from watermark.payload import bits_to_bytes, unpack_from_embedding, ENCODED_SIZE, RS_AVAILABLE
from watermark.pdf_utils import pdf_to_grayscale_images
from watermark.geometric_correction import auto_correct
from crypto.sign import serialize_record, verify_record
from crypto.keys import lookup_identity
from crypto.transfer import acceptance_event_id
from agent.quorum_client import check_watermark, list_transfer_children, verify_chain_proof

NODE_URLS = config.NODE_URLS


def _verified_transfer_event(event_id: str) -> dict | None:
    """Return one sender-signed transfer only when a trusted validator quorum agrees."""
    groups = {}
    for view in check_watermark(NODE_URLS, event_id):
        if not (view.get("found") and view.get("chain_valid") and view.get("validator_trusted")
                and view.get("validator_id")):
            continue
        record = view.get("record") or {}
        try:
            identity = lookup_identity(record["from_id"], key_version=record["from_key_version"],
                                       allow_revoked=True)
            raw = serialize_record(record)
            valid = (record.get("event_type") == "document_transfer"
                     and record.get("event_id") == event_id
                     and verify_record(raw, bytes.fromhex(view["signature_hex"]),
                                       identity["sig_alg"], bytes.fromhex(identity["sig_public"])))
        except (KeyError, TypeError, ValueError):
            valid = False
        if valid:
            groups.setdefault((raw.hex(), view["signature_hex"]), {"record": record, "nodes": set()})[
                "nodes"].add(view["validator_id"])
    return next((group["record"] for group in groups.values()
                 if len(group["nodes"]) >= config.QUORUM_REQUIRED), None)


def _verified_outgoing_branches(parent_event_id: str, parent_acceptance_id: str,
                                holder_id: str, document_id: str) -> list[dict]:
    """Walk the holder's verified transfer subtree; each fork remains its own event."""
    result = []
    queue = [(parent_event_id, parent_acceptance_id, holder_id, 1)]
    visited = set()
    while queue and len(visited) < 64:
        parent_id, accepted_id, expected_sender, depth = queue.pop(0)
        for child_id in list_transfer_children(NODE_URLS, parent_id):
            if child_id in visited:
                continue
            visited.add(child_id)
            child = _verified_transfer_event(child_id)
            if (not child or child.get("from_id") != expected_sender
                    or child.get("doc_id") != document_id
                    or child.get("parent_acceptance_event_id") != accepted_id):
                continue
            trail, _ = _verified_transfer_trail(child_id)
            child_acceptance_id = None
            if trail and trail[-1]["record"].get("event_id") == child_id:
                child_acceptance_id = trail[-1].get("acceptance", {}).get("record", {}).get("event_id")
            result.append({"record": child, "depth": depth,
                           "recipient_accepted": child_acceptance_id is not None})
            if child_acceptance_id:
                queue.append((child_id, child_acceptance_id, child.get("to_id"), depth + 1))
    return result


def _verified_transfer_trail(first_event_id: str | None) -> tuple[list[dict], str | None]:
    """Walk transfer parent IDs, requiring a trusted quorum and sender signature at each step."""
    if not first_event_id:
        return [], None
    newest_first = []
    seen = set()
    current = first_event_id
    try:
        while current:
            if current in seen or len(seen) >= 32:
                return [], "Transfer trail contains a cycle or exceeds 32 events."
            seen.add(current)
            views = check_watermark(NODE_URLS, current)
            unique = {}
            for view in views:
                if (view.get("found") and view.get("chain_valid") and view.get("validator_trusted")
                        and view.get("validator_id")):
                    unique.setdefault(view["validator_id"], view)
            groups = {}
            for view in unique.values():
                record = view.get("record") or {}
                if (record.get("event_type") != "document_transfer"
                        or record.get("event_id") != current):
                    continue
                canonical = serialize_record(record)
                signature = bytes.fromhex(view["signature_hex"])
                try:
                    identity = lookup_identity(
                        record["from_id"], key_version=record["from_key_version"], allow_revoked=True
                    )
                    valid_signature = verify_record(
                        canonical, signature, identity["sig_alg"], bytes.fromhex(identity["sig_public"])
                    )
                except (KeyError, ValueError, TypeError):
                    valid_signature = False
                if not valid_signature:
                    continue
                fingerprint = (canonical.hex(), view["signature_hex"])
                group = groups.setdefault(fingerprint, {
                    "record": record, "signature_hex": view["signature_hex"],
                    "sender_public_identity": {"recipient_id": record["from_id"],
                                               "key_version": record["from_key_version"],
                                               "sig_alg": identity["sig_alg"],
                                               "sig_public": identity["sig_public"]},
                    "nodes": [],
                })
                group["nodes"].append(view)
            quorum = next((group for group in groups.values()
                           if len(group["nodes"]) >= config.QUORUM_REQUIRED), None)
            if quorum is None:
                return [], f"Transfer event {current} did not have a valid trusted quorum and sender signature."
            transfer = quorum["record"]
            accepted_id = acceptance_event_id(
                current, transfer["to_id"], transfer["target_package_id"],
                transfer["target_package_sha256"],
            )
            accepted_views = check_watermark(NODE_URLS, accepted_id)
            accepted_groups = {}
            for view in accepted_views:
                if not (view.get("found") and view.get("chain_valid") and view.get("validator_trusted")
                        and view.get("validator_id")):
                    continue
                accepted = view.get("record") or {}
                try:
                    accepted_identity = lookup_identity(
                        accepted["recipient_id"], key_version=accepted["key_version"], allow_revoked=True
                    )
                    accepted_bytes = serialize_record(accepted)
                    accepted_signature = bytes.fromhex(view["signature_hex"])
                    accepted_valid = (
                        accepted.get("event_type") == "handoff_acceptance"
                        and accepted.get("event_id") == accepted_id
                        and accepted.get("transfer_event_id") == current
                        and accepted.get("recipient_id") == transfer.get("to_id")
                        and accepted.get("doc_id") == transfer.get("doc_id")
                        and accepted.get("package_id") == transfer.get("target_package_id")
                        and accepted.get("package_sha256") == transfer.get("target_package_sha256")
                        and accepted.get("document_sha256") == transfer.get("target_document_sha256")
                        and verify_record(accepted_bytes, accepted_signature, accepted_identity["sig_alg"],
                                          bytes.fromhex(accepted_identity["sig_public"]))
                    )
                except (KeyError, ValueError, TypeError):
                    accepted_valid = False
                if not accepted_valid:
                    continue
                accepted_key = (accepted_bytes.hex(), view["signature_hex"])
                accepted_groups.setdefault(accepted_key, {
                    "record": accepted, "signature_hex": view["signature_hex"],
                    "identity": {"recipient_id": accepted["recipient_id"],
                                 "key_version": accepted["key_version"],
                                 "sig_alg": accepted_identity["sig_alg"],
                                 "sig_public": accepted_identity["sig_public"]},
                    "nodes": [],
                })["nodes"].append(view)
            accepted_quorum = next((group for group in accepted_groups.values()
                                    if len({item["validator_id"] for item in group["nodes"]})
                                    >= config.QUORUM_REQUIRED), None)
            if accepted_quorum is None:
                return [], f"Transfer {current} has no recipient-key-signed acceptance committed by a trusted quorum."
            newest_first.append({
                "record": quorum["record"],
                "signature_hex": quorum["signature_hex"],
                "sender_signature_verified_client_side": True,
                "sender_public_identity": quorum["sender_public_identity"],
                "validator_evidence": [{
                    "validator_id": view["validator_id"],
                    "entry_hash": view["entry_hash"],
                    "ledger_backend": view.get("ledger_backend"),
                    "receipt": view.get("receipt"),
                    "receipt_signature_hex": view.get("receipt_signature_hex"),
                    "validator_public_key": view.get("validator_public_key"),
                    "validator_sig_alg": view.get("validator_sig_alg"),
                } for view in quorum["nodes"]],
                "validator_chain_proofs": [view.get("chain_proof", []) for view in quorum["nodes"]],
                "acceptance": {
                    "record": accepted_quorum["record"],
                    "signature_hex": accepted_quorum["signature_hex"],
                    "recipient_public_identity": accepted_quorum["identity"],
                    "validator_evidence": [{
                        "validator_id": view["validator_id"],
                        "entry_hash": view["entry_hash"],
                        "ledger_backend": view.get("ledger_backend"),
                        "receipt": view.get("receipt"),
                        "receipt_signature_hex": view.get("receipt_signature_hex"),
                        "validator_public_key": view.get("validator_public_key"),
                        "validator_sig_alg": view.get("validator_sig_alg"),
                    } for view in accepted_quorum["nodes"]],
                    "validator_chain_proofs": [view.get("chain_proof", []) for view in accepted_quorum["nodes"]],
                },
            })
            current = quorum["record"].get("parent_transfer_event_id")
        return list(reversed(newest_first)), None
    except Exception as exc:
        return [], f"Could not verify transfer trail: {exc}"

# Must match agent/cli.py's value -- if these drift out of sync,
# extraction silently breaks.
EMBED_REPEAT = config.EMBED_REPEAT
MIN_RECOVERY_CONFIDENCE = float(os.environ.get("SIGILCHAIN_MIN_RECOVERY_CONFIDENCE", "0.60"))

# ---------- console presentation ----------
LOGO_PATH = Path(__file__).parent / "assets" / "sigilchain-icon-red-sigil.png"
st.set_page_config(
    page_title="SigilChain Trace Console",
    page_icon=str(LOGO_PATH) if LOGO_PATH.is_file() else "S",
    layout="wide",
)

st.markdown("""
<style>
    :root {
        color-scheme: dark;
        --sc-bg: #0c1118;
        --sc-panel: #141c27;
        --sc-panel-soft: #182331;
        --sc-line: #29394a;
        --sc-text: #edf2f7;
        --sc-muted: #aab7c6;
        --sc-red: #ef3340;
        --sc-green: #39d6a0;
    }
    .stApp { background: var(--sc-bg); color: var(--sc-text); }
    [data-testid="stHeader"] { background: rgba(12, 17, 24, .92); }
    [data-testid="stToolbar"] { right: 1rem; }
    .block-container { max-width: 1480px; padding-top: 1.35rem; padding-bottom: 3rem; }
    h1, h2, h3, h4 { color: var(--sc-text) !important; letter-spacing: -.02em; }
    p, label, [data-testid="stMarkdownContainer"] { color: var(--sc-muted); }
    code { color: #ff6872 !important; background: #202631 !important; }
    [data-testid="stFileUploader"] section {
        background: var(--sc-panel); border: 1px dashed #496078; border-radius: 12px;
    }
    [data-testid="stFileUploader"] button, .stDownloadButton button {
        border: 1px solid #4384ad; border-radius: 9px; background: #236b98;
        color: white; font-weight: 650;
    }
    [data-testid="stFileUploader"] button:hover, .stDownloadButton button:hover {
        border-color: #80c8f4; background: #2c7eae; color: white;
    }
    div[data-testid="stExpander"] {
        background: var(--sc-panel); border: 1px solid var(--sc-line); border-radius: 10px;
    }
    div[data-testid="stExpander"] summary, div[data-testid="stExpander"] summary p { color: var(--sc-text) !important; }
    .sc-topbar {
        display:flex; align-items:center; gap:14px; padding:12px 18px; margin:0 0 26px;
        border:1px solid var(--sc-line); border-radius:14px; background:var(--sc-panel);
    }
    .sc-brand { color:var(--sc-text); font-size:1.14rem; font-weight:750; line-height:1.15; }
    .sc-brand-sub { color:var(--sc-muted); font-size:.72rem; letter-spacing:.08em; text-transform:uppercase; }
    .sc-topbar-title { border-left:1px solid var(--sc-line); margin-left:4px; padding-left:18px;
        color:var(--sc-text); font-weight:650; }
    .sc-local-badge { margin-left:auto; border:1px solid #27523f; background:#11271f;
        border-radius:999px; padding:8px 14px; color:var(--sc-green); font-size:.78rem;
        letter-spacing:.04em; white-space:nowrap; }
    .sc-intro { color:var(--sc-muted); font-size:1.02rem; line-height:1.6; margin-top:-8px; }
    .sc-upload-caption { color:var(--sc-muted); font-size:.9rem; padding:0 2px 12px; }
    .sc-file-row { display:flex; align-items:center; gap:12px; padding:11px 15px; margin:8px 0 22px;
        border:1px solid var(--sc-line); border-radius:10px; background:var(--sc-panel); }
    .sc-file-type { color:#9bcdf0; background:#203448; border-radius:7px; padding:6px 9px;
        font-size:.74rem; font-weight:700; }
    .sc-file-name { color:var(--sc-text); font-weight:650; }
    .sc-file-meta { color:var(--sc-muted); margin-left:14px; font-size:.9rem; }
    .sc-card, .sc-verified, .sc-danger, .sc-side-card {
        border-radius:11px; padding:18px 20px; margin-bottom:13px;
    }
    .sc-card, .sc-side-card { background:var(--sc-panel); border:1px solid var(--sc-line); }
    .sc-verified { background:#10291f; border:1px solid #24784f; }
    .sc-danger { background:#2b171b; border:1px solid #843944; }
    .sc-label { color:#9caaba; font-family:ui-monospace,Consolas,monospace; font-size:.76rem;
        text-transform:uppercase; letter-spacing:.06em; }
    .sc-value { color:var(--sc-text); font-size:1rem; margin-top:3px; }
    .sc-mono { font-family:ui-monospace,Consolas,monospace; color:#ff5964; overflow-wrap:anywhere; }
    .sc-section-title { color:var(--sc-text); font-weight:700; margin-bottom:14px; }
    .sc-check { border-bottom:1px solid var(--sc-line); padding:8px 0 10px; }
    .sc-check:last-child { border-bottom:0; padding-bottom:0; }
    .sc-check-label { display:block; color:var(--sc-muted); font-size:.82rem; }
    .sc-check-value { display:block; color:var(--sc-green); font-weight:700; margin-top:2px; }
    .sc-evidence-copy { color:var(--sc-muted); font-size:.9rem; line-height:1.55; }
    .sc-interpretation { border-left:4px solid #f0c66a; background:#2a2518; color:#e7dfca;
        border-radius:0 9px 9px 0; padding:13px 16px; margin:3px 0 18px; line-height:1.55; }
    .sc-interpretation strong { color:#f2cb73; }
    @media (max-width: 760px) {
        .block-container { padding:1rem 1rem 2rem; }
        .sc-topbar { gap:9px; padding:10px; }
        .sc-topbar-title { display:none; }
        .sc-local-badge { font-size:.66rem; padding:7px 9px; }
        .sc-card, .sc-verified, .sc-danger, .sc-side-card { padding:15px; }
    }
</style>
""", unsafe_allow_html=True)

if LOGO_PATH.is_file():
    logo_data = base64.b64encode(LOGO_PATH.read_bytes()).decode("ascii")
    logo_markup = f"<img src='data:image/png;base64,{logo_data}' alt='SigilChain red sigil' width='48' height='48'>"
else:
    logo_markup = "<div class='sc-logo-fallback'>S</div>"
st.markdown(f"""<div class="sc-topbar">
    {logo_markup}
    <div><div class="sc-brand">SigilChain</div><div class="sc-brand-sub">Trace console</div></div>
    <div class="sc-topbar-title">Trace a leaked copy</div>
    <div class="sc-local-badge">LOCAL AIR-GAP DEMO</div>
    </div>""", unsafe_allow_html=True)

st.markdown("## Trace a leaked copy")
st.markdown(
    "<div class='sc-intro'>Upload a suspected leaked PDF or page image. Each page is checked independently "
    "against watermark records, validator proofs, and the registered recipient signature.</div>",
    unsafe_allow_html=True,
)
if not RS_AVAILABLE:
    st.warning(
        "reedsolo is not installed in this environment -- extraction will only work on images "
        "embedded WITHOUT Reed-Solomon encoding. Install reedsolo and restart for the full "
        "error-correction layer.",
        icon="\u26a0\ufe0f",
    )


def check_image(arr: np.ndarray) -> dict:
    """Run extraction + RS decode + node query + client-side signature
    re-verification on one grayscale image array. Returns a result dict
    with a `status` field the caller renders."""
    extraction_source = "original image"
    submitted_page_sha256 = hashlib.sha256(arr.tobytes()).hexdigest()
    try:
        bits, confidence = extract_bits_with_confidence(
            arr.astype(np.float64), ENCODED_SIZE * 8, repeat=EMBED_REPEAT
        )
        # Photo correction is a best-effort fallback. The confidence score
        # is a synchronization heuristic, not a calibrated probability.
        if confidence < MIN_RECOVERY_CONFIDENCE:
            corrected_candidates = [
                auto_correct(arr, output_size=(1275, 1650)),
                auto_correct(arr, output_size=(1240, 1754)),
            ]
            for corrected in corrected_candidates:
                if corrected is None:
                    continue
                corrected_bits, corrected_confidence = extract_bits_with_confidence(
                    corrected.astype(np.float64), ENCODED_SIZE * 8, repeat=EMBED_REPEAT
                )
                if corrected_confidence > confidence:
                    bits, confidence = corrected_bits, corrected_confidence
                    extraction_source = "perspective-corrected image (experimental)"
        if confidence < MIN_RECOVERY_CONFIDENCE:
            return {"status": "low_confidence", "confidence": confidence,
                    "minimum_confidence": MIN_RECOVERY_CONFIDENCE,
                    "message": "Watermark recovery is inconclusive; no recipient attribution was made."}
        encoded = bits_to_bytes(bits)
        watermark_id_bytes = unpack_from_embedding(encoded)
    except Exception as e:
        return {"status": "extraction_failed", "error": str(e)}

    watermark_id_hex = watermark_id_bytes.hex()
    views = check_watermark(NODE_URLS, watermark_id_hex)
    found_by_validator = {}
    for view in views:
        if (view.get("found") and view.get("chain_valid") and view.get("validator_trusted")
                and view.get("validator_id")):
            found_by_validator.setdefault(view["validator_id"], view)
    found_views = list(found_by_validator.values())

    if len(found_views) < config.QUORUM_REQUIRED:
        trust_errors = [v.get("validator_trust_error") for v in views
                        if v.get("found") and v.get("validator_trust_error")]
        quorum_message = (
            f"Records were returned, but fewer than {config.QUORUM_REQUIRED} distinct validator receipts "
            "matched the pinned trust roster. Pin the validator keys before relying on a trace."
            if trust_errors else
            f"Only {len(found_views)} of {len(NODE_URLS)} validators returned a trusted record with a valid chain; "
            f"{config.QUORUM_REQUIRED} are required."
        )
        return {"status": "not_found", "watermark_id": watermark_id_hex,
                "views": views, "found_count": len(found_views),
                "chain_valid_count": len(found_views), "confidence": confidence,
                "extraction_source": extraction_source, "message": quorum_message}

    try:
        verified_events = {}
        for view in found_views:
            record = view["record"]
            recipient_id = record["recipient_id"]
            if record.get("watermark_id") != watermark_id_hex:
                continue
            identity = lookup_identity(recipient_id,
                                       key_version=record.get("key_version", 1),
                                       allow_revoked=True)
            record_bytes = serialize_record(record)
            signature = bytes.fromhex(view["signature_hex"])
            sig_public = bytes.fromhex(identity["sig_public"])
            if verify_record(record_bytes, signature, identity["sig_alg"], sig_public):
                key = record_bytes.hex()
                verified_events.setdefault(key, {"record": record, "record_bytes": record_bytes,
                                                  "signatures": [], "nodes": []})
                verified_events[key]["signatures"].append(view["signature_hex"])
                verified_events[key]["nodes"].append(view)
    except Exception as e:
        return {"status": "verify_error", "watermark_id": watermark_id_hex, "error": str(e)}

    quorum_events = [event for event in verified_events.values()
                     if len(event["nodes"]) >= config.QUORUM_REQUIRED]
    if not quorum_events:
        return {"status": "not_found", "watermark_id": watermark_id_hex,
                "views": views, "found_count": 0, "chain_valid_count": len(found_views),
                "confidence": confidence, "extraction_source": extraction_source,
                "message": f"No matching signed record was verified by {config.QUORUM_REQUIRED} valid chains."}
    event = quorum_events[0]
    record = event["record"]
    signature_hex = event["signatures"][0]
    recipient_id = record["recipient_id"]
    transfer_trail, transfer_trail_error = _verified_transfer_trail(record.get("transfer_event_id"))
    if transfer_trail:
        endpoint = transfer_trail[-1]["record"]
        if (endpoint.get("event_id") != record.get("transfer_event_id")
                or endpoint.get("to_id") != record.get("recipient_id")
                or endpoint.get("doc_id") != record.get("doc_id")
                or endpoint.get("target_package_id") != record.get("package_id")
                or transfer_trail[-1].get("acceptance", {}).get("record", {}).get("event_id")
                    != record.get("handoff_acceptance_event_id")):
            transfer_trail = []
            transfer_trail_error = "The verified transfer trail does not end at this recipient and document."
        else:
            for older, newer in zip(transfer_trail, transfer_trail[1:]):
                previous = older["record"]
                following = newer["record"]
                if (following.get("parent_transfer_event_id") != previous.get("event_id")
                        or following.get("parent_acceptance_event_id")
                            != older.get("acceptance", {}).get("record", {}).get("event_id")
                        or previous.get("to_id") != following.get("from_id")
                        or previous.get("doc_id") != following.get("doc_id")
                        or previous.get("target_package_id") != following.get("source_package_id")
                        or previous.get("target_package_sha256") != following.get("source_package_sha256")
                        or previous.get("target_document_sha256") != following.get("source_document_sha256")):
                    transfer_trail = []
                    transfer_trail_error = "A transfer link, holder, document ID, or document hash is inconsistent."
                    break

    outgoing_branches = []
    source_transfer_id = record.get("transfer_event_id")
    if source_transfer_id and transfer_trail:
        expected_acceptance = record.get("handoff_acceptance_event_id")
        outgoing_branches = _verified_outgoing_branches(
            source_transfer_id, expected_acceptance, recipient_id, record.get("doc_id"),
        )

    return {
        "status": "verified",
        "watermark_id": watermark_id_hex,
        "record": record,
        "signature_hex": signature_hex,
        "record_bytes_hex": event["record_bytes"].hex(),
        "validator_evidence": [
            {"url": v["url"], "entry_hash": v["entry_hash"],
             "validator_id": v["validator_id"],
             "ledger_backend": v.get("ledger_backend", "unknown"),
             "chain_valid": v["chain_valid"], "chain_entries": len(v["chain_proof"]),
             "receipt": v["receipt"],
             "receipt_signature_hex": v["receipt_signature_hex"],
             "validator_public_key": v["validator_public_key"],
             "validator_sig_alg": v.get("validator_sig_alg")
                 or v["receipt"].get("validator_sig_alg", "Ed25519")}
            for v in event["nodes"]
        ],
        "validator_proofs": [v["chain_proof"] for v in event["nodes"]],
        "found_count": len(event["nodes"]),
        "confidence": confidence,
        "extraction_source": extraction_source,
        "submitted_page_sha256": submitted_page_sha256,
        "recipient_id": recipient_id,
        "transfer_trail": transfer_trail,
        "transfer_trail_error": transfer_trail_error,
        "outgoing_branches": outgoing_branches,
    }


def render_result(result: dict, page_label: str = ""):
    prefix = html.escape(f"{page_label}: " if page_label else "")

    if result["status"] == "extraction_failed":
        st.markdown(f"""<div class="sc-danger">
            <span class="sc-label">{prefix}extraction failed</span><br>
            <span class="sc-value">{html.escape(str(result['error']))}</span></div>""", unsafe_allow_html=True)
        return

    if result["status"] == "low_confidence":
        st.markdown(f"""<div class="sc-danger">
            <span class="sc-label">inconclusive watermark recovery</span><br>
            <span class="sc-value">{html.escape(result['message'])} Recovery agreement:
            {result['confidence']:.1%} (minimum {result['minimum_confidence']:.0%}).</span></div>""",
            unsafe_allow_html=True)
        return

    st.markdown(f"""<div class="sc-card">
        <span class="sc-label">{prefix}extracted watermark id</span><br>
        <span class="sc-mono">{result['watermark_id']}</span></div>""", unsafe_allow_html=True)

    if result["status"] == "not_found":
        st.markdown(f"""<div class="sc-danger">
            <span class="sc-label">no verified quorum record</span><br>
            <span class="sc-value">{html.escape(result.get('message', f"Only {result['found_count']} of 3 nodes returned a record with a valid chain (need {config.QUORUM_REQUIRED})."))}
            This result does not identify a recipient.</span></div>""",
            unsafe_allow_html=True)
        with st.expander(f"{prefix}Raw node responses"):
            st.json(result["views"])
        return

    if result["status"] == "verify_error":
        st.markdown(f"""<div class="sc-danger">
            <span class="sc-label">verification error</span><br>
            <span class="sc-value">{html.escape(str(result['error']))}</span></div>""", unsafe_allow_html=True)
        return

    if result["status"] == "signature_invalid":
        st.markdown("""<div class="sc-danger">
            <span class="sc-label">\u26a0\ufe0f signature does not verify</span><br>
            <span class="sc-value">Record found on the ledger, but the signature does NOT
            match the recipient's registered public key. Do not trust this record.</span>
            </div>""", unsafe_allow_html=True)
        return

    # verified
    record = result["record"]
    safe_recipient = html.escape(str(result["recipient_id"]))
    safe_doc_id = html.escape(str(record.get("doc_id", "")))
    safe_timestamp = html.escape(str(record.get("timestamp", "")))
    backend = html.escape(str(result["validator_evidence"][0].get("ledger_backend", "unknown")))
    extraction_source = html.escape(str(result["extraction_source"]))
    person_auth = record.get("person_auth") if isinstance(record.get("person_auth"), dict) else None
    auth_subject = html.escape(str((person_auth or {}).get("subject", "")))
    tpm_evidence = [item["receipt"]["machine_attestation"]
                    for item in result["validator_evidence"]
                    if isinstance(item.get("receipt"), dict)
                    and isinstance(item["receipt"].get("machine_attestation"), dict)]
    person_auth_receipts = [item["receipt"]["person_auth_verification"]
                            for item in result["validator_evidence"]
                            if isinstance(item.get("receipt"), dict)
                            and isinstance(item["receipt"].get("person_auth_verification"), dict)]
    tpm_label = (f"{len(tpm_evidence)} signed validator receipts include TPM verifier evidence"
                 if tpm_evidence else "Not recorded")
    evidence = {
        "evidence_type": "SigilChain decryption-session attribution",
        "claim_limit": "The recovered watermark links this copy to a signed decryption-session record. It does not by itself prove who physically distributed the leaked copy. The event timestamp comes from the recipient device and is not an independently trusted time source.",
        "person_authentication_limit": ("The OIDC issuer asserted this subject and mapped it to the recipient account; this does not prove which human was physically using the device."
                                        if person_auth else None),
        "person_authentication_validator_receipts": person_auth_receipts,
        "extracted_watermark_id": result["watermark_id"],
        "required_quorum": config.QUORUM_REQUIRED,
        "ledger_backend": result["validator_evidence"][0].get("ledger_backend", "unknown"),
        "consensus_limit": "etcd Raft provides crash-fault majority consensus; it is not Byzantine fault tolerant. Validator receipts attest each node observed this ordered log entry.",
        "submitted_page_sha256": result["submitted_page_sha256"],
        "recovery_agreement": result["confidence"],
        "extraction_source": result["extraction_source"],
        "record": record,
        "transfer_trail": result.get("transfer_trail", []),
        "transfer_trail_error": result.get("transfer_trail_error"),
        "signature_hex": result["signature_hex"],
        "canonical_record_bytes_hex": result["record_bytes_hex"],
        "validator_evidence": result["validator_evidence"],
        "tpm_attestation_evidence": tpm_evidence,
        "validator_chain_proofs": result["validator_proofs"],
        "recipient_signature_verified_client_side": True,
        "recipient_public_identity": {
            "recipient_id": result["recipient_id"],
            "sig_alg": lookup_identity(
                result["recipient_id"],
                key_version=record.get("key_version", 1),
                allow_revoked=True,
            )["sig_alg"],
            "sig_public": lookup_identity(
                result["recipient_id"],
                key_version=record.get("key_version", 1),
                allow_revoked=True,
            )["sig_public"],
        },
    }

    details_col, checks_col = st.columns([1.85, 0.95], gap="large")
    with details_col:
        st.markdown(f"""<div class="sc-verified">
            <span class="sc-label">● &nbsp; verified</span><br><br>
            <span class="sc-value" style="font-size:1.28em;font-weight:750;">
            Signed session associated with recipient key: {safe_recipient}</span>
            <p style="margin:8px 0 18px;color:#b7cbbb;">The recovered mark matches a recipient-key-signed session record.</p>
            <hr style="border-color:#28513e;margin:14px 0 18px;">
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:18px 26px;">
              <div><span class="sc-label">Document ID</span><br><b>{safe_doc_id}</b></div>
              <div><span class="sc-label">Agent-reported timestamp</span><br><b>{safe_timestamp}</b></div>
              <div><span class="sc-label">Validator records</span><br><b>{result['found_count']} valid records with chain proofs</b></div>
              <div><span class="sc-label">Shared log</span><br><b>{backend}</b></div>
              <div><span class="sc-label">Watermark recovery agreement</span><br><b>{result['confidence']:.1%}</b></div>
              <div><span class="sc-label">Recovery path</span><br><b>{extraction_source}</b></div>
              <div><span class="sc-label">Machine attestation</span><br><b>{html.escape(tpm_label)}</b></div>
              {f'<div><span class="sc-label">OIDC subject (validator-verified)</span><br><b>{auth_subject}</b><br><small>{len(person_auth_receipts)} signed validator receipts attest to token validation</small></div>' if person_auth else ''}
            </div>
        </div>""", unsafe_allow_html=True)
        trail = result.get("transfer_trail", [])
        if trail:
            st.markdown("#### Document transfer trail")
            for handoff in trail:
                event = handoff["record"]
                sender = html.escape(str(event.get("from_id", "unknown")))
                recipient = html.escape(str(event.get("to_id", "unknown")))
                when = html.escape(str(event.get("timestamp", "")))
                st.markdown(f"**{sender} → {recipient}** · sender-signed offer; recipient-key acceptance verified · {when}")
            st.caption("Each hop links a sender-signed offer to a recipient-key-signed acceptance of the exact package. This confirms key-level receipt/acknowledgment, not human identity, physical delivery, or who leaked it.")
        elif record.get("transfer_event_id"):
            st.warning(result.get("transfer_trail_error") or "The package references a transfer event, but no verified trail was returned.")
        else:
            st.caption("No document transfer event was recorded for this package.")
        branches = result.get("outgoing_branches", [])
        if branches:
            st.markdown("#### Recorded branches from this recipient")
            for branch in branches:
                event = branch["record"]
                sender = html.escape(str(event.get("from_id", "unknown")))
                target = html.escape(str(event.get("to_id", "unknown")))
                branch_time = html.escape(str(event.get("timestamp", "")))
                accepted_status = "recipient accepted" if branch.get("recipient_accepted") else "acceptance not recorded"
                indent = "&nbsp;" * min(int(branch.get("depth", 1)) * 4, 24)
                st.markdown(f"{indent}**{sender} → {target}** · signed quorum offer · {accepted_status} · {branch_time}",
                            unsafe_allow_html=True)
            st.caption("The branch graph shows key-signed offers and any recorded acceptances. A transfer trail helps narrow custody and time; it does not establish who physically leaked a copy.")
    with checks_col:
        st.markdown(f"""<div class="sc-side-card">
            <div class="sc-section-title">What was verified</div>
            <div class="sc-check"><span class="sc-check-label">Recipient event signature</span><span class="sc-check-value">Verified</span></div>
            <div class="sc-check"><span class="sc-check-label">Hash-chain proofs</span><span class="sc-check-value">{result['found_count']} valid records</span></div>
            <div class="sc-check"><span class="sc-check-label">Validator quorum</span><span class="sc-check-value">{result['found_count']} matching</span></div>
            <div class="sc-check"><span class="sc-check-label">Ledger backend</span><span style="color:var(--sc-text);font-weight:700;">{backend}</span></div>
            <div class="sc-check"><span class="sc-check-label">TPM verifier evidence</span><span class="sc-check-value">{len(tpm_evidence)} receipts</span></div>
            {f'<div class="sc-check"><span class="sc-check-label">Person authentication</span><span class="sc-check-value">{len(person_auth_receipts)} receipt attestations</span></div>' if person_auth else ''}
        </div>""", unsafe_allow_html=True)
        st.markdown("""<div class="sc-side-card">
            <div class="sc-section-title">Evidence bundle</div>
            <div class="sc-evidence-copy">Download the page result, signed event, recipient signature, and validator proofs as JSON.</div>
        </div>""", unsafe_allow_html=True)
        st.download_button(
            "Download evidence bundle (JSON)",
            data=json.dumps(evidence, indent=2, sort_keys=True),
            file_name=f"sigilchain-evidence-{result['watermark_id'][:12]}.json",
            mime="application/json",
            key=f"evidence-download-{result['watermark_id']}-{page_label or 'image'}",
            use_container_width=True,
        )

    st.markdown("""<div class="sc-interpretation"><strong>Interpretation</strong><br>
        This links the recovered copy to a record signed by the registered recipient key. It does not independently prove
        that decryption occurred or identify who physically distributed the file. Identity depends on trusted enrollment and key custody.
        </div>""", unsafe_allow_html=True)
    if person_auth:
        st.caption(f"OIDC issuer subject {auth_subject} was validated and mapped to this recipient account. This is account-level attribution; shared or compromised credentials can weaken person-level attribution.")
    with st.expander(f"{prefix}Full signed record + proof"):
        st.json(evidence)


st.markdown("<div class='sc-upload-caption'>PDF, PNG, JPG, JPEG &nbsp;·&nbsp; Analysis starts after upload</div>",
            unsafe_allow_html=True)
uploaded = st.file_uploader("Leaked file", type=["png", "jpg", "jpeg", "pdf"], label_visibility="collapsed")

if uploaded is not None:
    if uploaded.type == "application/pdf" or uploaded.name.lower().endswith(".pdf"):
        pdf_bytes = uploaded.read()
        with st.spinner("Rasterizing PDF pages..."):
            pages = pdf_to_grayscale_images(pdf_bytes)
        st.markdown(f"""<div class="sc-file-row"><span class="sc-file-type">PDF</span>
            <span class="sc-file-name">{html.escape(uploaded.name)}</span>
            <span class="sc-file-meta">{len(pages)} page(s) found · checking each independently</span>
            </div>""", unsafe_allow_html=True)

        for i, page in enumerate(pages):
            st.markdown(f"### Page {i + 1} <span style='color:#9eacbc;font-size:.72em;font-weight:400'>of {len(pages)}</span>",
                        unsafe_allow_html=True)
            with st.spinner(f"Checking page {i + 1}..."):
                result = check_image(page)
            render_result(result, page_label=f"Page {i + 1}")

    else:
        image = Image.open(uploaded).convert("L")
        arr = np.array(image)
        st.markdown(f"""<div class="sc-file-row"><span class="sc-file-type">IMAGE</span>
            <span class="sc-file-name">{html.escape(uploaded.name)}</span>
            </div>""", unsafe_allow_html=True)

        col1, col2 = st.columns([1, 1])
        with col1:
            st.image(image, caption="Uploaded image", use_container_width=True)
        with col2:
            with st.spinner("Extracting and verifying..."):
                result = check_image(arr)
            render_result(result)
