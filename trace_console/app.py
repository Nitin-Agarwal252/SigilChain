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
from agent.quorum_client import check_watermark, verify_chain_proof

NODE_URLS = config.NODE_URLS

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
    evidence = {
        "evidence_type": "SigilChain decryption-session attribution",
        "claim_limit": "The recovered watermark links this copy to a signed decryption-session record. It does not by itself prove who physically distributed the leaked copy. The event timestamp comes from the recipient device and is not an independently trusted time source.",
        "extracted_watermark_id": result["watermark_id"],
        "required_quorum": config.QUORUM_REQUIRED,
        "ledger_backend": result["validator_evidence"][0].get("ledger_backend", "unknown"),
        "consensus_limit": "etcd Raft provides crash-fault majority consensus; it is not Byzantine fault tolerant. Validator receipts attest each node observed this ordered log entry.",
        "submitted_page_sha256": result["submitted_page_sha256"],
        "recovery_agreement": result["confidence"],
        "extraction_source": result["extraction_source"],
        "record": record,
        "signature_hex": result["signature_hex"],
        "canonical_record_bytes_hex": result["record_bytes_hex"],
        "validator_evidence": result["validator_evidence"],
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
            </div>
        </div>""", unsafe_allow_html=True)
    with checks_col:
        st.markdown(f"""<div class="sc-side-card">
            <div class="sc-section-title">What was verified</div>
            <div class="sc-check"><span class="sc-check-label">Recipient event signature</span><span class="sc-check-value">Verified</span></div>
            <div class="sc-check"><span class="sc-check-label">Hash-chain proofs</span><span class="sc-check-value">{result['found_count']} valid records</span></div>
            <div class="sc-check"><span class="sc-check-label">Validator quorum</span><span class="sc-check-value">{result['found_count']} matching</span></div>
            <div class="sc-check"><span class="sc-check-label">Ledger backend</span><span style="color:var(--sc-text);font-weight:700;">{backend}</span></div>
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
