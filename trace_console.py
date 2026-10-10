"""Streamlit UI for page-by-page watermark tracing and evidence download."""
from __future__ import annotations

import json

import streamlit as st

from sigilchain.trace import image_pages, trace_page

st.set_page_config(page_title="SigilChain Trace", page_icon="◈", layout="centered")
st.title("SigilChain Trace Console")
st.caption("Recover a session watermark and check its signed evidence against pinned validators.")
st.markdown("A match links this copy to a key-signed decryption-session record. It does not prove who physically distributed a leak or provide a trusted timestamp.")
photo_capture = st.checkbox(
    "Try experimental camera-photo correction",
    help="Use only for a photograph of a page or screen. It tries page-boundary detection, perspective correction, and fine alignment; glare, heavy cropping, and strong angles can still defeat recovery.",
)
upload = st.file_uploader("Leaked document or page image", type=["pdf", "png", "jpg", "jpeg", "bmp", "tif", "tiff", "webp"])
if upload:
    try:
        pages = image_pages(upload.getvalue(), upload.name)
        st.write(f"Checking {len(pages)} page(s) independently…")
        for index, page in enumerate(pages, start=1):
            with st.expander(f"Page {index}", expanded=True):
                result = trace_page(page, photo_capture=photo_capture)
                if result["status"] == "verified":
                    st.success("Verified session match")
                    st.code(result["watermark_id"])
                    st.write(f"Carrier agreement: {result['confidence']:.1%}")
                    st.write(f"Recovery path: {result.get('recovery_path', 'original image')}")
                    data = json.dumps(result["bundle"], indent=2).encode()
                    st.download_button("Download JSON evidence", data,
                        file_name=f"sigilchain-evidence-{result['watermark_id'][:12]}.json",
                        mime="application/json", key=f"evidence-{index}")
                elif result["status"] == "inconclusive":
                    confidence = result.get("confidence")
                    detail = f" ({confidence:.1%} agreement)" if confidence is not None else ""
                    st.warning(f"{result.get('reason', 'Watermark recovery was inconclusive.')}{detail} Do not attribute this copy.")
                else:
                    st.error(result.get("reason", result.get("error", "No verifiable session found.")))
    except Exception as exc:
        st.error(f"Could not read upload: {exc}")
