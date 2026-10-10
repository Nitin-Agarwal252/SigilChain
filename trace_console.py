"""Streamlit UI for page-by-page watermark tracing and evidence download."""
from __future__ import annotations

import json

import streamlit as st

from sigilchain.trace import image_pages, trace_page

st.set_page_config(page_title="SigilChain Trace", page_icon="◈", layout="centered")
st.title("SigilChain Trace Console")
st.caption("Recover a session watermark and check its signed evidence against pinned validators.")
st.markdown("A match links this copy to a key-signed decryption-session record. It does not prove who physically distributed a leak or provide a trusted timestamp.")
upload = st.file_uploader("Leaked document or page image", type=["pdf", "png", "jpg", "jpeg", "bmp", "tif", "tiff", "webp"])
if upload:
    try:
        pages = image_pages(upload.getvalue(), upload.name)
        st.write(f"Checking {len(pages)} page(s) independently…")
        for index, page in enumerate(pages, start=1):
            with st.expander(f"Page {index}", expanded=True):
                result = trace_page(page)
                if result["status"] == "verified":
                    st.success("Verified session match")
                    st.code(result["watermark_id"])
                    st.write(f"Carrier agreement: {result['confidence']:.1%}")
                    data = json.dumps(result["bundle"], indent=2).encode()
                    st.download_button("Download JSON evidence", data,
                        file_name=f"sigilchain-evidence-{result['watermark_id'][:12]}.json",
                        mime="application/json", key=f"evidence-{index}")
                elif result["status"] == "inconclusive":
                    st.warning(f"Watermark recovery was inconclusive ({result['confidence']:.1%} agreement). Do not attribute this copy.")
                else:
                    st.error(result.get("reason", result.get("error", "No verifiable session found.")))
    except Exception as exc:
        st.error(f"Could not read upload: {exc}")
