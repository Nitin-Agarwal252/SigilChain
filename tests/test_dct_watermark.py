"""
Round-trip robustness test for the DCT watermark core.

Simulates a rendered document page (not a blank image — flat white
regions behave very differently under JPEG than real page content), embeds
a real payload, and checks recovery after:
  1. Lossless PNG round-trip (sanity check, must be perfect)
  2. JPEG re-encoding at several quality levels (the actual claim:
     "survives screenshot + recompression by construction")

Run: python3 tests/test_dct_watermark.py
"""

import os
import sys
import cv2
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from watermark.dct_watermark import embed_bits, extract_bits, bit_error_rate, capacity
from watermark.payload import generate_watermark_id, bytes_to_bits, bits_to_bytes, WATERMARK_ID_SIZE


def make_synthetic_document(width=1275, height=1650) -> np.ndarray:
    """A grayscale image that behaves like a real rendered PDF page under
    JPEG compression: white background, black text lines, a header rule,
    and a bit of natural noise — not a flat blank canvas."""
    img = np.full((height, width), 255, dtype=np.uint8)

    cv2.putText(img, "PS 26237 -- MINISTRY OF DEFENCE (WESEE)", (80, 100),
                cv2.FONT_HERSHEY_SIMPLEX, 1.1, (0,), 2, cv2.LINE_AA)
    cv2.line(img, (80, 130), (width - 80, 130), (0,), 2)

    rng = np.random.default_rng(42)
    y = 220
    for line in range(28):
        x = 80
        line_len = rng.integers(15, 28)
        for _word in range(line_len):
            word_len = rng.integers(3, 9)
            cv2.putText(img, "x" * word_len, (x, y), cv2.FONT_HERSHEY_SIMPLEX,
                        0.55, (0,), 1, cv2.LINE_AA)
            x += word_len * 13 + 10
            if x > width - 150:
                break
        y += 42
        if y > height - 100:
            break

    # mild scanner-like sensor noise so the image isn't unnaturally clean
    noise = rng.normal(0, 2.5, img.shape)
    img = np.clip(img.astype(np.float64) + noise, 0, 255).astype(np.uint8)
    return img


def jpeg_round_trip(img: np.ndarray, quality: int) -> np.ndarray:
    ok, enc = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, quality])
    assert ok
    decoded = cv2.imdecode(enc, cv2.IMREAD_GRAYSCALE)
    return decoded


def png_round_trip(img: np.ndarray) -> np.ndarray:
    ok, enc = cv2.imencode(".png", img)
    assert ok
    decoded = cv2.imdecode(enc, cv2.IMREAD_GRAYSCALE)
    return decoded


def main():
    doc = make_synthetic_document()
    print(f"Synthetic document: {doc.shape[1]}x{doc.shape[0]} px, "
          f"{capacity(doc.shape)} available 8x8 blocks")

    # Build a real payload the same way Part 3/4 would.
    payload = generate_watermark_id()
    bits = bytes_to_bits(payload)
    print(f"Payload: {WATERMARK_ID_SIZE} bytes -> {len(bits)} bits (random watermark_id: {payload.hex()})")

    DELTA = 110.0
    REPEAT = 40
    needed_blocks = len(bits) * REPEAT
    print(f"Embedding with delta={DELTA}, repeat={REPEAT} "
          f"({needed_blocks} of {capacity(doc.shape)} blocks used)\n")

    watermarked = embed_bits(doc.astype(np.float64), bits, delta=DELTA, repeat=REPEAT)
    watermarked_u8 = np.clip(watermarked, 0, 255).astype(np.uint8)

    # visible-distortion sanity check
    mean_abs_diff = np.mean(np.abs(watermarked_u8.astype(np.int16) - doc.astype(np.int16)))
    print(f"Mean absolute pixel change from watermarking: {mean_abs_diff:.3f} / 255\n")

    results = []

    # 1. Lossless PNG round trip
    png_img = png_round_trip(watermarked_u8)
    extracted_bits = extract_bits(png_img.astype(np.float64), len(bits), repeat=REPEAT)
    ber = bit_error_rate(bits, extracted_bits)
    recovered_bytes = bits_to_bytes(extracted_bits)
    exact = recovered_bytes == payload
    results.append(("PNG (lossless)", ber, exact))

    # 2. JPEG at several quality levels
    for q in [95, 90, 85, 75, 60, 50, 40, 30, 20, 15]:
        jimg = jpeg_round_trip(watermarked_u8, q)
        extracted_bits = extract_bits(jimg.astype(np.float64), len(bits), repeat=REPEAT)
        ber = bit_error_rate(bits, extracted_bits)
        recovered_bytes = bits_to_bytes(extracted_bits)
        exact = recovered_bytes == payload
        results.append((f"JPEG q={q}", ber, exact))

    print(f"{'Condition':<18} {'Bit Error Rate':<16} {'Payload recovered exactly?'}")
    print("-" * 62)
    for name, ber, exact in results:
        status = "YES" if exact else "no"
        print(f"{name:<18} {ber*100:>6.2f}%          {status}")

    print()
    all_exact = all(r[2] for r in results)
    if all_exact:
        print("RESULT: payload recovered exactly at every tested compression level.")
    else:
        print("RESULT: payload recovery failed at one or more levels — tune delta/repeat.")

    # --- Partial-damage robustness: the actual real-world scenario the
    # page-wide spread assignment is for. This tests something specific:
    # given that the surviving region is still correctly aligned to its
    # original coordinates (i.e. the page itself wasn't shifted/cropped
    # before extraction — that alignment problem is what Part 7's
    # geometric correction solves separately), does losing a chunk of the
    # page (crease, glare, torn photo, partial obstruction) still leave
    # enough surviving blocks for majority voting to recover the payload?
    print("\n--- Partial-damage robustness (JPEG q=75 + a region blacked out) ---")
    jimg75 = jpeg_round_trip(watermarked_u8, 75)
    h, w = jimg75.shape
    damage_cases = [
        ("top 15% destroyed", (slice(0, int(h * 0.15)), slice(None))),
        ("bottom 15% destroyed", (slice(int(h * 0.85), h), slice(None))),
        ("left 20% destroyed", (slice(None), slice(0, int(w * 0.20)))),
        ("center 30% band destroyed", (slice(int(h * 0.35), int(h * 0.65)), slice(None))),
    ]
    for name, region in damage_cases:
        damaged = jimg75.copy()
        damaged[region] = 0
        extracted_bits = extract_bits(damaged.astype(np.float64), len(bits), repeat=REPEAT)
        ber = bit_error_rate(bits, extracted_bits)
        exact = bits_to_bytes(extracted_bits) == payload
        print(f"  {name:<28} BER={ber*100:5.2f}%  exact={'YES' if exact else 'no'}")

    # Save visual comparison for an eyeball check that the mark is actually invisible
    cv2.imwrite("/tmp/doc_original.png", doc)
    cv2.imwrite("/tmp/doc_watermarked.png", watermarked_u8)
    diff = np.abs(watermarked_u8.astype(np.int16) - doc.astype(np.int16)).astype(np.uint8)
    diff_amplified = np.clip(diff.astype(np.int16) * 20, 0, 255).astype(np.uint8)
    cv2.imwrite("/tmp/doc_diff_amplified_20x.png", diff_amplified)
    print("\nSaved /tmp/doc_original.png, /tmp/doc_watermarked.png, "
          "/tmp/doc_diff_amplified_20x.png for visual inspection")


if __name__ == "__main__":
    main()
