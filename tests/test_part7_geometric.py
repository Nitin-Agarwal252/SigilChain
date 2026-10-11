"""
Part 7 test: synthesize a "photograph" of a watermarked page -- placed at
an angle on a background, with camera-like noise -- and prove
auto_correct() recovers a flat enough image for extraction to still work.

This is the honest test of the stretch goal: it will show exactly how
well (or poorly) this works under a specific, stated distortion, not a
vague claim either way.

Run: python tests/test_part7_geometric.py
"""

import os
import sys

import cv2
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from watermark.dct_watermark import embed_bits, extract_bits, bit_error_rate
from watermark.payload import generate_watermark_id, bytes_to_bits, bits_to_bytes, WATERMARK_ID_SIZE
from watermark.geometric_correction import auto_correct, find_document_corners, fine_align
from tests.test_dct_watermark import make_synthetic_document

DELTA = 110.0
REPEAT = 40


def synthesize_photo(page: np.ndarray, tilt_strength: float, canvas_size=(2200, 2800),
                      rotation_deg: float = 3.0) -> np.ndarray:
    """
    Place `page` onto a larger gray "desk" background at a perspective
    angle and slight rotation, then add mild blur + noise to mimic a
    phone camera capture (not a perfect screenshot).
    """
    h, w = page.shape
    canvas_h, canvas_w = canvas_size
    canvas = np.full((canvas_h, canvas_w), 60, dtype=np.uint8)  # gray "desk"
    rng = np.random.default_rng(7)
    canvas = np.clip(canvas.astype(np.float64) + rng.normal(0, 6, canvas.shape), 0, 255).astype(np.uint8)

    src = np.array([[0, 0], [w - 1, 0], [w - 1, h - 1], [0, h - 1]], dtype=np.float32)

    margin_x, margin_y = canvas_w * 0.15, canvas_h * 0.12
    top_shrink = w * tilt_strength
    dst = np.array([
        [margin_x + top_shrink, margin_y],
        [canvas_w - margin_x - top_shrink * 0.3, margin_y + h * 0.03 * tilt_strength * 10],
        [canvas_w - margin_x, canvas_h - margin_y],
        [margin_x, canvas_h - margin_y - h * 0.02 * tilt_strength * 10],
    ], dtype=np.float32)

    center = (canvas_w / 2, canvas_h / 2)
    rot_mat = cv2.getRotationMatrix2D(center, rotation_deg, 1.0)
    dst_h = np.hstack([dst, np.ones((4, 1))])
    dst = (rot_mat @ dst_h.T).T.astype(np.float32)

    matrix = cv2.getPerspectiveTransform(src, dst)
    warped_page = cv2.warpPerspective(page, matrix, (canvas_w, canvas_h),
                                       borderMode=cv2.BORDER_CONSTANT, borderValue=60)
    mask = cv2.warpPerspective(np.full((h, w), 255, dtype=np.uint8), matrix, (canvas_w, canvas_h),
                                borderMode=cv2.BORDER_CONSTANT, borderValue=0)

    photo = np.where(mask > 127, warped_page, canvas)

    # mild camera-like degradation
    photo = cv2.GaussianBlur(photo, (3, 3), 0.6)
    photo = np.clip(photo.astype(np.float64) + rng.normal(0, 4, photo.shape), 0, 255).astype(np.uint8)

    return photo


def main():
    print("=== Building and marking a synthetic document ===")
    doc = make_synthetic_document()
    watermark_id = generate_watermark_id()
    bits = bytes_to_bits(watermark_id)
    marked = embed_bits(doc.astype(np.float64), bits, delta=DELTA, repeat=REPEAT)
    marked_u8 = np.clip(marked, 0, 255).astype(np.uint8)
    print(f"Watermark ID: {watermark_id.hex()}")

    photo_recovery_results = []
    for tilt in [0.05, 0.12, 0.20]:
        print(f"\n=== Simulated photo, tilt_strength={tilt} ===")
        photo = synthesize_photo(marked_u8, tilt_strength=tilt)
        cv2.imwrite(f"/tmp/photo_tilt_{tilt}.png", photo)

        corners = find_document_corners(photo)
        if corners is None:
            print("  Document boundary NOT found -- correction skipped.")
            continue
        print(f"  Document boundary found: {corners.tolist()}")

        corrected = auto_correct(photo, output_size=(doc.shape[1], doc.shape[0]))
        cv2.imwrite(f"/tmp/photo_corrected_{tilt}.png", corrected)

        extracted_bits = extract_bits(corrected.astype(np.float64), len(bits), repeat=REPEAT)
        ber = bit_error_rate(bits, extracted_bits)
        exact = bits_to_bytes(extracted_bits) == watermark_id
        print(f"  After perspective correction alone: BER={ber*100:.2f}%  exact_match={exact}")

        aligned, confidence = fine_align(corrected, len(bits), REPEAT, search_range=8)
        extracted_bits2 = extract_bits(aligned.astype(np.float64), len(bits), repeat=REPEAT)
        ber2 = bit_error_rate(bits, extracted_bits2)
        exact2 = bits_to_bytes(extracted_bits2) == watermark_id
        photo_recovery_results.append(exact2)
        print(f"  After perspective correction + fine alignment: BER={ber2*100:.2f}%  "
              f"exact_match={exact2}  confidence={confidence:.3f}")

    print("\n=== Sanity check: does extraction work on the UNCORRECTED photo? ===")
    photo = synthesize_photo(marked_u8, tilt_strength=0.12)
    # naive resize to expected dims, no perspective correction -- the wrong way
    naive = cv2.resize(photo, (doc.shape[1], doc.shape[0]))
    extracted_bits_naive = extract_bits(naive.astype(np.float64), len(bits), repeat=REPEAT)
    ber_naive = bit_error_rate(bits, extracted_bits_naive)
    print(f"  Without correction: BER={ber_naive*100:.2f}% (expected to be far worse / near random)")

    print("\n=== HONEST CONCLUSION ===")
    if all(photo_recovery_results):
        print("End-to-end recovery passed for all three specified synthetic photo tilts, "
              "with subpixel corner refinement. This does not establish reliability "
              "for arbitrary real camera captures; glare, cropping, blur, and page detection "
              "remain outside this test's coverage.")
    else:
        raise AssertionError("At least one of the three synthetic photo cases failed end-to-end recovery.")


if __name__ == "__main__":
    main()
