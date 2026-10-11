"""
SigilChain — Part 7: Geometric Correction (photo-capture stretch goal).

A screenshot is pixel-aligned with the original page -- the DCT watermark
core (Part 3) reads it directly. A PHOTOGRAPH of a screen or printed page
is not: camera angle introduces perspective distortion, so the same 8x8
block grid no longer lines up with where the watermark was embedded.
This module detects the document's rectangular boundary in a photo and
warps it back to a flat, aligned view -- after which the normal
extraction in dct_watermark.py works unchanged.

This remains an experimental stretch case. Screenshot/recompression
recovery has only been measured on specified synthetic inputs; this
corrects for the *additional* problem a photo introduces, under
reasonable conditions (decent lighting, the page
mostly filling the frame, close to head-on angle). It does not attempt
to handle extreme angles, heavy glare, or a partially-visible page.
"""

import cv2
import numpy as np


def find_document_corners(bgr_or_gray: np.ndarray) -> np.ndarray | None:
    """
    Find the 4 corners of the largest roughly-rectangular, high-contrast
    region in the image -- the document page against its background.
    Returns a (4, 2) array of subpixel-refined (x, y) points in no
    particular order, or None if no confident quadrilateral was found.
    """
    if bgr_or_gray.ndim == 3:
        gray = cv2.cvtColor(bgr_or_gray, cv2.COLOR_BGR2GRAY)
    else:
        gray = bgr_or_gray

    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    edges = cv2.Canny(blurred, 50, 150)
    edges = cv2.dilate(edges, np.ones((5, 5), np.uint8), iterations=2)

    contours, _ = cv2.findContours(edges, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)
    if not contours:
        return None

    image_area = gray.shape[0] * gray.shape[1]
    best_quad = None
    best_area = 0

    for contour in contours:
        area = cv2.contourArea(contour)
        # the page should be a large fraction of the frame -- ignore tiny noise contours
        if area < 0.15 * image_area:
            continue
        perimeter = cv2.arcLength(contour, True)
        approx = cv2.approxPolyDP(contour, 0.02 * perimeter, True)
        if len(approx) == 4 and area > best_area:
            best_area = area
            best_quad = approx.reshape(4, 2)

    if best_quad is None:
        return None
    # Polygon approximation is adequate for finding the page but its few
    # pixel corner error shifts the DCT block grid. Refine against the
    # local image gradients before constructing the homography.
    refined = best_quad.astype(np.float32).reshape(4, 1, 2)
    criteria = (cv2.TERM_CRITERIA_EPS + cv2.TERM_CRITERIA_MAX_ITER, 80, 0.001)
    try:
        cv2.cornerSubPix(np.ascontiguousarray(gray), refined, (9, 9), (-1, -1), criteria)
    except cv2.error:
        return best_quad
    if not np.isfinite(refined).all():
        return best_quad
    return refined.reshape(4, 2)


def _order_corners(pts: np.ndarray) -> np.ndarray:
    """Order 4 points as top-left, top-right, bottom-right, bottom-left --
    required for a correct (not mirrored/rotated) perspective warp."""
    rect = np.zeros((4, 2), dtype=np.float32)
    s = pts.sum(axis=1)
    rect[0] = pts[np.argmin(s)]       # top-left: smallest x+y
    rect[2] = pts[np.argmax(s)]       # bottom-right: largest x+y
    diff = np.diff(pts, axis=1).flatten()
    rect[1] = pts[np.argmin(diff)]    # top-right: smallest y-x
    rect[3] = pts[np.argmax(diff)]    # bottom-left: largest y-x
    return rect


def correct_perspective(image: np.ndarray, corners: np.ndarray,
                         output_size: tuple[int, int] | None = None) -> np.ndarray:
    """
    Warp `image` so the quadrilateral `corners` becomes a flat rectangle.
    output_size, if given, is (width, height) of the result; otherwise
    it's estimated from the corner distances.
    """
    rect = _order_corners(corners.astype(np.float32))
    (tl, tr, br, bl) = rect

    width_a = np.linalg.norm(br - bl)
    width_b = np.linalg.norm(tr - tl)
    max_width = int(max(width_a, width_b))

    height_a = np.linalg.norm(tr - br)
    height_b = np.linalg.norm(tl - bl)
    max_height = int(max(height_a, height_b))

    if output_size is not None:
        max_width, max_height = output_size

    dst = np.array([
        [0, 0],
        [max_width - 1, 0],
        [max_width - 1, max_height - 1],
        [0, max_height - 1],
    ], dtype=np.float32)

    matrix = cv2.getPerspectiveTransform(rect, dst)
    warped = cv2.warpPerspective(image, matrix, (max_width, max_height))
    return warped


def auto_correct(image: np.ndarray, output_size: tuple[int, int] | None = None) -> np.ndarray | None:
    """
    One-call convenience: find the document, warp it flat, return the
    corrected image. Returns None if no document boundary was confidently
    found (caller should fall back to trying extraction on the raw image,
    or ask the user for a clearer photo).
    """
    corners = find_document_corners(image)
    if corners is None:
        return None
    return correct_perspective(image, corners, output_size=output_size)


def fine_align(corrected: np.ndarray, num_bits: int, repeat: int, search_range: int = 6) -> tuple[np.ndarray, float]:
    """
    The corner detection that feeds correct_perspective() is accurate to
    within a handful of pixels, not sub-pixel -- and DCT block-grid
    watermarking has no tolerance for that: a 3-4 pixel corner error can
    shift every 8x8 block's contents enough to scramble the embedded
    data entirely, even though the perspective warp itself is correct
    (verified separately: 0% error when given exact corners).

    This searches small pixel shifts around the refined coarse correction and
    picks whichever one gives the highest-CONFIDENCE extraction -- using
    extract_bits_with_confidence's agreement score, not the (unknown, at
    this point) ground truth. This is the standard fix for this class of
    problem (watermark "synchronization"), not a full solution to
    photo-capture robustness by itself.

    Returns (best_shifted_image, confidence). Caller should treat a low
    returned confidence as "extraction result not trustworthy."
    """
    import config
    if config.WATERMARK_TRANSFORM == "dwt-dct":
        from watermark.dwt_dct_watermark import extract_bits_with_confidence
    else:
        from watermark.dct_watermark import extract_bits_with_confidence

    h, w = corrected.shape
    best_img = corrected
    best_conf = -1.0

    for dy in range(-search_range, search_range + 1, 2):
        for dx in range(-search_range, search_range + 1, 2):
            shifted = np.roll(corrected, shift=(dy, dx), axis=(0, 1))
            _, conf = extract_bits_with_confidence(shifted.astype(np.float64), num_bits, repeat)
            if conf > best_conf:
                best_conf = conf
                best_img = shifted

    return best_img, best_conf
