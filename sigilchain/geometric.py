"""Experimental perspective and block-grid correction for camera captures.

This is an optional recovery aid for photographs of a page or screen. It is
not required for PDFs or screenshots and does not guarantee recovery from
glare, severe perspective, cropping, or low resolution.
"""
from __future__ import annotations

import cv2
import numpy as np

from . import config
from .watermark import ID_BYTES, RS_PARITY, extract_page


def find_document_corners(image: np.ndarray) -> np.ndarray | None:
    """Return corners of the largest page-like quadrilateral, if found."""
    if image.ndim == 3:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    elif image.ndim == 2:
        gray = image
    else:
        return None
    gray = np.ascontiguousarray(gray, dtype=np.uint8)
    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    edges = cv2.Canny(blurred, 50, 150)
    edges = cv2.dilate(edges, np.ones((5, 5), np.uint8), iterations=2)
    contours, _ = cv2.findContours(edges, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)
    image_area = gray.shape[0] * gray.shape[1]
    best, best_area = None, 0.0
    for contour in contours:
        area = cv2.contourArea(contour)
        if area < 0.15 * image_area:
            continue
        polygon = cv2.approxPolyDP(contour, 0.02 * cv2.arcLength(contour, True), True)
        if len(polygon) == 4 and area > best_area:
            best, best_area = polygon.reshape(4, 2), area
    if best is None:
        return None
    refined = best.astype(np.float32).reshape(4, 1, 2)
    criteria = (cv2.TERM_CRITERIA_EPS + cv2.TERM_CRITERIA_MAX_ITER, 80, 0.001)
    try:
        cv2.cornerSubPix(gray, refined, (9, 9), (-1, -1), criteria)
    except cv2.error:
        return best.astype(np.float32)
    return refined.reshape(4, 2) if np.isfinite(refined).all() else best.astype(np.float32)


def _order_corners(points: np.ndarray) -> np.ndarray:
    ordered = np.zeros((4, 2), dtype=np.float32)
    sums = points.sum(axis=1)
    ordered[0] = points[np.argmin(sums)]
    ordered[2] = points[np.argmax(sums)]
    differences = np.diff(points, axis=1).flatten()
    ordered[1] = points[np.argmin(differences)]
    ordered[3] = points[np.argmax(differences)]
    return ordered


def correct_perspective(image: np.ndarray, corners: np.ndarray) -> np.ndarray:
    """Flatten a detected quadrilateral and return a grayscale page image."""
    tl, tr, br, bl = _order_corners(corners.astype(np.float32))
    width = max(2, int(max(np.linalg.norm(br - bl), np.linalg.norm(tr - tl))))
    height = max(2, int(max(np.linalg.norm(tr - br), np.linalg.norm(tl - bl))))
    destination = np.array([[0, 0], [width - 1, 0], [width - 1, height - 1],
                            [0, height - 1]], dtype=np.float32)
    matrix = cv2.getPerspectiveTransform(np.array([tl, tr, br, bl], dtype=np.float32), destination)
    corrected = cv2.warpPerspective(image, matrix, (width, height))
    return cv2.cvtColor(corrected, cv2.COLOR_BGR2GRAY) if corrected.ndim == 3 else corrected


def _extract_confidence(image: np.ndarray, bit_count: int) -> float:
    target = image
    if config.WATERMARK_TRANSFORM == "dwt-dct":
        target, _ = _haar_ll(image)
    _, confidence = _extract(target, bit_count, config.EMBED_REPEAT)
    return confidence


def _haar_ll(gray: np.ndarray) -> tuple[np.ndarray, tuple[int, int]]:
    height, width = gray.shape
    padded = np.pad(gray.astype(np.float64), ((0, height % 2), (0, width % 2)), mode="edge")
    a, b = padded[0::2, 0::2], padded[0::2, 1::2]
    c, d = padded[1::2, 0::2], padded[1::2, 1::2]
    return (a + b + c + d) / 4.0, (height, width)


def _extract(gray: np.ndarray, bit_count: int, repeat: int) -> tuple[list[int], float]:
    # Keep alignment scoring identical to the regular DCT/DWT-DCT decoder.
    from .watermark import _extract as extract_carriers
    return extract_carriers(gray, bit_count, repeat)


def fine_align(image: np.ndarray, search_range: int = 6) -> tuple[np.ndarray, float]:
    """Search small pixel offsets and retain the one with best carrier agreement."""
    bit_count = (ID_BYTES + RS_PARITY) * 8
    best, best_confidence = image, -1.0
    for dy in range(-search_range, search_range + 1, 2):
        for dx in range(-search_range, search_range + 1, 2):
            shifted = np.roll(image, shift=(dy, dx), axis=(0, 1))
            confidence = _extract_confidence(shifted, bit_count)
            if confidence > best_confidence:
                best, best_confidence = shifted, confidence
    return best, best_confidence


def correct_photo(image: np.ndarray) -> tuple[np.ndarray, float] | None:
    """Detect, flatten, and align a photographed page; None means no page found."""
    corners = find_document_corners(image)
    if corners is None:
        return None
    corrected = correct_perspective(image, corners)
    return fine_align(corrected)
