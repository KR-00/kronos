"""
Module: oob_detection.py
------------------------
This module provides out-of-band (OOB) detection.
It checks for external indicators (e.g., DNS or HTTP callbacks).
Currently, this is a future implementation.
I Will probably delete it later
"""

import logging

logger = logging.getLogger("SQLiScanner")

def detect_oob_anomaly(response):
    if "oob_callback_triggered" in response.lower():
        report = {
            "category": "OOB",
            "label": "OOB:Detected",
            "matched_text": "OOB Callback Triggered",
            "severity": 5,
            "context": "Detected OOB interaction marker in response.",
            "pattern": "N/A"
        }
        logger.debug("OOB anomaly detected: %s", report)
        return report
    return None
