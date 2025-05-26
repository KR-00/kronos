# handles boolean-based detection — checks if content changed too much after injection

# NOT IMPLEMENTED YET !! 

from difflib import SequenceMatcher
import logging

logger = logging.getLogger("SQLiScanner")

def detect_boolean_anomaly(baseline_content, test_content, similarity_threshold=0.95):
    # compare the baseline response to the test response using string similarity
    similarity = SequenceMatcher(None, baseline_content, test_content).ratio()

    # if it's less similar than expected, flag it
    if similarity < similarity_threshold:
        report = {
            "category": "Boolean",  # type of detection
            "label": "Boolean:Anomaly",  # short label
            "matched_text": f"Similarity: {similarity:.2f}",  # what triggered the flag
            "severity": 3,  # mid-level severity
            "context": f"Baseline vs Test similarity is {similarity:.2f}",  # more details
            "pattern": "N/A"  # no specific pattern used
        }
        logger.debug("Boolean anomaly detected: %s", report)
        return report

    return None  # no issue found
