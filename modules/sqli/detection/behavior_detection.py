# detects strange behavior after injecting payloads
# if the page acts differently compared to the baseline, we flag it

# although i run thousands of tests on it , it still needs refinement
# It works idealy on the tests i run , but it cant be certain based on the website's response. 

#IMPORTANT : The severity is inserted for later use in report creation or exporting details

import logging
import difflib
from urllib.parse import urlparse

logger = logging.getLogger("SQLiScanner")

# fallback threshold values in case none are provided from config
DEFAULT_SIMILARITY_THRESHOLD = 0.75
DEFAULT_LENGTH_DIFF_THRESHOLD = 0.20

def urls_are_similar(url1, url2):
    # compares URLs but ignores query parameters and fragments
    # It cares more about page paths than things like ?id=123
    parsed1 = urlparse(url1)
    parsed2 = urlparse(url2)

    return (parsed1.scheme, parsed1.netloc, parsed1.path) == (parsed2.scheme, parsed2.netloc, parsed2.path)

def detect_behavior_anomaly(current_url, baseline_url, baseline_response, response,
                              baseline_keywords=None, response_keywords=None, thresholds=None):
    # this is the main function that checks if something strange happened after injecting a payload
    # it compares the response to the baseline in multiple ways

    # use config thresholds if available, else fall back to built-in ones
    if thresholds is None:
        similarity_threshold = DEFAULT_SIMILARITY_THRESHOLD
        length_diff_threshold = DEFAULT_LENGTH_DIFF_THRESHOLD
    else:
        similarity_threshold = thresholds.get('similarity_threshold', DEFAULT_SIMILARITY_THRESHOLD)
        length_diff_threshold = thresholds.get('length_diff_threshold', DEFAULT_LENGTH_DIFF_THRESHOLD)
    
    anomalies = []  # collect reasons we might flag this response
    context = {}    # store extra data that helps explain why

    # 1. Check if the URL changed (but ignore query strings)
    if not urls_are_similar(current_url, baseline_url):
        anomalies.append("URL changed")
        context["url_change"] = f"URL changed from {baseline_url} to {current_url}"

    # 2. Check how similar the page content is to the baseline
    similarity = difflib.SequenceMatcher(None, baseline_response, response).ratio()
    if similarity < similarity_threshold:
        anomalies.append("Content mismatch")
        context["content_similarity"] = similarity

    # 3. Check if the page length changed a lot
    baseline_length = len(baseline_response)
    response_length = len(response)
    length_diff = abs(response_length - baseline_length) / baseline_length if baseline_length > 0 else 0
    if length_diff > length_diff_threshold:
        anomalies.append("Significant length difference")
        context["length_difference"] = length_diff

    # 4. See if any new error keywords showed up (e.g., "SQL", "syntax", "warning")
    if baseline_keywords is not None and response_keywords is not None:
        new_keywords = set(response_keywords) - set(baseline_keywords)
        if new_keywords:
            anomalies.append("New error keywords detected")
            context["new_error_keywords"] = list(new_keywords)

    # if anything was flagged, return a report
    if anomalies:
        report = {
            "category": "Behavior",
            "label": "Behavior:Anomaly",
            "matched_text": "; ".join(anomalies),
            "severity": 5,
            "context": context,
            "pattern": "Multi-metric anomaly detection"
        }
        logger.debug("Behavior anomaly detected: %s", report)
        return report

    return None  # nothing weird found
