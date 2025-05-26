import logging
from . import behavior_detection, error_detection
from ..config import load_configuration

logger = logging.getLogger("SQLiScanner")

def run_all_detections(response, baseline_response, baseline_time, test_time,
                       current_url, baseline_url, use_fuzzy=False):
    # this is the main detection hub — it runs all enabled detection checks
    # returns a list of anomaly reports if anything gets flagged

    config = load_configuration()
    thresholds = config.get("thresholds", {})  # get similarity and length thresholds

    reports = []

    # 1. Run behavior-based detection (checks for changes in URL, content, etc.)
    behavior_report = behavior_detection.detect_behavior_anomaly(
        current_url=current_url,
        baseline_url=baseline_url,
        baseline_response=baseline_response,
        response=response,
        thresholds=thresholds
    )
    if behavior_report:
        reports.append(behavior_report)

    # 2. Run error keyword detection (looks for things like "SQL syntax" in response)
    error_reports = error_detection.detect_error_keywords(response, use_fuzzy=use_fuzzy)
    if error_reports:
        reports.extend(error_reports)

    # 3. Run GUI content leak detection (checks if any sensitive content appeared)
    gui_reports = error_detection.detect_gui_content_leaks(
        baseline_html=baseline_response,
        payload_html=response
    )
    if gui_reports:
        reports.extend(gui_reports)

    logger.debug("Detection reports: %s", reports)  # log what was found
    return reports

