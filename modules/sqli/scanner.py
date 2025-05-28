import os
import time
import logging
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import WebDriverException

# import modules that do each part of the scan
from .config import load_configuration
from .payload_manager import load_payloads
from .baseline import get_fresh_baseline, normalize
from .injection import advanced_inject_payload
from .detection import detection_manager
from .timing_analysis import measure_response_time
from .utils import wait_for_page, close_popups, ProgressTracker

logger = logging.getLogger("SQLiScanner")

def launch_new_browser(headless=True):
    # starts a new Chrome browser instance
    options = webdriver.ChromeOptions()
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--window-size=1200,800")
    if headless:
        options.add_argument("--headless")  # run without showing the browser
    return webdriver.Chrome(options=options)

def safe_get(driver, url, max_retries=3):
    # tries to load a page up to 3 times; stops if it can't
    for attempt in range(max_retries):
        try:
            driver.get(url)
            return True
        except WebDriverException as e:
            logger.warning(f"[Attempt {attempt+1}] Failed to load page: {e.msg}")
            time.sleep(2)
    logger.error("Failed to access target URL after multiple attempts. Halting scan.")
    return False

def check_sql_injection(
    url,
    payload_dir,
    categories_to_test=None,      # either a category or...
    custom_payload_file=None,     # ...a custom .txt file (not both)
    stop_event=None,              # allows stopping mid-scan from the GUI
    progress_callback=None,       # used to update progress bar in GUI
    credentials_override=None,    # for future login support
    anomaly_callback=None,        # called when a payload triggers something
    headless=True                 # run Chrome headless 
):
    config = load_configuration()
    logger.info("User provided main target: %s", url)
    logger.info("No authentication configured; proceeding without login.")

    try:
        driver = launch_new_browser(headless=headless)
        wait = WebDriverWait(driver, 15)

        if not safe_get(driver, url):
            driver.quit()
            return

        wait_for_page(driver, wait)
        close_popups(driver, wait)

        # get_baseline handles a test injection to collect reference content
        baseline_text, avg_length, avg_time, baseline_url, page_title, dom_signature, fingerprint, status_code = get_fresh_baseline(
            driver, wait, url, advanced_inject_payload, stop_event
        )
        norm_baseline = normalize(baseline_text)

        selected_category = categories_to_test[0] if categories_to_test else None

        payloads = load_payloads(
            payload_dir=payload_dir,
            custom_file=custom_payload_file,
            selected_category=selected_category
        )

        total_payloads = sum(len(lst) for lst in payloads.values())

        if not custom_payload_file:
            # log source of the loaded payloads
            source_label = list(payloads.keys())[0] if payloads else "unknown"
            logger.info("[+] Loaded %d payloads from: %s", total_payloads, source_label)

        if total_payloads == 0:
            # bail early if there's nothing to test
            logger.warning("No payloads found to test. Aborting scan.")
            driver.quit()
            return

        progress_tracker = ProgressTracker(total_payloads)
        anomalies = []  # collect all anomaly reports
        injection_count = 0
        logged_payloads = set()  # used to avoid duplicate GUI alerts

        for category, payload_list in payloads.items():
            for payload in payload_list:
                if stop_event and stop_event.is_set():
                    logger.info("Stop event triggered. Halting scan.")
                    driver.quit()
                    return

                injection_count += 1
                progress_tracker.update(1)

                # reset the session before each test
                driver.delete_all_cookies()
                if not safe_get(driver, url):
                    driver.quit()
                    return

                wait_for_page(driver, wait)
                close_popups(driver, wait)

                logger.debug("Testing payload: %s", payload)
                logger.debug("Current URL after reload: %s", driver.current_url)

                # run the injection and time how long it takes
                response, elapsed_time = measure_response_time(advanced_inject_payload, driver, payload, wait)
                current_url = driver.current_url
                norm_response = normalize(response)

                # analyze the result using all detection modules
                reports = detection_manager.run_all_detections(
                    response,
                    norm_baseline,
                    avg_time,
                    elapsed_time,
                    current_url,
                    baseline_url,
                    use_fuzzy=False
                )

                if reports:
                    # attach metadata and report each anomaly
                    for report in reports:
                        report["payload"] = payload
                        report["elapsed_time"] = elapsed_time
                        anomalies.append(report)

                        # call the GUI's anomaly handler if one is set
                        if anomaly_callback and payload not in logged_payloads:
                            anomaly_callback(report)
                            logged_payloads.add(payload)

                    # if behavior anomaly was found, restart browser for clean state
                    if any(r["category"] == "Behavior" for r in reports):
                        logger.warning("Behavior anomaly detected — restarting browser for clean state.")
                        driver.quit()
                        time.sleep(0.2)
                        driver = launch_new_browser(headless=headless)
                        wait = WebDriverWait(driver, 10)
                        if not safe_get(driver, url):
                            driver.quit()
                            return
                        wait_for_page(driver, wait)
                        close_popups(driver, wait)

                # update progress bar (if GUI passed a callback)
                if progress_callback:
                    progress_callback(
                        progress_tracker.percentage(),
                        progress_tracker.remaining_time(),
                        progress_tracker.progress_string()
                    )

    except WebDriverException:
        logger.error("[!] Scan stopped: browser was closed or became unresponsive.")
    except Exception as e:
        logger.error(f"[!] Scan stopped due to an unexpected error: {str(e)}")
    finally:
        try:
            driver.quit()
        except:
            pass
        logger.info("Scanner shut down.")
