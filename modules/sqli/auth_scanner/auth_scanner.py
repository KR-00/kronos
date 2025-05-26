import os
import time
import logging

from modules.sqli.config import load_configuration
from modules.sqli.payload_manager import load_payloads
from modules.sqli.auth_scanner.auth_baseline import get_auth_baseline_response
from modules.sqli.injection import advanced_inject_payload
from modules.sqli.detection import detection_manager
from modules.sqli.utils import ProgressTracker
from modules.sqli.auth_scanner.auth_session import AuthSession
from modules.sqli.baseline import normalize
from modules.sqli.timing_analysis import measure_response_time

from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait

def launch_new_browser(headless):
    options = webdriver.ChromeOptions()
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--window-size=1200,800")
    if headless:
        options.add_argument("--headless")
    return webdriver.Chrome(options=options)

class AuthScanner:
    def __init__(self, target_url, payload_dir, categories_to_test,
                 credentials, custom_payloads=None, stop_event=None,
                 progress_callback=None, anomaly_callback=None,
                 headless_mode=False):
        self.target_url = target_url
        self.payload_dir = payload_dir
        self.categories_to_test = categories_to_test
        self.credentials = credentials
        self.custom_payloads = custom_payloads
        self.stop_event = stop_event
        self.progress_callback = progress_callback
        self.anomaly_callback = anomaly_callback
        self.auth_session = None
        self.login_url = None
        self.headless_mode = headless_mode

    def start(self):
        logger = logging.getLogger("SQLiScanner")
        config = load_configuration()

        driver = launch_new_browser(self.headless_mode)
        wait = WebDriverWait(driver, 10)

        try:
            self.auth_session = AuthSession(
                self.target_url,
                self.credentials.get("credential1"),
                self.credentials.get("credential2"),
                driver=driver,
                wait=wait
            )

            if not self.auth_session.find_login_page():
                logger.warning("[-] No login page detected. Stopping authenticated scan.")
                driver.quit()
                return

            if not self.auth_session.perform_login():
                logger.warning("[-] Login failed. Stopping authenticated scan.")
                driver.quit()
                return

            session = self.auth_session.get_session()
            self.login_url = self.auth_session.login_url

            driver.get(self.target_url)
            time.sleep(2)

            baseline_data = get_auth_baseline_response(self.target_url, session)
            if not baseline_data:
                logger.error("[-] Failed to collect authenticated baseline. Stopping scan.")
                driver.quit()
                return

            baseline_text, avg_length, avg_time, baseline_url, page_title, dom_signature, fingerprint, status_code = baseline_data
            norm_baseline = baseline_text

            logger.info("[AUTH SCAN] Baseline confirmed: URL: %s, Title: '%s', Fingerprint: %s, Status: %d",
                        baseline_url, page_title, fingerprint, status_code)

            if self.custom_payloads:
                payloads = {"custom": self.custom_payloads}
                logger.info("[+] Loaded %d custom payloads.", len(self.custom_payloads))
            else:
                selected_category = self.categories_to_test[0] if self.categories_to_test else None
                payloads = load_payloads(
                    payload_dir=self.payload_dir,
                    selected_category=selected_category
                )
                logger.info("[+] Loaded payloads from category: %s", selected_category)

            total_payloads = sum(len(lst) for lst in payloads.values())
            logger.info("[+] Total payloads to test: %d", total_payloads)

            if total_payloads == 0:
                logger.warning("No payloads found to test. Aborting scan.")
                return

            progress_tracker = ProgressTracker(total_payloads)
            anomalies = []
            injection_count = 0
            logged_payloads = set()

            for category, payload_list in payloads.items():
                for payload in payload_list:
                    if self.stop_event and self.stop_event.is_set():
                        logger.info("Stop event triggered. Halting scan.")
                        driver.quit()
                        return

                    injection_count += 1
                    progress_tracker.update(1)

                    driver.get(self.target_url)
                    time.sleep(2)

                    response, elapsed_time = measure_response_time(advanced_inject_payload, driver, payload, wait)
                    current_url = driver.current_url

                    if self.login_url and (self.login_url.split("?")[0] in current_url):
                        logger.warning("[!] Redirected to login page. Re-authenticating...")

                        if not self.auth_session.perform_login():
                            logger.error("[-] Re-login failed. Stopping scan.")
                            driver.quit()
                            return

                        driver.get(self.target_url)
                        time.sleep(2)

                        session = self.auth_session.get_session()
                        baseline_data = get_auth_baseline_response(self.target_url, session)
                        if baseline_data:
                            baseline_text, avg_length, avg_time, baseline_url, page_title, dom_signature, fingerprint, status_code = baseline_data
                            norm_baseline = baseline_text
                            logger.info("[*] Baseline re-collected after re-login.")
                        else:
                            logger.warning("[!] Failed to update baseline after re-login.")

                        response, elapsed_time = measure_response_time(advanced_inject_payload, driver, payload, wait)
                        current_url = driver.current_url

                    norm_response = normalize(response)

                    reports = detection_manager.run_all_detections(
                        response, norm_baseline, avg_time, elapsed_time, current_url, baseline_url, use_fuzzy=False
                    )

                    if reports:
                        for report in reports:
                            report["payload"] = payload
                            report["elapsed_time"] = elapsed_time
                            anomalies.append(report)
                            if self.anomaly_callback and payload not in logged_payloads:
                                self.anomaly_callback(report)
                                logged_payloads.add(payload)

                        if any(r["category"] == "Behavior" for r in reports):
                            logger.warning("Behavior anomaly detected — restarting browser and re-authenticating.")
                            driver.quit()
                            time.sleep(1)
                            driver = launch_new_browser(self.headless_mode)
                            wait = WebDriverWait(driver, 10)

                            self.auth_session.driver = driver
                            self.auth_session.wait = wait

                            if not self.auth_session.perform_login():
                                logger.error("[-] Re-login failed after browser reset.")
                                return

                            driver.get(self.target_url)
                            time.sleep(2)

                            session = self.auth_session.get_session()
                            baseline_data = get_auth_baseline_response(self.target_url, session)
                            if baseline_data:
                                baseline_text, avg_length, avg_time, baseline_url, page_title, dom_signature, fingerprint, status_code = baseline_data
                                norm_baseline = baseline_text
                                logger.info("[*] Baseline updated after browser restart.")
                            else:
                                logger.warning("[!] Failed to update baseline after restart.")

                    if self.progress_callback:
                        self.progress_callback(
                            progress_tracker.percentage(),
                            progress_tracker.remaining_time(),
                            progress_tracker.progress_string()
                        )

            logger.info("Authenticated scan completed.")

        finally:
            logger.info("[*] Closing Selenium browser.")
            driver.quit()
