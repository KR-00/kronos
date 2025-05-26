# modules/sqli/auth_scanner/auth_session.py

import logging
import time
import requests
from bs4 import BeautifulSoup
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import NoSuchElementException

logger = logging.getLogger("SQLiScanner")

class AuthSession:
    """
    Handles browser-based login and syncs session cookies to a requests.Session.
    Used for authenticated scanning scenarios.
    """

    def __init__(self, target_url, username, password, driver=None, wait=None):
        self.target_url = target_url
        self.username = username
        self.password = password
        self.session = requests.Session()  # requests session (used for non-Selenium parts)
        self.login_url = None
        self.driver = driver
        self.wait = wait

    def set_driver(self, driver, wait):
        """
        Used when the Selenium driver has been restarted and needs to be updated here.
        """
        self.driver = driver
        self.wait = wait
        logger.info("[*] AuthSession driver and wait updated after browser restart.")

    def find_login_page(self):
        """
        Attempts to detect if the given URL redirects to a login page
        by checking for redirection and password fields.
        """
        if not self.driver:
            logger.error("[-] Selenium driver not provided. Cannot detect login page.")
            return False

        try:
            self.driver.get(self.target_url)
            final_url = self.driver.current_url
        except Exception as e:
            logger.error("[-] Failed to open target URL in browser: %s", e)
            return False

        redirected = (final_url != self.target_url)
        self.login_url = final_url  # set login URL to where we landed

        logger.info("[*] Final URL after possible redirects: %s", self.login_url)

        soup = BeautifulSoup(self.driver.page_source, 'html.parser')
        password_inputs = soup.find_all('input', {'type': 'password'})  # look for password fields

        if redirected:
            if password_inputs:
                logger.info("[+] Redirected and password fields found. Detected login page: %s", self.login_url)
                return True
            else:
                logger.warning("[-] Redirected but no password fields found. Not a real login page.")
                return False
        else:
            logger.info("[*] No redirection detected. Assuming no login needed.")
            return False

    def perform_login(self):
        """
        Performs automated login using the Selenium driver.
        It fills in fields based on name attributes (e.g. 'user', 'pass'),
        submits the form, and verifies if login was successful.
        """
        if not self.login_url:
            logger.error("[-] Login URL is not set. Cannot perform login.")
            return False

        if not self.driver:
            logger.error("[-] Selenium driver not provided. Cannot perform login.")
            return False

        try:
            self.driver.get(self.login_url)
        except Exception as e:
            logger.error("[-] Failed to open login page: %s", e)
            return False

        try:
            # fill in form fields based on name/type
            inputs = self.driver.find_elements(By.TAG_NAME, "input")
            for inp in inputs:
                type_attr = (inp.get_attribute("type") or "").lower()
                name_attr = (inp.get_attribute("name") or "").lower()

                if type_attr == "hidden":
                    continue  # skip hidden fields

                # scroll into view if needed
                if not inp.is_displayed():
                    self.driver.execute_script("arguments[0].scrollIntoView(true);", inp)
                    self.wait.until(lambda d: inp.is_displayed())

                # fill username/password fields
                if 'user' in name_attr or 'email' in name_attr:
                    inp.clear()
                    inp.send_keys(self.username)
                elif 'pass' in name_attr:
                    inp.clear()
                    inp.send_keys(self.password)
                elif 'token' in name_attr:
                    continue
                else:
                    continue

            # try to find submit button
            try:
                submit = self.driver.find_element(By.XPATH, '//button[@type="submit"]')
            except NoSuchElementException:
                try:
                    submit = self.driver.find_element(By.XPATH, '//input[@type="submit"]')
                except NoSuchElementException:
                    submit = None

            # click submit, or press return if no button
            if submit:
                submit.click()
            else:
                inputs[0].send_keys(Keys.RETURN)

        except Exception as e:
            logger.error("[-] Error during login form submission: %s", e)
            return False

        time.sleep(2)  # wait for redirect

        final_url = self.driver.current_url
        # check if we were redirected to a new page (i.e., successful login)
        if final_url != self.login_url:
            logger.info("[+] Login successful! Redirected to: %s", final_url)
            self._sync_browser_cookies_to_session()
            return True
        # alternatively, check if page shows signs of success
        elif "logout" in self.driver.page_source.lower() or "dashboard" in self.driver.page_source.lower():
            logger.info("[+] Login successful! Detected dashboard or logout option.")
            self._sync_browser_cookies_to_session()
            return True
        else:
            logger.warning("[-] Login may have failed: still on login page or no clear success indicators.")
            return False

    def _sync_browser_cookies_to_session(self):
        """
        Pulls cookies from the Selenium driver and loads them into
        the requests.Session object so they can be reused.
        """
        if not self.driver:
            return

        try:
            selenium_cookies = self.driver.get_cookies()
            for cookie in selenium_cookies:
                self.session.cookies.set(cookie['name'], cookie['value'])
            logger.info("[*] Successfully synchronized browser cookies into session.")
        except Exception as e:
            logger.error("[-] Failed to synchronize cookies from browser: %s", e)

    def get_session(self):
        """
        Returns the current requests.Session — which may include auth cookies.
        """
        return self.session
