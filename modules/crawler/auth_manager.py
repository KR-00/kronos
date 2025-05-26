from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoSuchElementException, TimeoutException
import time
import random

# Stores the login page URL after first detection, for re-login checks
saved_login_url = None

def slow_typing(element, text, delay_range=(0.05, 0.15)):
    """
    Simulates human-like typing into a web element by inserting characters one by one
    with random delays. Helps avoid bot detection.
    """
    for char in text:
        element.send_keys(char)
        time.sleep(random.uniform(*delay_range))

def login(driver, login_url, username, password):
    """
    Attempts to perform a login on the given login URL using Selenium.
    Detects login success based on changes to URL or page content.

    Args:
        driver: Selenium WebDriver instance.
        login_url: URL of the login form.
        username: Username string.
        password: Password string.

    Returns:
        True if login appears successful, False otherwise.
    """
    global saved_login_url

    try:
        driver.get(login_url)
        wait = WebDriverWait(driver, 10)

        # Capture the initial page state before login
        initial_url = driver.current_url
        initial_title = driver.title
        initial_body = driver.find_element(By.TAG_NAME, "body").text.strip()

        # Find the login form elements
        username_field = find_username_field(driver, wait)
        password_field = find_password_field(driver, wait)
        login_button = find_login_button(driver, wait)

        if username_field and password_field:
            username_field.clear()
            slow_typing(username_field, username)  # Simulate human typing

            password_field.clear()
            slow_typing(password_field, password)

            if login_button:
                try:
                    login_button.click()
                except Exception:
                    print("[!] Click failed. Trying ENTER key...")
                    password_field.send_keys(Keys.RETURN)
            else:
                print("[!] No login button found. Pressing ENTER.")
                password_field.send_keys(Keys.RETURN)

            time.sleep(3)  # Allow time for redirect or content load

            # Capture post-login state
            new_url = driver.current_url
            new_title = driver.title
            new_body = driver.find_element(By.TAG_NAME, "body").text.strip()

            url_changed = (new_url != initial_url)
            body_changed = (new_body != initial_body)

            if url_changed or body_changed:
                print("[+] Page changed after login. Login probably successful.")
                if saved_login_url is None:
                    saved_login_url = initial_url
                return True
            else:
                print(f"[!] Login failed. Still at: {new_url} (Title: '{new_title}')")
                return False

        else:
            print("[!] Username or password fields not found.")
            return False

    except Exception as e:
        print(f"[!] Login attempt failed: {e}")
        return False

def login_successful(driver):
    """
    Secondary/fallback check to determine if login was successful
    by looking for common logout indicators.

    Returns:
        True if logout link/button is found.
    """
    try:
        if find_logout_button(driver):
            return True
    except Exception:
        pass
    return False

def needs_relogin(driver):
    """
    Determines whether the current page appears to be the login page,
    either by URL comparison or form field heuristics.

    Returns:
        True if re-login is needed.
    """
    global saved_login_url

    try:
        current_url = driver.current_url
        if saved_login_url and current_url == saved_login_url:
            return True

        if find_username_field(driver) and find_password_field(driver):
            return True
    except Exception:
        pass

    return False

def find_username_field(driver, wait=None):
    """
    Attempts to locate the username/email input field using common heuristics.
    """
    try:
        if wait:
            wait.until(EC.presence_of_element_located((By.XPATH, "//input")))

        inputs = driver.find_elements(By.XPATH, "//input")
        for input_tag in inputs:
            name = input_tag.get_attribute("name") or ""
            id_ = input_tag.get_attribute("id") or ""
            placeholder = input_tag.get_attribute("placeholder") or ""

            if any(keyword in name.lower() for keyword in ["user", "email", "login"]) or \
               any(keyword in id_.lower() for keyword in ["user", "email", "login"]) or \
               any(keyword in placeholder.lower() for keyword in ["user", "email", "login"]):
                return input_tag
    except (NoSuchElementException, TimeoutException):
        pass
    return None

def find_password_field(driver, wait=None):
    """
    Attempts to locate the password input field by type='password'.
    """
    try:
        if wait:
            wait.until(EC.presence_of_element_located((By.XPATH, "//input[@type='password']")))
        return driver.find_element(By.XPATH, "//input[@type='password']")
    except (NoSuchElementException, TimeoutException):
        return None

def find_login_button(driver, wait=None):
    """
    Attempts to locate the login/submit button based on type or label text.
    """
    try:
        if wait:
            wait.until(EC.presence_of_element_located((By.XPATH, "//button")))

        buttons = driver.find_elements(By.TAG_NAME, "button")
        for button in buttons:
            type_attr = button.get_attribute("type")
            text = button.text.lower()
            if (type_attr and type_attr.lower() == "submit") or ("login" in text):
                return button
    except (NoSuchElementException, TimeoutException):
        pass
    return None

def find_logout_button(driver):
    """
    Attempts to detect logout indicators after successful login.
    """
    try:
        links = driver.find_elements(By.TAG_NAME, "a")
        for link in links:
            text = link.text.lower()
            if "logout" in text or "sign out" in text:
                return link
    except NoSuchElementException:
        pass
    return None
