# handles the actual injection of payloads into forms
# has a basic injector and a more advanced one used for consistent scanning

import time
import logging
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException, ElementClickInterceptedException

logger = logging.getLogger("SQLiScanner")

def detect_form_elements(driver):
    # finds all <input> elements that are actually visible on the page
    inputs = driver.find_elements(By.TAG_NAME, "input")
    visible_inputs = [inp for inp in inputs if inp.is_displayed()]
    return visible_inputs

def inject_payload(driver, payload, wait):
    # simple payload injection — targets the first visible input field
    # enters the payload and hits RETURN
    inputs = detect_form_elements(driver)
    if not inputs:
        logger.error("No visible input elements found.")
        return driver.page_source
    try:
        first_input = inputs[0]
        first_input.clear()
        first_input.send_keys(payload)
        first_input.send_keys(Keys.RETURN)
    except Exception as e:
        logger.error("Error during payload injection: %s", e)
    time.sleep(2)  # give the page time to respond
    return driver.page_source.lower()

def advanced_inject_payload(driver, payload, wait):
    # this version is more thorough — used when building baselines
    # injects the payload into *every* visible and relevant input field
    inputs = driver.find_elements(By.TAG_NAME, "input")
    for inp in inputs:
        try:
            type_attr = (inp.get_attribute("type") or "").lower()
            if type_attr in ["hidden", "submit", "button", "reset"]:
                continue  # skip inputs that aren't meant for user input
            if not inp.is_displayed():
                # scroll into view if it's hidden initially
                driver.execute_script("arguments[0].scrollIntoView(true);", inp)
                wait.until(lambda d: inp.is_displayed())
            try:
                inp.clear()
                inp.send_keys(payload)
            except Exception:
                # fallback for inputs that can't be typed into — force-set the value
                driver.execute_script("arguments[0].value = arguments[1];", inp, payload)
        except Exception:
            continue  # move on to next input if something fails

    # now try to find a submit button to actually send the form
    submit = None
    try:
        # looks for a button with text like "login"
        submit = driver.find_element(
            By.XPATH, 
            '//button[contains(translate(text(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "login")]'
        )
    except NoSuchElementException:
        pass

    # fallback: try to find any submit-type button
    if not submit:
        try:
            submit = driver.find_element(By.XPATH, '//button[@type="submit"]')
        except NoSuchElementException:
            try:
                submit = driver.find_element(By.XPATH, '//input[@type="submit"]')
            except NoSuchElementException:
                pass

    # if we found a submit button, click it (even forcefully if needed)
    if submit:
        try:
            if not submit.is_displayed():
                driver.execute_script("arguments[0].scrollIntoView(true);", submit)
                wait.until(lambda d: submit.is_displayed())
            try:
                submit.click()
            except ElementClickInterceptedException:
                driver.execute_script("arguments[0].click();", submit)
        except Exception as e:
            logger.error("Error clicking submit button: %s", e)
    else:
        # fallback if no submit button was found — press RETURN on the first visible field
        try:
            for inp in inputs:
                if inp.is_displayed():
                    inp.send_keys(Keys.RETURN)
                    break
        except Exception:
            pass

    time.sleep(2)  # wait for page to reload after form submission
    return driver.page_source.lower()
