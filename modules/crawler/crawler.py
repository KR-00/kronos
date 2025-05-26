# crawler.py — handles crawling visible and hidden pages using Selenium

import os
import time
import re
import difflib
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException, TimeoutException, WebDriverException
import tldextract
from modules.crawler.auth_manager import login, needs_relogin

LOGIN_PAGE_URL = None  # shared global to remember login page if needed

# extract just the registered domain (e.g., site.com from blog.site.com)
def get_registered_domain(url):
    ext = tldextract.extract(url)
    return ext.registered_domain

# check if a URL is in the same domain scope as the base
def in_scope(url, base_reg_domain):
    try:
        url_reg_domain = get_registered_domain(url)
        return url_reg_domain == base_reg_domain
    except Exception:
        return False

# checks if the current page is unique by comparing visible text content
def is_unique_page(driver, unique_pages, url):
    try:
        page_content = driver.find_element(By.TAG_NAME, 'body').text
        if page_content not in unique_pages:
            unique_pages[page_content] = url
            return True
    except NoSuchElementException:
        pass
    return False

# main crawling logic for discovering linked pages
def discover_pages(driver, base_url, requires_authentication, authentication_type, username, password, login_url, stop_event):
    global LOGIN_PAGE_URL

    base_reg_domain = get_registered_domain(base_url)
    pages_to_check = [base_url]
    unique_pages = {}
    discovered_urls = []

    first_login_done = False

    while pages_to_check:
        if stop_event and stop_event.is_set():
            print("[!] Stop signal received. Stopping crawler (pages)...")
            break

        current_url = pages_to_check.pop(0)

        # skip known redirect loops or irrelevant domains
        if '/redirect' in current_url or re.search(r'legal\\.md$', current_url):
            continue

        try:
            driver.get(current_url)

            # if login is needed and not already handled
            if requires_authentication:
                if authentication_type == "direct" and not first_login_done:
                    print("[*] Performing direct login...")
                    success = login(driver, login_url, username, password)
                    if not success:
                        print("[!] Direct login failed. Continuing anyway...")
                    first_login_done = True
                    driver.get(current_url)
                elif authentication_type == "automatic" and needs_relogin(driver):
                    print("[*] Detected login page. Attempting automatic login...")
                    success = login(driver, driver.current_url, username, password)
                    if not success:
                        print("[!] Automatic login failed. Continuing anyway...")
                    driver.get(current_url)

            # skip if not in scope or not a page (e.g. image, file, etc.)
            if not in_scope(current_url, base_reg_domain):
                continue
            if re.search(r'\\.(pdf|md|jpg|png|zip|gif|jpeg|exe|doc|docx|txt)$', current_url):
                continue

            # if new, save it and collect links
            if is_unique_page(driver, unique_pages, current_url):
                discovered_urls.append(current_url)
                links = driver.find_elements(By.TAG_NAME, "a")
                for link in links:
                    href = link.get_attribute("href")
                    if href and in_scope(href, base_reg_domain) and href not in discovered_urls and href not in pages_to_check:
                        pages_to_check.append(href)

        except TimeoutException:
            print(f"[!] Timeout accessing {current_url}. Skipping...")
        except WebDriverException:
            print(f"[!] WebDriver error accessing {current_url}. Skipping...")

    return discovered_urls

# decides if the app uses hash-based or path-based routing
def auto_detect_mode(driver, base_url):
    if '#' in base_url:
        return "hash"
    try:
        driver.get(base_url)
        time.sleep(2)
        anchors = driver.find_elements(By.TAG_NAME, "a")
        for a in anchors:
            href = a.get_attribute("href")
            if href and href.strip().startswith("#/"):
                return "hash"
    except Exception:
        pass
    return "path"

# get the body content of a known 404 or error page
def get_error_page_content(driver, base_url, mode):
    bogus = "nonexistent_1234567890"
    if mode == "hash":
        if '#' in base_url:
            base_url = base_url.split('#')[0]
        candidate_url = base_url + "#/" + bogus
    else:
        candidate_url = base_url.rstrip('/') + "/" + bogus
    try:
        driver.get(candidate_url)
        time.sleep(2)
        content = driver.find_element(By.TAG_NAME, "body").text.strip()
        return content
    except Exception:
        return ""

# tries to brute-force hidden URLs using a wordlist and similarity
def find_hidden_pages(driver, base_url, wordlist_file, mode, stop_event):
    try:
        with open(wordlist_file, "r") as file:
            routes = file.readlines()
    except FileNotFoundError:
        print(f"[!] Wordlist file '{wordlist_file}' not found.")
        return []

    if mode == "hash":
        if '#' in base_url:
            base_url = base_url.split('#')[0]

    error_content = get_error_page_content(driver, base_url, mode)
    hidden_pages = []

    for route in routes:
        if stop_event and stop_event.is_set():
            print("[!] Stop signal received. Stopping crawler (hidden pages)...")
            break

        route = route.strip()
        if not route:
            continue

        # build full URL depending on routing style
        if mode == "hash":
            candidate = route if route.startswith("#/") else "#/" + route.lstrip("/")
            full_url = base_url + candidate
        else:
            full_url = base_url.rstrip('/') + "/" + route.lstrip('/')

        try:
            driver.get(full_url)
            time.sleep(2)
            content = driver.find_element(By.TAG_NAME, "body").text.strip()
            similarity = difflib.SequenceMatcher(None, content, error_content).ratio() if error_content else 0
            if similarity > 0.9:
                continue  # skip pages too similar to the 404
            if full_url not in hidden_pages:
                hidden_pages.append(full_url)
        except TimeoutException:
            print(f"[!] Timeout accessing {full_url}. Skipping...")
        except WebDriverException:
            print(f"[!] WebDriver error accessing {full_url}. Skipping...")

    return hidden_pages

# main function to start crawling, including visible and hidden pages
def start_crawler(
    base_url,
    wordlist_file,
    requires_authentication=False,
    authentication_type="automatic",
    username=None,
    password=None,
    login_url=None,
    stop_event=None,
    headless=False  # headless mode toggle
):
    global LOGIN_PAGE_URL
    LOGIN_PAGE_URL = None

    # default wordlist if not provided
    if not wordlist_file:
        wordlist_file = os.path.join(os.getcwd(), "payloads", "hidden_pages", "common_path.txt")

    # browser options
    options = webdriver.ChromeOptions()
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--window-size=1920,1080")
    if headless:
        options.add_argument("--headless")

    driver = webdriver.Chrome(options=options)
    driver.set_page_load_timeout(15)
    driver.set_script_timeout(10)

    try:
        print("[*] Crawler started... Please wait.")
        mode = auto_detect_mode(driver, base_url)

        # find all visible pages and then probe for hidden ones
        discovered_pages = discover_pages(
            driver,
            base_url,
            requires_authentication,
            authentication_type,
            username,
            password,
            login_url,
            stop_event
        )
        hidden_pages = find_hidden_pages(driver, base_url, wordlist_file, mode, stop_event)

        # combine lists but avoid duplicates
        all_pages = discovered_pages + [p for p in hidden_pages if p not in discovered_pages]

        print("\\n[*] Pages found:")
        for page in all_pages:
            print(page)

    finally:
        driver.quit()
        print("[*] Crawler finished, browser closed.")
