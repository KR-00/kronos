# Creates the baseline for comparison , probably will need more work in the future.

import time
import re
import logging
import hashlib
from collections import Counter
from bs4 import BeautifulSoup  

from .utils import wait_for_page, close_popups

logger = logging.getLogger("SQLiScanner")

def clean_html(html, aggressive=True):
    """
    Cleans the HTML/text by removing or standardizing dynamic content that may vary between requests.
    
    Parameters:
      aggressive (bool): If True, apply aggressive cleaning rules; otherwise, perform minimal cleaning.
    
    Aggressive cleaning (if True) performs the following substitutions:
      - Removes timestamps & dates (e.g. "2025-03-28 14:33:10" and "Fri, 28 Mar 2025 14:33:10 GMT").
      - Removes CSRF tokens and similar tokens by targeting common token names (csrf*, token, nonce).
      - Removes dynamic ad/analytics scripts.
      - Removes long hexadecimal/random IDs from id or data-id attributes (16+ characters).
      - Removes HTML comments.
      - Removes meta tags.
      - Removes CAPTCHA/Recaptcha widgets.
      - Removes footer/header version info.
      - Removes hidden input fields.
      - Normalizes whitespace.
      - Converts the result to lowercase.
    
    If aggressive is False, only whitespace normalization and lowercasing are performed.
    """
    if aggressive:
        # Remove timestamps & dates.
        html = re.sub(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", "", html)
        html = re.sub(r"[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT", "", html)
        
        # Remove CSRF and token-related attributes (generalized).
        html = re.sub(r"(name|id)=['\"]?(csrf\w*|token|nonce)['\"]?\s+value=['\"][^'\"]+['\"]", "", html, flags=re.IGNORECASE)
        
        # Remove dynamic ad/analytics scripts.
        html = re.sub(r"<script[^>]*analytics[^>]*>.*?</script>", "", html, flags=re.DOTALL)
        
        # Remove long hexadecimal/random IDs from id or data-id attributes (16+ characters).
        html = re.sub(r'\b(id|data-id)=["\']?[a-f0-9]{16,}["\']?', '', html, flags=re.IGNORECASE)
        
        # Remove HTML comments.
        html = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)
        
        # Remove meta tags.
        html = re.sub(r"<meta[^>]*>", "", html)
        
        # Remove CAPTCHA/Recaptcha widgets.
        html = re.sub(r"<div[^>]*class=['\"]g-recaptcha['\"].*?</div>", "", html, flags=re.DOTALL)
        
        # Remove footer/header version info.
        html = re.sub(r"Page rendered in .*? seconds", "", html)
        html = re.sub(r"Version [\d\.]+", "", html)
        
        # Remove hidden input fields.
        html = re.sub(r"<input type=['\"]hidden['\"].*?>", "", html)
    
    # Normalize whitespace and convert to lowercase (applies in both cases).
    html = re.sub(r"\s+", " ", html).strip().lower()
    return html

def normalize(text, aggressive=True):
    """
    Returns the cleaned version of the text.
    """
    return clean_html(text, aggressive)

def get_fresh_baseline(driver, wait, url, advanced_inject_payload, stop_event=None, debug_prefix=""):
    """
    Collects a baseline sample from the target page by injecting a consistent benign payload ("normal").
    
    Process:
      - Clears cookies and reloads the URL.
      - Closes pop-ups/overlays using close_popups.
      - Verifies that the response appears to be HTML.
      - Injects the benign payload "normal" using advanced_inject_payload.
      - Captures, cleans, and normalizes the response.
      - Measures the content length and response time.
      - Extracts additional details:
            * Page title (from the HTML <title> tag)
            * A tag frequency DOM signature (using Counter on all tag names)
            * A fingerprint hash (MD5 of the normalized response)
            * Simulated HTTP status code (assumed 200)
      
    Returns a tuple:
      (normalized_response, content_length, response_time, baseline_url, 
       page_title, dom_signature, fingerprint, status_code)
      
    Performs a sanity check to warn if the baseline appears unusually short.
    If debug logging is enabled and a debug_prefix is provided, saves raw and cleaned baseline snapshots.
    """
    if stop_event and stop_event.is_set():
        logger.info("Stop event detected before baseline collection. Exiting baseline collection.")
        return "", 0, 0, "", "", {}, "", 0
    
    driver.delete_all_cookies()
    driver.get(url)
    wait_for_page(driver, wait)
    close_popups(driver, wait)
    
    # Content-Type check.
    if "text/html" not in driver.page_source.lower():
        logger.warning("Baseline response may not be HTML.")
    
    # Inject benign payload ("normal") for baseline sampling.
    payload = "normal"
    start = time.time()
    response = advanced_inject_payload(driver, payload, wait)
    end = time.time()
    
    raw_response = response  # Save raw response for debugging.
    norm_resp = normalize(response, aggressive=True)
    baseline_url = driver.current_url
    response_time = end - start
    content_length = len(norm_resp)
    
    # Simulated HTTP status code (Selenium does not provide it, so we assume 200).
    status_code = 200
    
    # Extract page title.
    page_title = driver.title.strip() if driver.title else ""
    if not page_title:
        logger.warning("Baseline page title is empty; this may indicate an error or a redirect.")
    
    # Parse DOM structure using BeautifulSoup and compute tag frequency.
    soup = BeautifulSoup(norm_resp, 'html.parser')
    tags = [tag.name for tag in soup.find_all()]
    dom_signature = dict(Counter(tags))
    
    # Compute fingerprint hash (MD5) of the normalized response.
    fingerprint = hashlib.md5(norm_resp.encode('utf-8')).hexdigest()
    
    # Sanity check.
    if content_length < 500:
        logger.warning("Baseline response unusually short (length: %d). Possible error or redirect.", content_length)
    
    # Optionally dump raw and cleaned baseline snapshots if debug logging is enabled.
    if logger.isEnabledFor(logging.DEBUG) and debug_prefix:
        try:
            raw_filename = f"{debug_prefix}_baseline_raw.html"
            clean_filename = f"{debug_prefix}_baseline_cleaned.html"
            with open(raw_filename, "w", encoding="utf-8") as f:
                f.write(raw_response)
            with open(clean_filename, "w", encoding="utf-8") as f:
                f.write(norm_resp)
            logger.debug("Baseline snapshots saved to %s and %s.", raw_filename, clean_filename)
        except Exception as e:
            logger.warning("Failed to save baseline snapshots: %s", e)
    
    logger.info("Baseline collected: URL: %s, Length: %d, Time: %.2f, Title: '%s', Fingerprint: %s, Status: %d",
                baseline_url, content_length, response_time, page_title, fingerprint, status_code)
    
    return norm_resp, content_length, response_time, baseline_url, page_title, dom_signature, fingerprint, status_code
