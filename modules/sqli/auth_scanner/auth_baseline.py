# auth_baseline.py
# gets a baseline response for authenticated pages using a logged-in requests.Session
# it cleans the response aggressively to avoid noise from dynamic tokens, timestamps, etc.

import time
import re
import hashlib
import logging
from collections import Counter
from bs4 import BeautifulSoup
import requests

logger = logging.getLogger("SQLiScanner")

def clean_html(html, aggressive=True):
    """
    Removes noise from the HTML that would mess up detection.
    This includes CSRF tokens, timestamps, user info, hidden fields, scripts, etc.
    """
    if aggressive:
        # Remove things that change every page load (timestamp format: YYYY-MM-DD HH:MM:SS)
        html = re.sub(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", "", html)

        # Remove RFC-like date headers (e.g., Tue, 30 Apr 2024 15:42:12 GMT)
        html = re.sub(r"[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT", "", html)

        # Remove CSRF, token, nonce input fields (names or IDs)
        html = re.sub(
            r"(name|id)=['\"]?(csrf\w*|token|auth|nonce)['\"]?\s+value=['\"][^'\"]+['\"]",
            "", html, flags=re.IGNORECASE
        )

        # Remove hidden input fields altogether (commonly used for state/anti-CSRF)
        html = re.sub(r"<input[^>]*type=['\"]hidden['\"][^>]*>", "", html, flags=re.IGNORECASE)

        # Strip out scripts and <meta> tags (often contain JS, analytics, etc.)
        html = re.sub(r"<script.*?>.*?</script>", "", html, flags=re.DOTALL)
        html = re.sub(r"<meta[^>]*>", "", html)

        # Remove any HTML comments (may contain debugging info or dynamic data)
        html = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)

        # Remove Google reCAPTCHA elements
        html = re.sub(r"<div[^>]*g-recaptcha[^>]*>.*?</div>", "", html, flags=re.DOTALL)

        # Remove long random-looking IDs (UUIDs, tokens, etc.)
        html = re.sub(r'\b(id|data-id)=["\']?[a-f0-9]{16,}["\']?', '', html, flags=re.IGNORECASE)

        # Remove dynamic username greetings (e.g., "Welcome admin")
        html = re.sub(r"welcome\s+\w+", "", html, flags=re.IGNORECASE)

    # Normalize all whitespace and lowercase everything
    html = re.sub(r"\s+", " ", html).strip().lower()
    return html

def normalize(text, aggressive=True):
    """
    Wrapper for clean_html() — just gives it a nicer name to call elsewhere.
    """
    return clean_html(text, aggressive)

def get_auth_baseline_response(url, session):
    """
    This function fetches a clean, normalized version of a page using an authenticated session.
    It's used to get the 'before injection' reference for protected areas with authentication.

    Returns:
      - cleaned response
      - its length
      - how long it took
      - original URL
      - page title
      - DOM tag breakdown
      - MD5 fingerprint
      - HTTP status code
    """
    try:
        start = time.time()
        response = session.get(url, timeout=10)
        end = time.time()

        if response.status_code != 200:
            logger.warning("[-] Baseline request returned non-200 status code: %d", response.status_code)

        raw_html = response.text
        norm_html = normalize(raw_html, aggressive=True)
        response_time = end - start
        content_length = len(norm_html)

        # Parse page title (for display/logging)
        soup = BeautifulSoup(raw_html, 'html.parser')
        page_title = soup.title.string.strip() if soup.title and soup.title.string else ""

        # Build a DOM "signature" — count how many tags like div, h1, table, etc.
        tags = [tag.name for tag in soup.find_all()]
        dom_signature = dict(Counter(tags))

        # Create a fingerprint by hashing the normalized HTML
        fingerprint = hashlib.md5(norm_html.encode('utf-8')).hexdigest()

        return (
            norm_html,
            content_length,
            response_time,
            url,
            page_title,
            dom_signature,
            fingerprint,
            response.status_code
        )

    except Exception as e:
        logger.error("[-] Failed to collect authenticated baseline: %s", e)
        return None
