# error_detection.py
# detects error messages in responses based on known patterns (DB, client, WAF, etc.)
# also catches GUI-based "leaks" — visible blocks that weren’t in the baseline

# The severity is not being used yet - and probably not accurate 
# The export file must be coded first - just for future proofing so i wont need to go back 

import re
import logging
from difflib import SequenceMatcher
from bs4 import BeautifulSoup

logger = logging.getLogger("SQLiScanner")
FUZZY_THRESHOLD = 0.8  # how close a fuzzy match must be to count


# RAW PATTERNS (strings)


# SQL error messages by DB type
SERVER_ERROR_PATTERNS_RAW = {
    "MySQL": [
        {"pattern": r"you have an error in your sql syntax", "severity": 5},
        {"pattern": r"warning.*mysql", "severity": 4},
        {"pattern": r"mysql_fetch_array", "severity": 3},
        {"pattern": r"check the manual that corresponds to your MySQL server version", "severity": 4}
    ],
    "SQL Server": [
        {"pattern": r"unclosed quotation mark", "severity": 5},
        {"pattern": r"quoted string not properly terminated", "severity": 5},
        {"pattern": r"Microsoft OLE DB Provider for SQL Server", "severity": 4},
        {"pattern": r"SQL Server error", "severity": 4}
    ],
    "Oracle": [
        {"pattern": r"ORA-\d{5}", "severity": 5},
        {"pattern": r"Oracle error", "severity": 4}
    ],
    "PostgreSQL": [
        {"pattern": r"syntax error at or near", "severity": 5},
        {"pattern": r"unexpected end of sql command", "severity": 4},
        {"pattern": r"pg_query", "severity": 3}
    ],
    "SQLite": [
        {"pattern": r"SQLiteException", "severity": 4},
        {"pattern": r"SQLite error:", "severity": 4}
    ]
}

# JavaScript/browser errors
CLIENT_ERROR_PATTERNS_RAW = [
    {"pattern": r"\[object Object\]", "severity": 2},
    {"pattern": r"TypeError:", "severity": 2},
    {"pattern": r"ReferenceError:", "severity": 2},
    {"pattern": r"undefined is not a function", "severity": 2},
    {"pattern": r"Cannot read property", "severity": 2}
]

# Web Application Firewall indicators
WAF_ERROR_PATTERNS_RAW = [
    {"pattern": r"modsecurity", "severity": 3},
    {"pattern": r"access denied", "severity": 3},
    {"pattern": r"(?<!cdnjs\.)cloudflare", "severity": 3},  # avoids false positives from cdnjs
    {"pattern": r"waf", "severity": 3}
]

# Any extra or user-defined patterns
CUSTOM_ERROR_PATTERNS_RAW = [
    {"pattern": r"CustomDatabaseError", "severity": 4},
    {"pattern": r"Oops! Something went wrong", "severity": 3}
]

# PHP error types
PHP_ERROR_PATTERNS_RAW = [
    {"pattern": r"Fatal error:", "severity": 4},
    {"pattern": r"Parse error:", "severity": 4},
    {"pattern": r"Warning:", "severity": 2},
    {"pattern": r"Notice:", "severity": 1}
]

# ASP.NET / IIS errors
ASP_NET_ERROR_PATTERNS_RAW = [
    {"pattern": r"Server Error in '/' Application", "severity": 5},
    {"pattern": r"HTTP Error 500 - Internal Server Error", "severity": 4},
    {"pattern": r"ASP\.NET is configured to show detailed errors", "severity": 3}
]


# Pattern compiler


def compile_patterns(raw_patterns):
    # compiles the regex strings into actual re.Pattern objects
    compiled = []
    for item in raw_patterns:
        try:
            c = re.compile(item["pattern"], re.IGNORECASE)
            compiled.append({"pattern": c, "severity": item["severity"], "raw": item["pattern"]})
        except Exception as e:
            logger.error("Failed to compile pattern %s: %s", item["pattern"], e)
    return compiled

# Precompile everything once so we don't repeat it on each scan
SERVER_ERROR_PATTERNS_COMPILED = {db: compile_patterns(patterns) for db, patterns in SERVER_ERROR_PATTERNS_RAW.items()}
CLIENT_ERROR_PATTERNS_COMPILED = compile_patterns(CLIENT_ERROR_PATTERNS_RAW)
WAF_ERROR_PATTERNS_COMPILED = compile_patterns(WAF_ERROR_PATTERNS_RAW)
CUSTOM_ERROR_PATTERNS_COMPILED = compile_patterns(CUSTOM_ERROR_PATTERNS_RAW)
PHP_ERROR_PATTERNS_COMPILED = compile_patterns(PHP_ERROR_PATTERNS_RAW)
ASP_NET_ERROR_PATTERNS_COMPILED = compile_patterns(ASP_NET_ERROR_PATTERNS_RAW)


# Main detection logic


def detect_error_keywords(response, use_fuzzy=False):
    # runs all compiled regexes against the response content
    # returns a list of findings with context

    reports = []

    def process_patterns(patterns, category, label):
        for pat in patterns:
            logger.debug("Testing pattern '%s' for category '%s'", pat["raw"], category)

            # exact match
            match = pat["pattern"].search(response)
            if match:
                snippet = match.group(0)
                context_start = max(match.start() - 30, 0)
                context_end = match.end() + 30
                context_snippet = response[context_start: context_end]

                report = {
                    "category": category,
                    "label": label,
                    "matched_text": snippet,
                    "severity": pat["severity"],
                    "context": context_snippet,
                    "pattern": pat["raw"]
                }
                logger.debug("Pattern matched: %s", report)
                reports.append(report)

            else:
                logger.debug("No exact match for pattern '%s' in category '%s'", pat["raw"], category)

            # optional fuzzy matching if enabled
            if use_fuzzy and not match:
                ratio = SequenceMatcher(None, pat["raw"], response).ratio()
                logger.debug("Fuzzy ratio for pattern '%s': %s", pat["raw"], ratio)
                if ratio >= FUZZY_THRESHOLD:
                    report = {
                        "category": category,
                        "label": f"{label} (Fuzzy)",
                        "matched_text": pat["raw"],
                        "severity": pat["severity"],
                        "context": response[:100],
                        "pattern": pat["raw"]
                    }
                    logger.debug("Fuzzy match detected: %s", report)
                    reports.append(report)

    # Run each detection category
    for db, patterns in SERVER_ERROR_PATTERNS_COMPILED.items():
        process_patterns(patterns, db, f"{db}:Syntax")

    process_patterns(CLIENT_ERROR_PATTERNS_COMPILED, "Client", "Client:Error")
    process_patterns(WAF_ERROR_PATTERNS_COMPILED, "WAF", "WAF:Block")
    process_patterns(PHP_ERROR_PATTERNS_COMPILED, "PHP", "PHP:Error")
    process_patterns(ASP_NET_ERROR_PATTERNS_COMPILED, "ASP.NET", "ASP.NET:Error")
    process_patterns(CUSTOM_ERROR_PATTERNS_COMPILED, "Custom", "Custom:Error")

    logger.debug("Error detection reports: %s", reports)
    return reports


# GUI leak detection


def detect_gui_content_leaks(baseline_html, payload_html, context=None):
    """
    Flags visual changes on the page (DOM blocks) that appeared only after injection.
    Useful for spotting data leaks or error blocks shown to the user.
    """
    soup_baseline = BeautifulSoup(baseline_html, "html.parser")
    soup_payload = BeautifulSoup(payload_html, "html.parser")

    tags_to_check = ["table", "tr", "td", "ul", "li", "form", "pre", "code", "div", "h1", "h2", "h3"]

    def extract_visible_blocks(soup):
        return set(
            el.get_text(strip=True)
            for el in soup.find_all(tags_to_check)
            if el.get_text(strip=True) and len(el.get_text(strip=True)) > 4
        )

    # get visible blocks from before and after payload injection
    baseline_blocks = extract_visible_blocks(soup_baseline)
    payload_blocks = extract_visible_blocks(soup_payload)

    # if new blocks showed up — they might be leaks
    new_blocks = payload_blocks - baseline_blocks

    if new_blocks:
        logger.debug("Heuristic GUI leak detected — new blocks: %s", list(new_blocks)[:3])
        return [{
            "category": "Heuristic",
            "label": "Heuristic:GUIContentLeak",
            "matched_text": "New visual content appeared after payload.",
            "severity": 5,
            "context": {"new_gui_blocks": list(new_blocks)[:5]},
            "pattern": "DOM: New visible blocks not in baseline"
        }]
    
    return []
