# handles loading SQLi payloads — either from a custom file or a specific category (but never both)
import os
import logging

logger = logging.getLogger("SQLiScanner")

def validate_payload_format(payload):
    # simple check — it just ignore empty strings
    return payload if payload else None

def deduplicate_preserve_order(payloads):
    # removes duplicates while keeping original order
    seen = set()
    return [p for p in payloads if p not in seen and not seen.add(p)]

def load_custom_payloads(custom_file):
    # loads payloads from a user-supplied .txt file
    # returns a dict: {"custom": [payloads]}
    if not custom_file or not os.path.isfile(custom_file):
        logger.warning("Custom payload file missing or invalid: %s", custom_file)
        return {}

    try:
        with open(custom_file, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]  # clean up blank lines
            payloads = [validate_payload_format(p) for p in lines if p]
            payloads = deduplicate_preserve_order(payloads)
            logger.info("[+] Loaded %d custom payloads from: %s", len(payloads), custom_file)
            return {"custom": payloads}
    except Exception as e:
        logger.error("Error loading custom payloads: %s", e)
        return {}

def load_payloads_from_category(payload_dir, category):
    # loads payloads from a file like 'error_based.txt' inside the payloads folder
    # returns a dict: {category: [payloads]}
    if not payload_dir or not os.path.isdir(payload_dir):
        logger.warning("Invalid payload directory: %s", payload_dir)
        return {}

    filename = f"{category}.txt"
    filepath = os.path.join(payload_dir, filename)

    if not os.path.isfile(filepath):
        logger.warning("Payload file for category '%s' not found: %s", category, filepath)
        return {}

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
            payloads = [validate_payload_format(p) for p in lines if p]
            payloads = deduplicate_preserve_order(payloads)
            return {category: payloads}
    except Exception as e:
        logger.error("Error loading payloads from category '%s': %s", category, e)
        return {}

def load_payloads(payload_dir=None, custom_file=None, selected_category=None):
    # main function to load payloads — picks either a custom file OR a category
    # if both are given, we ignore the category and prefer the custom file
    if custom_file and selected_category:
        logger.warning("Both custom file and category specified — only one source allowed. Ignoring category.")
        return load_custom_payloads(custom_file)

    if custom_file:
        return load_custom_payloads(custom_file)

    if selected_category:
        return load_payloads_from_category(payload_dir, selected_category)

    logger.warning("No valid payload source provided. Please select either a custom file or a category.")
    return {}
