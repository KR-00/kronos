# config.py — sets the default configuration for the SQLi scanner
# no external config files, just returns a built-in config dict
# That one needs refactoring , since i have put defaults on the detections
# but since it does not causes bugs i wont delete it yet ,
#  might be used later for adding custom configuration for fuzzing etc...

def load_configuration():
    # returns a dictionary with all default settings for the scanner

    configuration = {
        "target_url": "http://localhost:3000/#/",  # default scan target (can be changed in GUI)
        "login_url": "",           # left blank unless login is needed (user provides it)
        "requires_login": False,   # default is no login required
        "default_credentials": {
            "credential1": "admin",       # default test creds
            "credential2": "password"
        },
        "thresholds": {
            "similarity_threshold": 0.70,         # used for detecting response similarity
            "low_similarity_threshold": 0.65,     # looser match, still possibly suspicious
            "length_diff_threshold": 0.20,        # if response length differs by this much, it's flagged
            # "delay_threshold": 3.0              # not currently used, was for time-based stuff
        }
    }
    return configuration

def default_configuration():
    # just returns the same config — useful alias if needed
    return load_configuration()

if __name__ == "__main__":
    # if you run this file directly, it prints out the config info for testing/debugging
    import logging
    logger = logging.getLogger("SQLiScanner")
    logger.setLevel(logging.INFO)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    config = load_configuration()
    logger.info("Target URL: %s", config["target_url"])
    logger.info("Login URL: %s", config["login_url"])
    logger.info("Requires Login: %s", config["requires_login"])
    logger.info("Default Credentials: %s", config["default_credentials"])
    logger.info("Thresholds: %s", config["thresholds"])
