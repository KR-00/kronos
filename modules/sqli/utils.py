# general utilities shared by the scanner
import time
import logging
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# setting up a logger specific for SQLi scanner
logger = logging.getLogger("SQLiScanner")

def wait_for_page(driver, wait_obj):
    # waits for <body> tag to appear, which usually means the page has loaded
    # returns True if successful, False if it times out
    try:
        wait_obj.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        return True
    except Exception as e:
        logger.error("Timeout waiting for page load: %s", e)
        return False

def close_popups(driver, timeout=5):
    # tries to close common pop-ups like cookie banners or modals
    # this uses XPaths and checks for buttons with text like "close" or "dismiss"
    try:
        for xpath in [
            '//button[contains(translate(text(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "dismiss")]',
            '//button[contains(translate(text(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"), "close")]'
        ]:
            try:
                element = WebDriverWait(driver, timeout).until(EC.element_to_be_clickable((By.XPATH, xpath)))
                element.click()
                time.sleep(1)  # wait a bit in case it triggers another popup
            except Exception:
                continue  # if this one doesn't work, try the next
    except Exception as e:
        logger.error("Error closing pop-ups: %s", e)

def normalize_text(text):
    # cleans up extra whitespace in a string (e.g., for comparing content)
    return " ".join(text.split())

class ProgressTracker:
    #to keep track of how much work is done and estimate remaining time
    def __init__(self, total_tasks):
        self.total_tasks = total_tasks
        self.completed_tasks = 0
        self.start_time = time.time()  # so we can calculate elapsed time later
    
    def update(self, tasks_completed=1):
        # call this whenever a task is done
        self.completed_tasks += tasks_completed
    
    def percentage(self):
        # returns how much is done as a %
        return (self.completed_tasks / self.total_tasks) * 100 if self.total_tasks else 0
    
    def remaining_time(self):
        # estimates how much time is left based on average task time
        elapsed = time.time() - self.start_time
        if self.completed_tasks == 0:
            return None  # it can't guess yet the time and speed 
        avg_time = elapsed / self.completed_tasks
        remaining_tasks = self.total_tasks - self.completed_tasks
        return remaining_tasks * avg_time
    
    def progress_string(self):
        # returns something like "3/100" for the progress bar
        return f"{self.completed_tasks}/{self.total_tasks}"