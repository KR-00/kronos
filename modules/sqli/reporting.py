# reporting.py
# handles logging to file, console, and Tkinter GUI
# also manages anomaly logs and similarity messages

import logging
import tkinter as tk

class TextHandler(logging.Handler):
    """
    Custom log handler that outputs log messages to a Tkinter Text widget.
    Useful for showing logs directly inside the GUI.
    """
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

        # tag styling for "WARNING" messages — make them red
        self.text_widget.tag_config("warning_word", foreground="red")

    def emit(self, record):
        # format the log message
        msg = self.format(record)

        def append():
            self.text_widget.configure(state="normal")

            # highlight "WARNING" if it appears in the log
            if "WARNING" in msg:
                before, warning, after = msg.partition("WARNING")
                self.text_widget.insert(tk.END, before)                      # normal text
                self.text_widget.insert(tk.END, warning, "warning_word")    # red warning
                self.text_widget.insert(tk.END, after + "\n\n")             
            else:
                self.text_widget.insert(tk.END, msg + "\n\n")               # regular message

            self.text_widget.configure(state="disabled")
            self.text_widget.yview(tk.END)  # auto-scroll to bottom

        # queue this GUI update safely
        self.text_widget.after(0, append)

def initialize_logger(log_file="scanner.log", level=logging.INFO, text_widget=None, console=False):
    """
    Sets up the main logger for the scanner.
    It can log to a file, and in the gui.

    Params:
      log_file: where to write logs on disk
      level: minimum logging level (INFO, DEBUG, etc.)
      text_widget: if provided, also logs into the GUI text box
      console: if True, also logs to the terminal

    Returns:
      logger instance
    """
    logger = logging.getLogger("SQLiScanner")

    # prevent duplicate handlers if this was called before
    if not logger.hasHandlers():
        logger.setLevel(level)

        # standard format for all handlers
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # log to file
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        # log to GUI if a text widget was passed
        if text_widget is not None:
            text_handler = TextHandler(text_widget)
            text_handler.setLevel(level)
            text_handler.setFormatter(formatter)
            logger.addHandler(text_handler)

        # optional terminal logging
        if console:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

    # create a separate logger for similarity debug messages
    similarity_logger = logging.getLogger("SQLiScanner.similarity")
    similarity_logger.setLevel(logging.DEBUG)

    return logger

def log_anomaly(logger, anomaly_details):
    """
    Logs a quick summary of a detected anomaly.
    Useful for showing which payload triggered something and how long it took.

    Params:
      anomaly_details: a dict from the detection module
    """
    payload = anomaly_details.get("payload", "N/A")
    elapsed_time = anomaly_details.get("elapsed_time", 0)
    summary_msg = (
        f"Anomaly detected with payload: '{payload}' | Elapsed Time: {elapsed_time:.2f}s"
    )
    logger.warning(summary_msg)

def clear_text_widget(text_widget):
    """
    Clears the contents of the GUI Text widget — used when restarting or resetting the scan.
    """
    text_widget.configure(state="normal")
    text_widget.delete("1.0", tk.END)
    text_widget.configure(state="disabled")

def log_similarity(similarity):
    """
    Logs just the similarity score — goes to the similarity sub-logger (DEBUG level).
    Can be helpful for debugging near-miss detections.

    Params:
      similarity: a float value 
    """
    similarity_logger = logging.getLogger("SQLiScanner.similarity")
    similarity_logger.debug("Similarity percentage after payload: {:.2f}%".format(similarity))
