# This is the main GUI class for the SQL injection scanner
# It lets you select a target, pick payloads, and run scans

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import time
import contextlib

# Import core modules: config, logger, and email alerts
from modules.sqli.config import load_configuration
from modules.sqli.reporting import initialize_logger
from modules.notifications.sqli_alerts import send_email_alert


class SqliGUI(ttk.Frame):  # GUI class that fits inside a Tkinter window
    def __init__(self, master):
        super().__init__(master)

        # Load settings (target URL, default creds)
        self.config_data = load_configuration()
        self.default_target = self.config_data.get("target_url", "http://localhost:3000/#/")
        self.default_credentials = self.config_data.get(
            "default_credentials", {"credential1": "admin", "credential2": "password"}
        )

        # Path where category payload files are stored
        self.payload_dir = os.path.join(os.getcwd(), "payloads", "sqli_payloads")

        # Runtime state vars
        self.custom_payload_path = None
        self.stop_event = threading.Event()  # to interrupt scan
        self.scan_thread = None
        self.payload_progress = "0/0"
        self.last_eta_remaining = None
        self.last_eta_update_time = None

        # Email alert credentials
        self.email_sender = None
        self.email_password = None
        self.email_recipient = None
        self.email_alert_enabled = False

        # GUI checkboxes
        self.headless_mode = tk.BooleanVar(value=False)
        self.use_custom_payload = tk.BooleanVar(value=False)

        # Set up GUI widgets, logger, category loader, and timer
        self.create_widgets()

        # allow expanding space in the layout
        for col in range(3):
            self.grid_columnconfigure(col, weight=1)
        self.grid_rowconfigure(8, weight=1)

        self.logger = initialize_logger(text_widget=self.output_text)
        self.after(0, self.load_categories)
        self.update_timer()

    # Build GUI layout
    def create_widgets(self):
        # Target URL input
        ttk.Label(self, text="Target URL:", font=("Helvetica", 12)).grid(
            row=0, column=0, sticky=tk.W, padx=5, pady=5
        )
        self.sqli_url = ttk.Entry(self, width=60, font=("Helvetica", 12))
        self.sqli_url.insert(0, self.default_target)
        self.sqli_url.grid(row=0, column=1, columnspan=2, sticky=tk.W, padx=5, pady=5)

        # Login toggle + credential input fields
        self.requires_login = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            self, text="Requires Login", variable=self.requires_login, command=self.toggle_credentials
        ).grid(row=1, column=0, sticky=tk.W, padx=5)

        self.credentials_frame = ttk.Frame(self)
        self.credentials_frame.grid(row=1, column=1, columnspan=2, sticky=tk.W)
        ttk.Label(self.credentials_frame, text="Username:", font=("Helvetica", 12)).grid(
            row=0, column=0, padx=5, pady=5
        )
        self.cred1_entry = ttk.Entry(self.credentials_frame, width=25, font=("Helvetica", 12))
        self.cred1_entry.insert(0, self.default_credentials.get("credential1", "admin"))
        self.cred1_entry.grid(row=0, column=1, padx=5)

        ttk.Label(self.credentials_frame, text="Password:", font=("Helvetica", 12)).grid(
            row=1, column=0, padx=5, pady=5
        )
        self.cred2_entry = ttk.Entry(
            self.credentials_frame, width=25, font=("Helvetica", 12), show="*"
        )
        self.cred2_entry.insert(0, self.default_credentials.get("credential2", "password"))
        self.cred2_entry.grid(row=1, column=1, padx=5)
        self.toggle_credentials()

        # Category selection
        ttk.Label(self, text="Select Payload Category:", font=("Helvetica", 12)).grid(
            row=2, column=0, padx=5, pady=5, sticky=tk.W
        )
        self.category_listbox = tk.Listbox(
            self, selectmode=tk.SINGLE, width=50, height=6, font=("Helvetica", 12)
        )
        self.category_listbox.grid(row=2, column=1, columnspan=2, padx=5, pady=5, sticky=tk.W)

        # Start button
        self.sqli_run_button = ttk.Button(self, text="Run Selected Payload", command=self.run_sqli)
        self.sqli_run_button.grid(row=3, column=0, columnspan=3, pady=10)

        # Custom payload option
        ttk.Label(self, text="Run Custom Payload:", font=("Helvetica", 12)).grid(
            row=4, column=0, padx=5, pady=5, sticky=tk.W
        )
        custom_frame = ttk.Frame(self)
        custom_frame.grid(row=4, column=1, columnspan=2, padx=5, pady=5, sticky=tk.W)
        self.custom_payload_entry = ttk.Entry(
            custom_frame, width=30, font=("Helvetica", 12), state="disabled"
        )
        self.custom_payload_entry.pack(side=tk.LEFT)
        self.custom_payload_button = ttk.Button(
            custom_frame, text="Browse", command=self.browse_custom_file, state="disabled"
        )
        self.custom_payload_button.pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(
            custom_frame, text="Enable", variable=self.use_custom_payload, command=self.toggle_payload_mode
        ).pack(side=tk.LEFT)

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self, length=300, mode="determinate", variable=self.progress_var
        )
        self.progress_bar.grid(row=5, column=0, columnspan=3, pady=(5, 0))
        self.progress_label = ttk.Label(
            self, text="Payload: 0/0 - Remaining Time: 00:00:00", font=("Helvetica", 10)
        )
        self.progress_label.grid(row=6, column=0, columnspan=3)

        # Add buttons and log output box
        self.create_control_buttons()
        self.create_output_text()

    # Buttons: Stop, Clear, Email Settings, Headless toggle
    def create_control_buttons(self):
        button_frame = ttk.Frame(self)
        button_frame.grid(row=7, column=0, columnspan=3, pady=5)
        ttk.Button(button_frame, text="Stop", command=self.stop_scan).pack(side=tk.LEFT, padx=10)
        ttk.Button(button_frame, text="Clear Output", command=self.clear_output).pack(
            side=tk.LEFT, padx=10
        )
        ttk.Button(button_frame, text="Email Settings", command=self.open_email_popup).pack(
            side=tk.LEFT, padx=(30, 5)
        )
        ttk.Checkbutton(button_frame, text="Headless Mode", variable=self.headless_mode).pack(
            side=tk.LEFT, padx=(30, 0)
        )

    # Setup output text area with scrollbar
    def create_output_text(self):
        output_frame = ttk.Frame(self)
        output_frame.grid(
            row=8, column=0, columnspan=3, padx=10, pady=10, sticky="nsew"
        )
        output_frame.grid_rowconfigure(0, weight=1)
        output_frame.grid_columnconfigure(0, weight=1)

        scrollbar = ttk.Scrollbar(output_frame)
        scrollbar.grid(row=0, column=1, sticky="ns")

        self.output_text = tk.Text(
            output_frame,
            wrap=tk.WORD,
            height=8,
            font=("Courier", 11),
            bg="#ffffff",
            fg="#333333",
            insertbackground="#007acc",
            yscrollcommand=scrollbar.set,
        )
        self.output_text.grid(row=0, column=0, sticky="nsew")
        scrollbar.config(command=self.output_text.yview)

        # right-click menu on text
        context_menu = tk.Menu(self.output_text, tearoff=0)
        context_menu.add_command(
            label="Copy", command=lambda: self.output_text.event_generate("<<Copy>>")
        )
        context_menu.add_command(
            label="Paste", command=lambda: self.output_text.event_generate("<<Paste>>")
        )
        self.output_text.bind(
            "<Button-3>", lambda event: context_menu.tk_popup(event.x_root, event.y_root)
        )

    # Show/hide login fields
    def toggle_credentials(self):
        self.credentials_frame.grid() if self.requires_login.get() else self.credentials_frame.grid_remove()

    # Switch between custom file mode and category mode
    def toggle_payload_mode(self):
        use_custom = self.use_custom_payload.get()
        self.custom_payload_entry.config(state="normal" if use_custom else "disabled")
        self.custom_payload_button.config(state="normal" if use_custom else "disabled")
        self.category_listbox.config(state="disabled" if use_custom else "normal")
        if not use_custom:
            self.custom_payload_path = None
            self.custom_payload_entry.delete(0, tk.END)

    # Load category names into listbox
    def load_categories(self):
        self.category_listbox.delete(0, tk.END)
        try:
            files = sorted(f for f in os.listdir(self.payload_dir) if f.endswith(".txt"))
            for f in files:
                self.category_listbox.insert(tk.END, f.rsplit(".", 1)[0])
        except Exception as e:
            self.logger.error(f"Failed to load categories: {e}")

    # Open file dialog to pick custom payload file
    def browse_custom_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            self.custom_payload_entry.delete(0, tk.END)
            self.custom_payload_entry.insert(0, file_path)
            self.custom_payload_path = file_path

    # if a scan is already running, don't allow another one
    def run_sqli(self):
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showwarning("Scan Running", "A scan is already in progress.")
            return

        # get inputs from GUI
        url = self.sqli_url.get().strip()
        is_headless = self.headless_mode.get()
        credentials = {
            "credential1": self.cred1_entry.get().strip(),
            "credential2": self.cred2_entry.get().strip()
        }
        # reset stop event in case user clicks run again
        self.stop_event.clear()

        # decide between category payloads or custom file
        use_custom = self.use_custom_payload.get()
        custom_file = self.custom_payload_path if use_custom else None
        selected_category = None

        # if not using custom, make sure a category is selected
        if not use_custom:
            selected = self.category_listbox.curselection()
            if not selected:
                messagebox.showwarning("No Category Selected", "Please select a category.")
                return
            selected_category = self.category_listbox.get(selected[0])

        # the actual scan logic runs in a thread so the GUI stays responsive
        def sqli_thread():
            with contextlib.redirect_stdout(None):
                if self.requires_login.get():
                    from modules.sqli.auth_scanner.auth_scanner import AuthScanner
                    scanner = AuthScanner(
                        target_url=url,
                        payload_dir=self.payload_dir,
                        categories_to_test=[selected_category] if selected_category else None,
                        credentials=credentials,
                        custom_payloads=None if not custom_file else self.load_custom_payloads(custom_file),
                        stop_event=self.stop_event,
                        progress_callback=self.update_progress,
                        anomaly_callback=self.anomaly_callback,
                        headless_mode=is_headless
                    )
                    scanner.start()
                else:
                    from modules.sqli.scanner import check_sql_injection
                    check_sql_injection(
                        url,
                        self.payload_dir,
                        categories_to_test=[selected_category] if selected_category else None,
                        custom_payload_file=custom_file,
                        stop_event=self.stop_event,
                        progress_callback=self.update_progress,
                        credentials_override=None,
                        anomaly_callback=self.anomaly_callback,
                        headless=is_headless
                    )

        self.clear_output()
        self.scan_thread = threading.Thread(target=sqli_thread)
        self.scan_thread.start()

    # load payloads from a custom file selected by the user
    def load_custom_payloads(self, file_path):
        try:
            with open(file_path, "r") as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.logger.error(f"Failed to load custom payloads: {e}")
            return []

    def update_progress(self, percentage, remaining, progress_str):
        self.last_eta_remaining = remaining
        self.last_eta_update_time = time.time()
        self.payload_progress = progress_str
        self.after(0, lambda: self.progress_var.set(percentage))

    def update_timer(self):
        if not self.scan_thread or not self.scan_thread.is_alive():
            self.reset_progress()
            self.after(1000, self.update_timer)
            return
        if self.last_eta_remaining is None or self.last_eta_update_time is None:
            self.after(1000, self.update_timer)
            return
        elapsed = time.time() - self.last_eta_update_time
        remaining = max(self.last_eta_remaining - elapsed, 0)
        formatted = time.strftime('%H:%M:%S', time.gmtime(remaining))
        self.progress_label.config(text=f"Payload: {self.payload_progress} - Remaining Time: {formatted}")
        self.after(1000, self.update_timer)

    def reset_progress(self):
        self.progress_var.set(0)
        self.progress_label.config(text="Payload: 0/0 - Remaining Time: 00:00:00")
        self.last_eta_remaining = None
        self.last_eta_update_time = None
        self.payload_progress = "0/0"

    def stop_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.stop_event.set()
            self.logger.info("Stop event triggered. Halting scan...")
            self.after(2000, self.reset_progress)
        else:
            self.logger.info("No active scan to stop.")

    def clear_output(self):
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.configure(state="disabled")

    def anomaly_callback(self, anomaly):
        self.logger.warning(
            f"Anomaly detected with payload: {anomaly.get('payload')} | Elapsed Time: {anomaly.get('elapsed_time', 0):.2f}s"
        )
        if self.email_alert_enabled and self.email_sender and self.email_password and self.email_recipient:
            self.send_email_alert(anomaly)

    def open_email_popup(self):
        popup = tk.Toplevel(self)
        popup.title("Configure Email Alerts")
        popup.geometry("400x350")

        ttk.Label(popup, text="Your Gmail Address:").pack(pady=5)
        sender_entry = ttk.Entry(popup, width=40)
        sender_entry.insert(0, self.email_sender or "")
        sender_entry.pack()

        ttk.Label(popup, text="Your App Password:").pack(pady=5)
        password_entry = ttk.Entry(popup, width=40, show="*")
        password_entry.insert(0, self.email_password or "")
        password_entry.pack()

        ttk.Label(popup, text="Recipient Email:").pack(pady=5)
        recipient_entry = ttk.Entry(popup, width=40)
        recipient_entry.insert(0, self.email_recipient or "")
        recipient_entry.pack()

        email_alert_var = tk.BooleanVar(value=self.email_alert_enabled)
        ttk.Checkbutton(popup, text="Enable Email Alerts", variable=email_alert_var).pack(pady=10)

        message_label = tk.Label(popup, text="", fg="red")
        message_label.pack()

        def save_credentials():
            sender = sender_entry.get().strip()
            password = password_entry.get().strip()
            recipient = recipient_entry.get().strip()
            if not self.validate_email(sender) or not self.validate_email(recipient):
                message_label.config(text="Please enter valid email addresses.", fg="red")
                return
            if len(password) < 12:
                message_label.config(text="Password must be at least 12 characters.", fg="red")
                return
            self.email_sender = sender
            self.email_password = password
            self.email_recipient = recipient
            self.email_alert_enabled = email_alert_var.get()
            message_label.config(text="Credentials saved successfully!", fg="green")
            popup.after(1200, popup.destroy)

        ttk.Button(popup, text="Save", command=save_credentials).pack(pady=20)

    def validate_email(self, email):
        return "@" in email and "." in email and email.index("@") < email.rindex(".") and " " not in email and len(email) >= 6

    def send_email_alert(self, anomaly):
        try:
            subject = "Kronos Alert: SQL Injection Anomaly Detected"
            body = f"Anomaly detected!\n\nPayload: {anomaly.get('payload')}\nElapsed Time: {anomaly.get('elapsed_time', 0):.2f}s"
            send_email_alert(subject, body, self.email_sender, self.email_password, self.email_recipient)
        except Exception as e:
            self.logger.error(f"Failed to send email: {e}")


# Example “main” stub
if __name__ == "__main__":
    root = tk.Tk()
    root.title("SQLi Scanner")
    root.geometry("950x470")

    root.resizable(True, False)

    gui = SqliGUI(root)
    gui.grid(sticky="nsew")
    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)

    root.mainloop()
