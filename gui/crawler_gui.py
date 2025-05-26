import tkinter as tk
from tkinter import ttk, filedialog
import threading
import queue
import contextlib
from modules.crawler.crawler import start_crawler


# ─────────────────────────────────────────────────────────────────────
# Helper to redirect print() into the GUI’s text widget
# ─────────────────────────────────────────────────────────────────────
class Redirector:
    def __init__(self, text_widget, out_queue):
        self.text_widget = text_widget
        self.out_queue = out_queue

    def write(self, s):
        self.out_queue.put(s)

    def flush(self):
        pass


# ─────────────────────────────────────────────────────────────────────
# Crawler GUI
# ─────────────────────────────────────────────────────────────────────
class CrawlerGUI(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)

        self.queue = queue.Queue()
        self.crawler_thread = None
        self.stop_signal = threading.Event()
        self.wordlist_enabled = tk.BooleanVar(value=False)

        self.create_widgets()
        self.update_text_widget()

        # ────────── RESIZING TWEAKS ──────────
        # Let row 7 (the output terminal) expand, and let both columns
        # absorb horizontal stretch so the Text widget grows with the
        # window.
        self.grid_rowconfigure(7, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        # ─────────────────────────────────────

    # ---------------------------------------------------------------
    # Widget layout
    # ---------------------------------------------------------------
    def create_widgets(self):
        ttk.Label(self, text="Target URL:", font=("Helvetica", 12)).grid(
            row=0, column=0, padx=5, pady=5, sticky=tk.W
        )
        self.crawler_base_url = ttk.Entry(self, width=60, font=("Helvetica", 12))
        self.crawler_base_url.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.crawler_base_url.insert(0, "http://localhost")

        # Authentication options
        self.requires_auth = tk.BooleanVar(value=False)
        self.auth_checkbox = ttk.Checkbutton(
            self,
            text="Requires Authentication",
            variable=self.requires_auth,
            command=self.toggle_authentication_fields,
        )
        self.auth_checkbox.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)

        self.auth_type = tk.StringVar(value="automatic")
        self.auth_type_frame = ttk.Frame(self)
        self.auth_automatic = ttk.Radiobutton(
            self.auth_type_frame,
            text="Automatic Detection",
            variable=self.auth_type,
            value="automatic",
            command=self.toggle_login_url,
        )
        self.auth_direct = ttk.Radiobutton(
            self.auth_type_frame,
            text="Direct Login",
            variable=self.auth_type,
            value="direct",
            command=self.toggle_login_url,
        )
        self.auth_automatic.pack(side=tk.LEFT, padx=5)
        self.auth_direct.pack(side=tk.LEFT, padx=5)
        self.auth_type_frame.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

        # Credentials
        self.credentials_frame = ttk.Frame(self)
        self.credentials_frame.grid(
            row=2, column=0, columnspan=2, padx=5, pady=5, sticky=tk.W
        )
        ttk.Label(
            self.credentials_frame, text="Username:", font=("Helvetica", 12)
        ).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.username_entry = ttk.Entry(
            self.credentials_frame, width=25, font=("Helvetica", 12)
        )
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(
            self.credentials_frame, text="Password:", font=("Helvetica", 12)
        ).grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.password_entry = ttk.Entry(
            self.credentials_frame, width=25, font=("Helvetica", 12), show="*"
        )
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        self.login_url_label = ttk.Label(
            self.credentials_frame, text="Login URL:", font=("Helvetica", 12)
        )
        self.login_url_entry = ttk.Entry(
            self.credentials_frame, width=60, font=("Helvetica", 12)
        )

        self.toggle_authentication_fields()

        # Wordlist controls
        ttk.Label(self, text="Run Custom Wordlist:", font=("Helvetica", 12)).grid(
            row=3, column=0, padx=5, pady=5, sticky=tk.W
        )
        wordlist_frame = ttk.Frame(self)
        wordlist_frame.grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Checkbutton(
            wordlist_frame, variable=self.wordlist_enabled, command=self.toggle_wordlist_inputs
        ).pack(side=tk.LEFT)

        self.crawler_wordlist_entry = ttk.Entry(
            wordlist_frame, width=40, font=("Helvetica", 12), state="disabled"
        )
        self.crawler_wordlist_entry.pack(side=tk.LEFT, padx=(5, 0))

        self.crawler_wordlist_button = ttk.Button(
            wordlist_frame, text="Browse", command=self.browse_crawler_wordlist, state="disabled"
        )
        self.crawler_wordlist_button.pack(side=tk.LEFT, padx=(5, 0))

        # Headless checkbox
        self.headless_mode = tk.BooleanVar(value=False)
        ttk.Checkbutton(self, text="Headless Mode", variable=self.headless_mode).grid(
            row=4, column=0, padx=5, pady=5, sticky=tk.W
        )

        # Run button
        ttk.Button(self, text="Run Crawler", command=self.run_crawler).grid(
            row=5, column=0, columnspan=2, pady=(20, 10)
        )

        # Stop / Clear
        button_frame = ttk.Frame(self)
        button_frame.grid(row=6, column=0, columnspan=2, pady=(10, 10))
        ttk.Button(button_frame, text="Clear Output", command=self.clear_output).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(button_frame, text="Stop", command=self.stop_crawler).pack(
            side=tk.LEFT, padx=5
        )

        # Output terminal
        output_frame = ttk.Frame(self)
        output_frame.grid(
            row=7, column=0, columnspan=2, sticky="nsew", padx=10, pady=10
        )
        output_frame.grid_rowconfigure(0, weight=1)
        output_frame.grid_columnconfigure(0, weight=1)

        scrollbar = ttk.Scrollbar(output_frame)
        scrollbar.grid(row=0, column=1, sticky="ns")

        self.output_text = tk.Text(
            output_frame,
            wrap=tk.WORD,
            font=("Courier", 11),
            bg="#ffffff",
            fg="#333333",
            insertbackground="#007acc",
            yscrollcommand=scrollbar.set,
        )
        self.output_text.grid(row=0, column=0, sticky="nsew")
        scrollbar.config(command=self.output_text.yview)

        # Simple right-click copy/paste
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

    # ---------------------------------------------------------------
    # Toggle helpers
    # ---------------------------------------------------------------
    def toggle_wordlist_inputs(self):
        state = "normal" if self.wordlist_enabled.get() else "disabled"
        self.crawler_wordlist_entry.configure(state=state)
        self.crawler_wordlist_button.configure(state=state)

    def toggle_authentication_fields(self):
        if self.requires_auth.get():
            self.auth_type_frame.grid()
            self.credentials_frame.grid()
            self.toggle_login_url()
        else:
            self.auth_type_frame.grid_remove()
            self.credentials_frame.grid_remove()
            self.login_url_label.grid_remove()
            self.login_url_entry.grid_remove()

    def toggle_login_url(self):
        if self.auth_type.get() == "direct":
            self.login_url_label.grid(
                row=2, column=0, padx=5, pady=5, sticky=tk.W
            )
            self.login_url_entry.grid(
                row=2, column=1, padx=5, pady=5, sticky=tk.W
            )
        else:
            self.login_url_label.grid_remove()
            self.login_url_entry.grid_remove()

    # ---------------------------------------------------------------
    # File picker
    # ---------------------------------------------------------------
    def browse_crawler_wordlist(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            self.crawler_wordlist_entry.delete(0, tk.END)
            self.crawler_wordlist_entry.insert(0, file_path)

    # ---------------------------------------------------------------
    # Crawler thread
    # ---------------------------------------------------------------
    def run_crawler(self):
        base_url = self.crawler_base_url.get().strip()
        wordlist_file = (
            self.crawler_wordlist_entry.get().strip()
            if self.wordlist_enabled.get()
            else None
        )
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        requires_auth = self.requires_auth.get()
        auth_type = self.auth_type.get()
        login_url = self.login_url_entry.get().strip() if auth_type == "direct" else None
        headless = self.headless_mode.get()

        self.output_text.delete("1.0", tk.END)
        self.stop_signal.clear()

        def crawler_thread_function():
            with contextlib.redirect_stdout(Redirector(self.output_text, self.queue)):
                start_crawler(
                    base_url,
                    wordlist_file,
                    requires_authentication=requires_auth,
                    authentication_type=auth_type,
                    username=username,
                    password=password,
                    login_url=login_url,
                    stop_event=self.stop_signal,
                    headless=headless,
                )

        self.crawler_thread = threading.Thread(target=crawler_thread_function)
        self.crawler_thread.start()

    def stop_crawler(self):
        if self.crawler_thread and self.crawler_thread.is_alive():
            self.stop_signal.set()
            self.output_text.insert(tk.END, "\n[!] Stopping crawler...\n")
            self.output_text.see(tk.END)
        else:
            self.output_text.insert(tk.END, "\n[!] No active crawler to stop.\n")
            self.output_text.see(tk.END)

    def clear_output(self):
        self.output_text.delete("1.0", tk.END)

    # ---------------------------------------------------------------
    # Queue-driven live output
    # ---------------------------------------------------------------
    def update_text_widget(self):
        try:
            while True:
                line = self.queue.get_nowait()
                self.output_text.insert(tk.END, line)
                self.output_text.see(tk.END)
        except queue.Empty:
            pass
        self.after(100, self.update_text_widget)


# ─────────────────────────────────────────────────────────────────────
# Example “main” that keeps the window height fixed but lets it stretch
# sideways so the output terminal grows with it.
# ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Crawler")
    root.geometry("900x420")   # initial size

    # Width can change, height stays fixed
    root.resizable(True, False)

    gui = CrawlerGUI(root)
    gui.grid(sticky="nsew")
    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)

    root.mainloop()
