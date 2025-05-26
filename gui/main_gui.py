import tkinter as tk
from tkinter import ttk
from gui.crawler_gui import CrawlerGUI
from gui.sqli_gui import SqliGUI

def run_main_gui():
    root = tk.Tk()  #  main window
    root.configure(bg="#f0f0f0")  # background
    root.title("Kronos - Web Application Vulnerability Scanner")  # window title
    root.geometry("850x650")  # size of the window
    
    #  style of the interface
    style = ttk.Style()
    style.theme_use("clam")  # theme
    style.configure("TFrame", background="#f0f0f0")  # background for frames
    style.configure("TLabel", background="#f0f0f0", foreground="#333333", font=("Helvetica", 12))  # labels styling
    style.configure("TNotebook", background="#ffffff")  # background of the tab area
    style.configure("TNotebook.Tab", background="#e0e0e0", foreground="#333333", padding=[10, 5])  # tab look
    style.map("TNotebook.Tab", background=[("selected", "#007acc")], foreground=[("selected", "#ffffff")])  # active tab style
    style.configure("TButton", background="#007acc", foreground="#ffffff", padding=6)  # button styling
    style.configure("TEntry", fieldbackground="#ffffff", foreground="#333333", padding=5)  #input styling
    style.configure("Custom.Horizontal.TProgressbar",
                    troughcolor="#e0e0e0",
                    background="#007acc",
                    thickness=20)  # progress bar style, custom class used later maybe

    # creating the notebook (tabbed interface)
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)  # make it fill the window

    # create and attach the different modules / Later can be added more such as XSS etc..
    sqli_tab = SqliGUI(notebook)  # creating the SQLi module first
    crawler_tab = CrawlerGUI(notebook)  # then the crawler module

    # adding the modules to the tabs
    notebook.add(sqli_tab, text="SQL Injection")
    notebook.add(crawler_tab, text="Crawler")
    
    # prevent resizing, keeps layout from breaking (Still needs work but okay for now)
    root.update()
    root.minsize(root.winfo_width(), root.winfo_height())

    root.mainloop()  # run the GUI loop
