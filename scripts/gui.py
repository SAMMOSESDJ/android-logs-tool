import tkinter as tk
from tkinter import scrolledtext, ttk
import threading
from scripts.android_logs import get_logcat, get_call_logs, get_sms_logs, monitor_logs

# GUI Initialization
root = tk.Tk()
root.title("Android Forensic Tool - Cyber Edition")
root.geometry("900x600")
root.configure(bg="black")

# Fonts & Colors
FONT = ("Consolas", 10)
BG_COLOR = "black"
FG_COLOR = "lime"

# Tab Control
tab_control = ttk.Notebook(root)

# Extract Logs Tab
tab_extract = ttk.Frame(tab_control)
tab_control.add(tab_extract, text="Extract Logs")

# Live Monitoring Tab
tab_live = ttk.Frame(tab_control)
tab_control.add(tab_live, text="Live Monitoring")

# All Logs Tab
tab_all_logs = ttk.Frame(tab_control)
tab_control.add(tab_all_logs, text="All Logs")

# Logcat Logs Tab
tab_logcat = ttk.Frame(tab_control)
tab_control.add(tab_logcat, text="Logcat Logs")

# Filter Logs Tab
tab_filter = ttk.Frame(tab_control)
tab_control.add(tab_filter, text="Filter Logs")

tab_control.pack(expand=1, fill="both")

# Extract Logs Function
def extract_logs():
    threading.Thread(target=extraction_thread, daemon=True).start()

def extraction_thread():
    get_logcat()
    get_call_logs()
    get_sms_logs()
    output_text.insert(tk.END, "\n✅ Logs Extracted Successfully!\n")
    output_text.see(tk.END)

# Live Monitoring Function
def start_monitoring():
    threading.Thread(target=monitor_thread, daemon=True).start()

def monitor_thread():
    monitor_logs(lambda log: update_live_monitor(log))

def update_live_monitor(log):
    live_text.insert(tk.END, log + "\n")
    live_text.see(tk.END)

# Extract Logs Button
extract_button = tk.Button(tab_extract, text="Extract Logs", command=extract_logs, bg="gray", fg="black", font=FONT)
extract_button.pack(pady=10)

# Live Monitoring Text Box
live_text = scrolledtext.ScrolledText(tab_live, wrap=tk.WORD, width=100, height=30, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
live_text.pack(pady=10)

start_monitoring_button = tk.Button(tab_live, text="Start Live Monitoring", command=start_monitoring, bg="gray", fg="black", font=FONT)
start_monitoring_button.pack(pady=10)

# All Logs Display
all_logs_text = scrolledtext.ScrolledText(tab_all_logs, wrap=tk.WORD, width=100, height=30, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
all_logs_text.pack(pady=10)

# Logcat Logs Display
logcat_text = scrolledtext.ScrolledText(tab_logcat, wrap=tk.WORD, width=100, height=30, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
logcat_text.pack(pady=10)

# Filter Logs Section
filter_type_label = tk.Label(tab_filter, text="Log Type", bg=BG_COLOR, fg=FG_COLOR, font=FONT)
filter_type_label.pack(pady=5)
filter_type_combo = ttk.Combobox(tab_filter, values=["Logcat", "Calls", "SMS"])
filter_type_combo.pack(pady=5)

filter_time_label = tk.Label(tab_filter, text="Time Range", bg=BG_COLOR, fg=FG_COLOR, font=FONT)
filter_time_label.pack(pady=5)
filter_time_combo = ttk.Combobox(tab_filter, values=["Past 1 Hour", "Past 24 Hours", "Past 7 Days"])
filter_time_combo.pack(pady=5)

filter_keyword_entry = tk.Entry(tab_filter, width=50)
filter_keyword_entry.pack(pady=5)

apply_filter_button = tk.Button(tab_filter, text="Apply Filter", bg="gray", fg="black", font=FONT)
apply_filter_button.pack(pady=5)

filter_output = scrolledtext.ScrolledText(tab_filter, wrap=tk.WORD, width=100, height=30, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
filter_output.pack(pady=10)

# Log Output Text Box
output_text = scrolledtext.ScrolledText(tab_extract, wrap=tk.WORD, width=100, height=30, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
output_text.pack(pady=10)

# Run GUI
root.mainloop()
