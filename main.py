import tkinter as tk
from tkinter import scrolledtext, ttk, filedialog, messagebox
import threading
from scripts.android_logs import get_logcat, get_call_logs, get_sms_logs, monitor_logs
from scripts.log_parser import filter_logs
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime, timedelta
from collections import Counter
import subprocess  # For ADB command execution
import time       # For sleep/delays
import queue      # For thread-safe communication
from collections import deque  # For efficient log buffering
import re
import pandas as pd
from fpdf import FPDF
import matplotlib.dates as mdates
import os
import json

# Add this right after your imports
monitoring_active = False
log_queue = queue.Queue()
monitoring_thread = None

# --- Add these lines after imports but before any other code ---
# Initialize required global variables
logcat_tabs = {}  # Dictionary for logcat tabs
graph_fig = None  # Figure object for graphs
graph_ax = None   # Axes object for graphs
BG_COLOR = "#ffffff"  # Or your preferred background color
BUTTON_COLOR = "#your_color"  # Define button colors
BUTTON_TEXT_COLOR = "#your_color"
TEXT_BG_COLOR = "#your_color"
TEXT_FG_COLOR = "#your_color"
FONT = ("Your Font", 10)  # Define your font
LOG_TYPES = {
    "Application": {
        "description": "Application-specific logs",
        "pattern": r'ActivityManager|PackageManager|ApplicationContext',
        "color": "blue"
    },
    "System": {
        "description": "System-level logs",
        "pattern": r'SystemServer|System\.err|SystemClock|SystemProperties',
        "color": "green"
    },
    "Crash": {
        "description": "Application crashes and exceptions",
        "pattern": r'FATAL|Exception|ANR|crash|force close|stacktrace',
        "color": "red"
    },
    "GC": {
        "description": "Garbage Collection events",
        "pattern": r'dalvikvm.*GC|art.*GC|GC_|collector',
        "color": "purple"
    },
    "Network": {
        "description": "Network activity logs",
        "pattern": r'ConnectivityManager|NetworkInfo|WifiManager|HttpURLConnection|socket|wifi|TCP|UDP|DNS',
        "color": "cyan"
    },
    "Broadcast": {
        "description": "Broadcast receivers and events",
        "pattern": r'BroadcastReceiver|sendBroadcast|onReceive|Intent.*broadcast',
        "color": "yellow"
    },
    "Service": {
        "description": "Service lifecycle events",
        "pattern": r'Service|startService|stopService|bindService|onBind',
        "color": "orange"
    },
    "Device": {
        "description": "Device state and hardware",
        "pattern": r'PowerManager|BatteryManager|sensor|hardware|camera|location|bluetooth|telephony',
        "color": "magenta"
    }
}

# Define all missing functions
def import_logs():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        messagebox.showinfo("Success", f"Imported logs from {file_path}")

def load_graph_tab(tab_name):
    global graph_fig, graph_ax
    messagebox.showinfo("Info", f"Loading graph for {tab_name} tab")

def load_logcat_type(log_type):
    file_path = f"logs/logcat_types/{log_type}_logs.txt"
    if os.path.exists(file_path):
        messagebox.showinfo("Loaded", f"{log_type} logs loaded")

def load_call_logs():
    if os.path.exists("logs/call_logs.txt"):
        messagebox.showinfo("Loaded", "Call logs loaded")

def load_sms_logs():
    if os.path.exists("logs/sms_logs.txt"):
        messagebox.showinfo("Loaded", "SMS logs loaded")
# --- End of additions ---

root = tk.Tk()
root.title("Android Forensic Tool - Advanced Cyber Edition")
root.geometry("950x650")
root.configure(bg="black")

FONT = ("Consolas", 10)
BG_COLOR = "black"
FG_COLOR = "lime"
TEXT_BG_COLOR = "black"
TEXT_FG_COLOR = "lime"
BUTTON_COLOR = "gray"
BUTTON_TEXT_COLOR = "black"

# Style configuration for ttk widgets
style = ttk.Style()
style.configure("TNotebook", background=BG_COLOR)
style.configure("TNotebook.Tab", background="gray", foreground="black", padding=[10, 2])
style.map("TNotebook.Tab", background=[("selected", "dark gray")])
style.configure("TFrame", background=BG_COLOR)

tab_control = ttk.Notebook(root)
tab_extract = ttk.Frame(tab_control)
tab_control.add(tab_extract, text="Extract Logs")
tab_live = ttk.Frame(tab_control)
live_text = scrolledtext.ScrolledText(tab_live, wrap=tk.WORD, font=("Courier", 10), bg="black", fg="white")
live_text.pack(fill=tk.BOTH, expand=True)
tab_control.add(tab_live, text="Live Monitoring")
tab_all_logs = ttk.Frame(tab_control)
tab_control.add(tab_all_logs, text="All Logs")
tab_logcat = ttk.Frame(tab_control)
tab_control.add(tab_logcat, text="Logcat Logs")
tab_logcat_types = ttk.Frame(tab_control)
tab_control.add(tab_logcat_types, text="Logcat Types")
tab_filter = ttk.Frame(tab_control)
tab_control.add(tab_filter, text="Filter Logs")
tab_graphs = ttk.Frame(tab_control)
tab_control.add(tab_graphs, text="Activity Graphs")
tab_control.pack(expand=1, fill="both")

# Initialize logcat tabs INSIDE tab_logcat_types
logcat_type_notebook = ttk.Notebook(tab_logcat_types)
logcat_type_notebook.pack(expand=1, fill="both")

# Initialize logcat_tabs dictionary with all log types
logcat_tabs = {}
logcat_type_texts = {}

print("LOG_TYPES type:", type(LOG_TYPES))
print("LOG_TYPES contents:", LOG_TYPES)
print("First key type:", type(next(iter(LOG_TYPES))) if LOG_TYPES else "Empty dictionary")

# Create tabs for each log type in LOG_TYPES
for log_type in LOG_TYPES:  # Direct iteration over dictionary keys
    # Create frame for each log type
    logcat_tabs[log_type] = ttk.Frame(logcat_type_notebook)
    logcat_type_notebook.add(logcat_tabs[log_type], text=log_type)
    
    # Add button frame
    button_frame = tk.Frame(logcat_tabs[log_type], bg=BG_COLOR)
    button_frame.pack(fill=tk.X, pady=5)
    
    # Add distribution button
    tk.Button(button_frame, text="Show Distribution", 
             bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR,
             command=lambda lt=log_type: plot_log_type_distribution(lt)
    ).pack(side=tk.LEFT, padx=10)
    
    # Add text widget
    text_widget = scrolledtext.ScrolledText(
        logcat_tabs[log_type],
        wrap=tk.WORD,
        width=100,
        height=30,
        bg=TEXT_BG_COLOR,
        fg=TEXT_FG_COLOR,
        font=FONT
    )
    text_widget.pack(fill=tk.BOTH, expand=True, pady=5)
    logcat_type_texts[log_type] = text_widget

# Continue with your existing text widgets...
output_text = scrolledtext.ScrolledText(tab_extract, wrap=tk.WORD, width=100, height=10, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
output_text.pack(fill=tk.BOTH, expand=True, pady=5)

live_text = scrolledtext.ScrolledText(tab_live, wrap=tk.WORD, width=100, height=30, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
live_text.pack(fill=tk.BOTH, expand=True, pady=5)

all_logs_text = scrolledtext.ScrolledText(tab_all_logs, wrap=tk.WORD, width=100, height=30, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
all_logs_text.pack(fill=tk.BOTH, expand=True, pady=5)

logcat_text = scrolledtext.ScrolledText(tab_logcat, wrap=tk.WORD, width=100, height=30, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
logcat_text.pack(fill=tk.BOTH, expand=True, pady=5)

# Buttons for each tab
extract_button = tk.Button(tab_extract, text="Extract Logs", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR, command=lambda: extract_logs())
extract_button.pack(pady=5)


# Filters: Time Range + Log Type for Graphs
graph_filter_frame = tk.Frame(tab_graphs, bg="black")
graph_filter_frame.pack(pady=10)

tk.Label(graph_filter_frame, text="Select Time Range:", bg="black", fg="lime").grid(row=0, column=0, padx=5)
graph_time_combo = ttk.Combobox(graph_filter_frame, values=["Past 1 Hour", "Past 24 Hours", "Past 7 Days", "All Time"])
graph_time_combo.set("Past 24 Hours")
graph_time_combo.grid(row=0, column=1, padx=5)

tk.Label(graph_filter_frame, text="Log Type:", bg="black", fg="lime").grid(row=0, column=2, padx=5)
# Enhanced graph types with the new logcat categories
graph_types = ["Call Logs", "SMS Logs", "Top SMS Senders", "Logcat Activity"] + list(LOG_TYPES.keys())
graph_type_combo = ttk.Combobox(graph_filter_frame, values=graph_types)
graph_type_combo.set("Call Logs")
graph_type_combo.grid(row=0, column=3, padx=5)

graph_button = tk.Button(graph_filter_frame, text="Generate Graph", bg="gray", fg="black", command=lambda: plot_graph())
graph_button.grid(row=0, column=4, padx=10)

# Add this button for Most Frequent Callers
freq_button = tk.Button(graph_filter_frame, text="Most Frequent Callers", bg="gray", fg="black", command=lambda: plot_frequent_callers())
freq_button.grid(row=0, column=5, padx=10)

# Placeholder for matplotlib chart
graph_fig, graph_ax = plt.subplots(figsize=(7, 4))
graph_canvas = FigureCanvasTkAgg(graph_fig, master=tab_graphs)
graph_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, pady=10)

# Create notebook for different logcat types
logcat_type_notebook = ttk.Notebook(tab_logcat_types)
logcat_type_notebook.pack(expand=1, fill="both")

# Create tabs for each logcat type
logcat_type_tabs = {}
logcat_type_texts = {}

for log_type in LOG_TYPES:
    tab = ttk.Frame(logcat_type_notebook)
    logcat_type_tabs[log_type] = tab
    logcat_type_notebook.add(tab, text=log_type)
    
    # Add scrolled text widget for each tab
    text_widget = scrolledtext.ScrolledText(tab, wrap=tk.WORD, width=100, height=30, bg=BG_COLOR, fg=FG_COLOR, font=FONT)
    text_widget.pack(fill=tk.BOTH, expand=True, pady=5)
    logcat_type_texts[log_type] = text_widget

def extract_logs():
    """Extract logs and display them in the output text widget."""
    threading.Thread(target=extraction_thread, daemon=True).start()

def extraction_thread():
    output_text.insert(tk.END, "⌛ Extracting logs, please wait...\n")
    output_text.see(tk.END)
    
    # Get standard logs
    get_logcat()
    get_call_logs()
    get_sms_logs()

    # Process logcat logs into different types
    try:
        categorize_logcat_logs()
    except Exception as e:
        output_text.insert(tk.END, f"⚠️ Error categorizing logcat logs: {str(e)}\n")

    # Load Logcat Logs
    try:
        with open("logs/android_logcat.txt", "r", encoding="utf-8", errors="replace") as f:
            logcat_text.delete(1.0, tk.END)
            logcat_text.insert(tk.END, f.read())
    except FileNotFoundError:
        logcat_text.insert(tk.END, "⚠️ Logcat file not found.\n")

    # Load All Logs
    all_logs_text.delete(1.0, tk.END)
    log_files = [("Logcat", "logs/android_logcat.txt"),
                 ("Calls", "logs/call_logs.txt"),
                 ("SMS", "logs/sms_logs.txt")]
    
    for log_name, path in log_files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                all_logs_text.insert(tk.END, f"\n===== {log_name} =====\n")
                all_logs_text.insert(tk.END, f.read())
        except FileNotFoundError:
            all_logs_text.insert(tk.END, f"\n⚠️ {log_name} log file not found.\n")

    output_text.insert(tk.END, "✅ Logs Extracted Successfully!\n")
    output_text.see(tk.END)

def categorize_logcat_logs():
    """Categorize logcat logs into different types based on patterns"""
    try:
        # Ensure logs directory exists
        os.makedirs("logs/logcat_types", exist_ok=True)
        
        # Clear previous categorized logs
        for log_type in LOG_TYPES:
            with open(f"logs/logcat_types/{log_type.lower()}_logs.txt", "w", encoding="utf-8") as f:
                f.write(f"=== {log_type} Logs ===\n\n")
        
        # Process main logcat file
        try:
            with open("logs/android_logcat.txt", "r", encoding="utf-8", errors="replace") as f:
                logcat_lines = f.readlines()
        except FileNotFoundError:
            output_text.insert(tk.END, "⚠️ Logcat file not found for categorization.\n")
            return
        
        # Clear text widgets for each log type
        for log_type in LOG_TYPES:
            logcat_type_texts[log_type].delete(1.0, tk.END)
        
        # Process each line and categorize
        for line in logcat_lines:
            for log_type, info in LOG_TYPES.items():
                if re.search(info["pattern"], line, re.IGNORECASE):
                    # Append to type-specific file
                    with open(f"logs/logcat_types/{log_type.lower()}_logs.txt", "a", encoding="utf-8") as f:
                        f.write(line)
                    
                    # Update text widget
                    logcat_type_texts[log_type].insert(tk.END, line)
        
        output_text.insert(tk.END, "✅ Logcat logs successfully categorized by type!\n")
    except Exception as e:
        output_text.insert(tk.END, f"❌ Error during log categorization: {str(e)}\n")
        raise e

def start_monitoring():
    """Start the monitoring thread with proper error handling"""
    if not hasattr(start_monitoring, '_thread') or not start_monitoring._thread.is_alive():
        start_monitoring._thread = threading.Thread(target=monitor_thread, daemon=True)
        start_monitoring._thread.start()
        update_live_monitor("🔍 Starting live monitoring...\n")
    else:
        update_live_monitor("⚠️ Monitoring is already running\n")

def monitor_thread():
    """Main monitoring thread with enhanced error handling"""
    try:
        def handle_log(log):
            # Queue log updates for thread-safe UI updates
            log_queue.put(('update', log))
            
            # Categorize logs
            for log_type, info in LOG_TYPES.items():
                if re.search(info["pattern"], log, re.IGNORECASE):
                    log_queue.put(('categorize', (log_type, log)))
        
        # Start the actual monitoring
        monitor_logs(handle_log)
        
    except Exception as e:
        log_queue.put(('error', f"Monitoring error: {str(e)}"))
    finally:
        log_queue.put(('status', "Monitoring stopped"))

def update_live_monitor(log):
    """Thread-safe UI updates"""
    def _update():
        live_text.config(state=tk.NORMAL)
        live_text.insert(tk.END, log)
        live_text.see(tk.END)
        
        # Limit log size
        if int(live_text.index('end-1c').split('.')[0]) > 1000:
            live_text.delete(1.0, "100.0")
            
        live_text.config(state=tk.DISABLED)
    
    root.after(0, _update)

def process_log_queue():
    """Process all queued log entries"""
    while not log_queue.empty():
        entry_type, data = log_queue.get_nowait()
        
        if entry_type == 'update':
            update_live_monitor(data + "\n")
        elif entry_type == 'categorize':
            log_type, log = data
            text_widget = logcat_type_texts.get(log_type)
            if text_widget:
                text_widget.config(state=tk.NORMAL)
                text_widget.insert(tk.END, log + "\n")
                text_widget.see(tk.END)
                text_widget.config(state=tk.DISABLED)
                
                # Append to file
                try:
                    os.makedirs("logs/logcat_types", exist_ok=True)
                    with open(f"logs/logcat_types/{log_type.lower()}_logs.txt", "a", encoding="utf-8") as f:
                        f.write(log + "\n")
                except Exception as e:
                    print(f"Error saving log: {e}")
        elif entry_type == 'error':
            messagebox.showerror("Monitoring Error", data)
        elif entry_type == 'status':
            update_live_monitor(f"⭐ {data}\n")
    
    root.after(100, process_log_queue)  # Continue processing

def plot_graph():
    log_type = graph_type_combo.get()
    time_range = graph_time_combo.get()
    
    # Function to extract timestamps from log files
    def get_timestamps_from_file(filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except FileNotFoundError:
            return None, []
        
        timestamps = []
        all_lines = []
        
        for line in lines:
            # Try to find standard datetime format
            date_match = re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', line)
            if date_match:
                try:
                    ts = datetime.strptime(date_match.group(), "%Y-%m-%d %H:%M:%S")
                    timestamps.append(ts)
                    all_lines.append(line)
                    continue
                except:
                    pass
            
            # Try unix timestamp format
            unix_match = re.search(r'date=(\d+)', line)
            if unix_match:
                try:
                    ts = datetime.fromtimestamp(int(unix_match.group(1)) / 1000)
                    timestamps.append(ts)
                    all_lines.append(line)
                except:
                    pass
                
            # Try logcat timestamp format
            logcat_match = re.search(r'(\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
            if logcat_match:
                try:
                    today = datetime.now()
                    date_str = f"{today.year}-{logcat_match.group(1)}"
                    ts = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                    # Handle year boundary
                    if ts > today:
                        ts = ts.replace(year=today.year - 1)
                    timestamps.append(ts)
                    all_lines.append(line)
                except:
                    pass
        
        return all_lines, timestamps

    # Apply time filter based on selected range
    now = datetime.now()
    def apply_time_filter(timestamps, lines):
        filtered_timestamps = []
        filtered_lines = []
        
        for i, ts in enumerate(timestamps):
            include = False
            
            if time_range == "Past 1 Hour" and now - ts <= timedelta(hours=1):
                include = True
            elif time_range == "Past 24 Hours" and now - ts <= timedelta(hours=24):
                include = True
            elif time_range == "Past 7 Days" and now - ts <= timedelta(days=7):
                include = True
            elif time_range == "All Time":
                include = True
                
            if include:
                filtered_timestamps.append(ts)
                filtered_lines.append(lines[i])
                
        return filtered_timestamps, filtered_lines

    # Clear the previous graph
    graph_ax.clear()

    # Generate graphs based on log type
    if log_type in ["Call Logs", "SMS Logs"]:
        path = "logs/call_logs.txt" if log_type == "Call Logs" else "logs/sms_logs.txt"
        lines, timestamps = get_timestamps_from_file(path)
        
        if lines is None or not lines:
            graph_ax.text(0.5, 0.5, f"{log_type} file not found or empty", fontsize=14, ha='center')
            graph_canvas.draw()
            return

        timestamps, lines = apply_time_filter(timestamps, lines)
        
        if not timestamps:
            graph_ax.text(0.5, 0.5, "No data in selected time range", fontsize=12, ha='center')
            graph_canvas.draw()
            return

        # Aggregate data by hour
        activity_per_hour = {}
        for ts in timestamps:
            hour = ts.replace(minute=0, second=0, microsecond=0)
            activity_per_hour[hour] = activity_per_hour.get(hour, 0) + 1

        sorted_times = sorted(activity_per_hour.keys())
        counts = [activity_per_hour[t] for t in sorted_times]

        # Plot the time series graph
        graph_ax.plot(sorted_times, counts, marker="o", color="lime", linewidth=2)
        graph_ax.set_title(f"{log_type} Activity Over Time", color="lime", fontsize=12)
        graph_ax.set_ylabel("Count", color="lime")
        graph_ax.set_xlabel("Time", color="lime")
        graph_ax.tick_params(axis='x', colors='lime')
        graph_ax.tick_params(axis='y', colors='lime')
        graph_ax.grid(True, alpha=0.3)
        
        # Format x-axis dates properly
        graph_ax.xaxis.set_major_formatter(mdates.DateFormatter('%m-%d %H:%M'))
        graph_fig.autofmt_xdate()

    elif log_type == "Top SMS Senders":
        lines, timestamps = get_timestamps_from_file("logs/sms_logs.txt")
        
        if lines is None or not lines:
            graph_ax.text(0.5, 0.5, "SMS log file not found or empty", fontsize=14, ha='center')
            graph_canvas.draw()
            return

        timestamps, lines = apply_time_filter(timestamps, lines)
        
        if not timestamps:
            graph_ax.text(0.5, 0.5, "No data in selected time range", fontsize=12, ha='center')
            graph_canvas.draw()
            return

        # Extract sender phone numbers
        senders = []
        for line in lines:
            match = re.search(r'from: (\+?\d+)', line)
            if match:
                senders.append(match.group(1))

        if not senders:
            graph_ax.text(0.5, 0.5, "No sender data found in logs", fontsize=12, ha='center')
            graph_canvas.draw()
            return

        # Count most frequent senders
        counter = Counter(senders)
        top_senders = counter.most_common(10)
        labels = [s[0] for s in top_senders]
        counts = [s[1] for s in top_senders]

        # Create horizontal bar chart
        bars = graph_ax.barh(labels[::-1], counts[::-1], color="lime")
        graph_ax.set_title("Top 10 SMS Senders", color="lime", fontsize=12)
        graph_ax.set_xlabel("Number of Messages", color="lime")
        graph_ax.tick_params(axis='x', colors='lime')
        graph_ax.tick_params(axis='y', colors='lime')
        graph_ax.grid(True, axis='x', alpha=0.3)
        
        # Add count values at the end of each bar
        for i, bar in enumerate(bars):
            width = bar.get_width()
            graph_ax.text(width + 0.3, bar.get_y() + bar.get_height()/2, 
                         str(int(width)), ha='left', va='center', color='lime')

    elif log_type == "Logcat Activity":
        lines, timestamps = get_timestamps_from_file("logs/android_logcat.txt")
        
        if lines is None or not lines:
            graph_ax.text(0.5, 0.5, "Logcat file not found or empty", fontsize=14, ha='center')
            graph_canvas.draw()
            return

        timestamps, lines = apply_time_filter(timestamps, lines)
        
        if not timestamps:
            graph_ax.text(0.5, 0.5, "No logcat activity in selected time range", fontsize=12, ha='center')
            graph_canvas.draw()
            return

        # Aggregate data by hour
        activity_per_hour = {}
        for ts in timestamps:
            hour = ts.replace(minute=0, second=0, microsecond=0)
            activity_per_hour[hour] = activity_per_hour.get(hour, 0) + 1

        sorted_times = sorted(activity_per_hour.keys())
        counts = [activity_per_hour[t] for t in sorted_times]

        # Plot time series graph
        graph_ax.plot(sorted_times, counts, marker="o", linestyle="-", color="lime", linewidth=2)
        graph_ax.set_title("Logcat Activity Over Time", color="lime", fontsize=12)
        graph_ax.set_ylabel("Number of Entries", color="lime")
        graph_ax.set_xlabel("Time", color="lime")
        graph_ax.tick_params(axis='x', colors='lime')
        graph_ax.tick_params(axis='y', colors='lime')
        graph_ax.grid(True, alpha=0.3)
        
        # Format x-axis dates properly
        graph_ax.xaxis.set_major_formatter(mdates.DateFormatter('%m-%d %H:%M'))
        graph_fig.autofmt_xdate()
    
    # Handle specialized logcat type graphs
    elif log_type in LOG_TYPES:
        # Get the color for this log type
        log_color = LOG_TYPES[log_type]["color"] if log_type in LOG_TYPES else "lime"
        
        # Get the file path for this log type
        filepath = f"logs/logcat_types/{log_type.lower()}_logs.txt"
        
        # Get timestamps from file
        lines, timestamps = get_timestamps_from_file(filepath)
        
        if lines is None or not timestamps:
            graph_ax.text(0.5, 0.5, f"No {log_type} logs found", fontsize=14, ha='center')
            graph_canvas.draw()
            return
            
        # Apply time filter
        timestamps, lines = apply_time_filter(timestamps, lines)
        
        if not timestamps:
            graph_ax.text(0.5, 0.5, f"No {log_type} logs in selected time range", fontsize=12, ha='center')
            graph_canvas.draw()
            return
            
        # For specialized log types, show two graphs:
        # 1. Activity over time
        # 2. Distribution of subtypes (if applicable)
        
        # Activity over time (primary graph)
        activity_per_hour = {}
        for ts in timestamps:
            hour = ts.replace(minute=0, second=0, microsecond=0)
            activity_per_hour[hour] = activity_per_hour.get(hour, 0) + 1
            
        sorted_times = sorted(activity_per_hour.keys())
        counts = [activity_per_hour[t] for t in sorted_times]
        
        # Plot the time series
        graph_ax.plot(sorted_times, counts, marker="o", color=log_color, linewidth=2)
        graph_ax.set_title(f"{log_type} Activity Over Time", color="lime", fontsize=12)
        graph_ax.set_ylabel("Count", color="lime")
        graph_ax.set_xlabel("Time", color="lime")
        graph_ax.tick_params(axis='x', colors='lime')
        graph_ax.tick_params(axis='y', colors='lime')
        graph_ax.grid(True, alpha=0.3)
        
        # Format x-axis dates properly
        graph_ax.xaxis.set_major_formatter(mdates.DateFormatter('%m-%d %H:%M'))
        graph_fig.autofmt_xdate()

    # Apply dark theme to the graph figure
    graph_fig.patch.set_facecolor('#121212')
    graph_ax.set_facecolor('#1e1e1e')
    
    # Draw the updated graph
    graph_canvas.draw()

def plot_frequent_callers():
    try:
        with open("logs/call_logs.txt", "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except FileNotFoundError:
        graph_ax.clear()
        graph_ax.text(0.5, 0.5, "Call log file not found", fontsize=14, ha='center')
        graph_canvas.draw()
        return
    
    # Apply time filter
    time_range = graph_time_combo.get()
    now = datetime.now()
    
    filtered_lines = []
    for line in lines:
        date_match = re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', line)
        unix_match = re.search(r'date=(\d+)', line)
        
        include = False
        if date_match:
            try:
                ts = datetime.strptime(date_match.group(), "%Y-%m-%d %H:%M:%S")
                if (time_range == "Past 1 Hour" and now - ts <= timedelta(hours=1)) or \
                   (time_range == "Past 24 Hours" and now - ts <= timedelta(hours=24)) or \
                   (time_range == "Past 7 Days" and now - ts <= timedelta(days=7)) or \
                   (time_range == "All Time"):
                    include = True
            except:
                pass
        elif unix_match:
            try:
                ts = datetime.fromtimestamp(int(unix_match.group(1)) / 1000)
                if (time_range == "Past 1 Hour" and now - ts <= timedelta(hours=1)) or \
                   (time_range == "Past 24 Hours" and now - ts <= timedelta(hours=24)) or \
                   (time_range == "Past 7 Days" and now - ts <= timedelta(days=7)) or \
                   (time_range == "All Time"):
                    include = True
            except:
                pass
        
        if include or time_range == "All Time":
            filtered_lines.append(line)
    
    if not filtered_lines:
        graph_ax.clear()
        graph_ax.text(0.5, 0.5, "No call data in selected time range", fontsize=12, ha='center')
        graph_canvas.draw()
        return
    
    # Extract phone numbers
    numbers = []
    for line in filtered_lines:
        # Look for phone numbers in the line
        matches = re.findall(r'(?:number:|to:|from:)\s*(\+?\d{7,15})', line)
        if matches:
            numbers.extend(matches)
        else:
            # Try the general phone number pattern
            matches = re.findall(r'(\+?\d{7,15})', line)
            numbers.extend(matches)

    if not numbers:
        graph_ax.clear()
        graph_ax.text(0.5, 0.5, "No phone numbers found in logs", fontsize=12, ha='center')
        graph_canvas.draw()
        return

    # Count frequencies and get top callers
    counter = Counter(numbers)
    top_callers = counter.most_common(10)
    labels = [x[0] for x in top_callers]
    counts = [x[1] for x in top_callers]

    # Create the bar chart
    graph_ax.clear()
    bars = graph_ax.barh(labels[::-1], counts[::-1], color="lime")
    graph_ax.set_title("Top 10 Frequent Callers", color="lime", fontsize=12)
    graph_ax.set_xlabel("Number of Calls", color="lime")
    graph_ax.tick_params(axis='x', colors='lime')
    graph_ax.tick_params(axis='y', colors='lime')
    graph_ax.grid(True, axis='x', alpha=0.3)
    
    # Add count values at the end of each bar
    for i, bar in enumerate(bars):
        width = bar.get_width()
        graph_ax.text(width + 0.3, bar.get_y() + bar.get_height()/2, 
                     str(int(width)), ha='left', va='center', color='lime')
    
    # Apply dark theme
    graph_fig.patch.set_facecolor('#121212')
    graph_ax.set_facecolor('#1e1e1e')
    
    # Draw the updated graph
    graph_canvas.draw()

def create_log_distribution_chart(log_type):
    """Create a distribution chart for a specific logcat type showing subtypes"""
    try:
        filepath = f"logs/logcat_types/{log_type.lower()}_logs.txt"
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            
        if not lines:
            return None
            
        # For each log type, define specific patterns to look for
        patterns = {}
        if log_type == "Application":
            patterns = {
                "Activity": r'Activity|startActivity',
                "Fragment": r'Fragment',
                "View": r'View|Inflate',
                "Lifecycle": r'onCreate|onStart|onResume|onPause|onStop|onDestroy',
                "Other": r'.*'  # Catch-all
            }
        elif log_type == "System":
            patterns = {
                "Boot": r'boot|start up|startup|starting',
                "Memory": r'memory|heap|ram',
                "CPU": r'cpu|processor',
                "Battery": r'battery|power',
                "Other": r'.*'  # Catch-all
            }
        elif log_type == "Crash":
            patterns = {
                "NullPointer": r'NullPointerException',
                "OutOfMemory": r'OutOfMemoryError',
                "IllegalState": r'IllegalStateException',
                "ANR": r'ANR|Not Responding',
                "Other": r'.*'  # Catch-all
            } 
        elif log_type == "Network":
            patterns = {
                "WiFi": r'wifi|wlan',
                "Mobile": r'mobile|cellular|data connection',
                "HTTP": r'http|https|URL',
                "Socket": r'socket|tcp|udp',
                "Other": r'.*'  # Catch-all
            }
        else:
            # Generic pattern for other log types
            patterns = {
                "Error": r'error|exception|fail',
                "Warning": r'warn|warning',
                "Info": r'info|information',
                "Debug": r'debug',
                "Other": r'.*'  # Catch-all
            }
            
        # Count occurrences
        counts = {pattern: 0 for pattern in patterns}
        for line in lines:
            for pattern_name, pattern in patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    counts[pattern_name] += 1
                    # Only count for the first matching pattern unless it's Other
                    if pattern_name != "Other":
                        break
                        
        # Create distribution chart
        labels = list(counts.keys())
        values = list(counts.values())
        
        # Create a new figure
        dist_fig, dist_ax = plt.subplots(figsize=(6, 4))
        dist_ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=90, 
                   colors=plt.cm.tab10.colors[:len(labels)])
        dist_ax.set_title(f"{log_type} Log Distribution")
        
        # Return the figure
        return dist_fig
    except Exception as e:
        print(f"Error creating distribution chart for {log_type}: {e}")
        return None
def process_logs_for_type(log_type):
    """Process logs for the specified log type and return a list of log entries"""
    try:
        # Get the text widget content for this log type
        text_widget = logcat_type_texts.get(log_type)
        if not text_widget:
            return []
            
        # Get all text from the widget
        log_content = text_widget.get("1.0", tk.END)
        
        # Split into lines and filter empty lines
        log_lines = [line.strip() for line in log_content.split('\n') if line.strip()]
        
        # Get the regex pattern for this log type
        pattern = LOG_TYPES[log_type]["pattern"]
        
        # Filter lines that match the pattern
        matching_lines = [line for line in log_lines if re.search(pattern, line, re.IGNORECASE)]
        
        # Extract relevant components (modify as needed)
        processed_logs = []
        for line in matching_lines:
            # Example: Extract the first word as the log component
            component = line.split()[0] if line.split() else "Unknown"
            processed_logs.append(component)
            
        return processed_logs
        
    except Exception as e:
        print(f"Error processing logs for {log_type}: {str(e)}")
        return []
def plot_log_type_distribution(log_type):
    """Create a distribution chart window for a specific log type"""
    def create_log_distribution_chart(log_type):
        # Sample data - replace with your actual log processing
        log_data = process_logs_for_type(log_type)  # Implement this function
        if not log_data:
            return None
            
        counter = Counter(log_data)
        if len(counter) < 1:
            return None

        # Create figure with better layout
        fig, ax = plt.subplots(figsize=(8, 6))
        fig.subplots_adjust(left=0.1, right=0.85)
        
        # Prepare data (group small slices into 'Other')
        threshold = 5  # percentage threshold
        total = sum(counter.values())
        filtered = {k: v for k, v in counter.items() if v/total*100 >= threshold}
        other = sum(v for k, v in counter.items() if v/total*100 < threshold)
        
        if other > 0:
            filtered['Other'] = other
            
        # Sort by value descending
        filtered = dict(sorted(filtered.items(), key=lambda item: item[1], reverse=True))
        
        # Create pie chart with better spacing
        wedges, texts, autotexts = ax.pie(
            filtered.values(),
            labels=filtered.keys(),
            autopct=lambda p: f'{p:.1f}%' if p >= threshold else '',
            startangle=90,
            pctdistance=0.8,
            textprops={'fontsize': 9, 'color': 'white'},
            wedgeprops={'linewidth': 1, 'edgecolor': 'black'},
            rotatelabels=True  # Rotate labels to prevent overlap
        )
        
        # Improve label positioning
        for text in texts:
            text.set_horizontalalignment('center')
            text.set_rotation_mode('anchor')
            
        # Equal aspect ratio
        ax.axis('equal')
        
        # Style adjustments
        ax.set_title(f'{log_type} Log Distribution', color='white', pad=20)
        fig.patch.set_facecolor('black')
        ax.set_facecolor('black')
        
        return fig

    dist_fig = create_log_distribution_chart(log_type)
    if dist_fig:
        # Create a new toplevel window
        dist_window = tk.Toplevel(root)
        dist_window.title(f"{log_type} Log Distribution")
        dist_window.geometry("700x600")  # Slightly larger window
        dist_window.configure(bg="black")
        
        # Add the figure to the window
        canvas = FigureCanvasTkAgg(dist_fig, master=dist_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add an export button
        export_frame = tk.Frame(dist_window, bg="black")
        export_frame.pack(pady=10)
        
        tk.Button(export_frame, text="Export as PNG", bg="gray", fg="black",
                 command=lambda: export_chart(dist_fig, f"{log_type.lower()}_distribution.png")
                 ).pack(side=tk.LEFT, padx=10)
        
        tk.Button(export_frame, text="Export as PDF", bg="gray", fg="black",
                 command=lambda: export_chart(dist_fig, f"{log_type.lower()}_distribution.pdf")
                 ).pack(side=tk.LEFT, padx=10)
        
        # Add a close button
        tk.Button(export_frame, text="Close", bg="gray", fg="black",
                 command=dist_window.destroy).pack(side=tk.RIGHT, padx=10)
    else:
        messagebox.showerror("Error", f"No data available for {log_type} distribution")
def export_chart(fig, filename):
    """Export a figure to a file"""
    try:
        # Create logs directory if it doesn't exist
        os.makedirs("logs/exports", exist_ok=True)
        filepath = os.path.join("logs/exports", filename)
        
        # Save the figure
        fig.savefig(filepath, dpi=300, bbox_inches='tight')
        messagebox.showinfo("Export Successful", f"Chart exported to {filepath}")
    except Exception as e:
        messagebox.showerror("Export Failed", f"Failed to export chart: {str(e)}")

def export_graph_data(format_type):
    """Export the currently displayed graph to CSV or PDF"""
    try:
        log_type = graph_type_combo.get()
        data = []

        if graph_ax.lines:  # For line charts like Call Logs, SMS Logs, Logcat
            x_data = graph_ax.lines[0].get_xdata()
            y_data = graph_ax.lines[0].get_ydata()
            data = list(zip(x_data, y_data))

        elif graph_ax.patches:  # For bar charts like Top SMS Senders
            bars = graph_ax.patches
            y_labels = [bar.get_y() + bar.get_height()/2 for bar in bars]
            values = [bar.get_width() for bar in bars]
            labels = [bar.get_label() if hasattr(bar, 'get_label') else "" for bar in bars]
            tick_labels = [tick.get_text() for tick in graph_ax.get_yticklabels()]
            data = list(zip(tick_labels[::-1], values[::-1]))

        if not data:
            messagebox.showwarning("Export Warning", "No graph data to export.")
            return

        # Create exports directory if it doesn't exist
        os.makedirs("logs/exports", exist_ok=True)

        # Format timestamp for filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format_type == "csv":
            df = pd.DataFrame(data, columns=["Label/Time", "Count"])
            filepath = f"logs/exports/graph_export_{timestamp}.csv"
            df.to_csv(filepath, index=False)
            messagebox.showinfo("Export Successful", f"Data exported to {filepath}")
        
        elif format_type == "pdf":
            filepath = f"logs/exports/graph_export_{timestamp}.pdf"
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            pdf.cell(200, 10, txt=f"{log_type} - Graph Export", ln=True, align='C')
            pdf.cell(200, 10, txt=f"Time Range: {graph_time_combo.get()}", ln=True)
            pdf.cell(200, 10, txt=f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
            pdf.ln(10)
            
            # Create data table
            pdf.set_font("Arial", 'B', size=10)
            pdf.cell(100, 10, txt="Time/Label", border=1)
            pdf.cell(50, 10, txt="Count", border=1)
            pdf.ln()
            
            pdf.set_font("Arial", size=10)
            for i, (label, count) in enumerate(data):
                # Format the label/time
                if isinstance(label, datetime):
                    label_str = label.strftime('%Y-%m-%d %H:%M')
                else:
                    label_str = str(label)
                
                # Add a row to the table
                pdf.cell(100, 10, txt=label_str, border=1)
                pdf.cell(50, 10, txt=str(count), border=1)
                pdf.ln()
            
            # Save the PDF
            pdf.output(filepath)
            messagebox.showinfo("Export Successful", f"Report exported to {filepath}")
    
    except Exception as e:
        messagebox.showerror("Export Failed", f"Failed to export data: {str(e)}")

def export_full_report():
    """Generate a comprehensive report with all log analysis"""
    try:
        # Create exports directory if it doesn't exist
        os.makedirs("logs/exports", exist_ok=True)
        
        # Format timestamp for filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = f"logs/exports/forensic_report_{timestamp}.pdf"
        
        pdf = FPDF()
        
        # Add a cover page
        pdf.add_page()
        pdf.set_font("Arial", 'B', size=24)
        pdf.cell(200, 40, txt="Android Forensic Analysis Report", ln=True, align='C')
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt=f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
        pdf.ln(20)
        
        # Add device information if available
        try:
            # Try to get basic device info from logcat
            device_info = {
                "Device Model": "Unknown",
                "Android Version": "Unknown",
                "Kernel Version": "Unknown"
            }
            
            with open("logs/android_logcat.txt", "r", encoding="utf-8", errors="replace") as f:
                logs = f.read()
                # Look for device model
                model_match = re.search(r'model=([^,\s]+)', logs)
                if model_match:
                    device_info["Device Model"] = model_match.group(1)
                
                # Look for Android version
                version_match = re.search(r'Android\s+(\d+(\.\d+)*)', logs)
                if version_match:
                    device_info["Android Version"] = version_match.group(1)
                
                # Look for kernel version
                kernel_match = re.search(r'Linux\s+version\s+([^\s]+)', logs)
                if kernel_match:
                    device_info["Kernel Version"] = kernel_match.group(1)
            
            # Add device info to the report
            pdf.set_font("Arial", 'B', size=14)
            pdf.cell(200, 10, txt="Device Information", ln=True)
            pdf.ln(5)
            
            pdf.set_font("Arial", size=12)
            for key, value in device_info.items():
                pdf.cell(200, 10, txt=f"{key}: {value}", ln=True)
            
        except Exception as e:
            pdf.cell(200, 10, txt="Could not retrieve device information", ln=True)
        
        # Add table of contents placeholder (would need to be filled in post-processing)
        pdf.add_page()
        pdf.set_font("Arial", 'B', size=16)
        pdf.cell(200, 10, txt="Table of Contents", ln=True)
        pdf.ln(10)
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="1. Call Log Analysis", ln=True)
        pdf.cell(200, 10, txt="2. SMS Log Analysis", ln=True)
        pdf.cell(200, 10, txt="3. Logcat Analysis", ln=True)
        
        # Call Log Analysis
        pdf.add_page()
        pdf.set_font("Arial", 'B', size=16)
        pdf.cell(200, 10, txt="1. Call Log Analysis", ln=True)
        pdf.ln(10)
        
        try:
            with open("logs/call_logs.txt", "r", encoding="utf-8", errors="replace") as f:
                call_logs = f.readlines()
                
            if call_logs:
                # Call statistics
                call_count = len(call_logs)
                
                # Count incoming/outgoing/missed calls
                incoming = sum(1 for line in call_logs if re.search(r'type:\s*1|INCOMING', line, re.IGNORECASE))
                outgoing = sum(1 for line in call_logs if re.search(r'type:\s*2|OUTGOING', line, re.IGNORECASE))
                missed = sum(1 for line in call_logs if re.search(r'type:\s*3|MISSED', line, re.IGNORECASE))
                
                pdf.set_font("Arial", size=12)
                pdf.cell(200, 10, txt=f"Total calls: {call_count}", ln=True)
                pdf.cell(200, 10, txt=f"Incoming calls: {incoming}", ln=True)
                pdf.cell(200, 10, txt=f"Outgoing calls: {outgoing}", ln=True)
                pdf.cell(200, 10, txt=f"Missed calls: {missed}", ln=True)
                pdf.ln(10)
                
                # Most frequent callers
                numbers = []
                for line in call_logs:
                    matches = re.findall(r'(?:number:|to:|from:)\s*(\+?\d{7,15})', line)
                    if matches:
                        numbers.extend(matches)
                    else:
                        matches = re.findall(r'(\+?\d{7,15})', line)
                        numbers.extend(matches)
                
                if numbers:
                    counter = Counter(numbers)
                    top_callers = counter.most_common(5)
                    
                    pdf.set_font("Arial", 'B', size=14)
                    pdf.cell(200, 10, txt="Top 5 Most Frequent Callers", ln=True)
                    pdf.ln(5)
                    
                    pdf.set_font("Arial", 'B', size=12)
                    pdf.cell(100, 10, txt="Phone Number", border=1)
                    pdf.cell(50, 10, txt="Call Count", border=1)
                    pdf.ln()
                    
                    pdf.set_font("Arial", size=12)
                    for number, count in top_callers:
                        pdf.cell(100, 10, txt=number, border=1)
                        pdf.cell(50, 10, txt=str(count), border=1)
                        pdf.ln()
            else:
                pdf.cell(200, 10, txt="No call logs found", ln=True)
                
        except FileNotFoundError:
            pdf.cell(200, 10, txt="Call log file not found", ln=True)
        except Exception as e:
            pdf.cell(200, 10, txt=f"Error analyzing call logs: {str(e)}", ln=True)
        
        # SMS Log Analysis
        pdf.add_page()
        pdf.set_font("Arial", 'B', size=16)
        pdf.cell(200, 10, txt="2. SMS Log Analysis", ln=True)
        pdf.ln(10)
        
        try:
            with open("logs/sms_logs.txt", "r", encoding="utf-8", errors="replace") as f:
                sms_logs = f.readlines()
                
            if sms_logs:
                # SMS statistics
                sms_count = len(sms_logs)
                
                # Count incoming/outgoing SMS
                incoming = sum(1 for line in sms_logs if re.search(r'type:\s*1|INCOMING|from:', line, re.IGNORECASE))
                outgoing = sum(1 for line in sms_logs if re.search(r'type:\s*2|OUTGOING|to:', line, re.IGNORECASE))
                
                pdf.set_font("Arial", size=12)
                pdf.cell(200, 10, txt=f"Total SMS messages: {sms_count}", ln=True)
                pdf.cell(200, 10, txt=f"Incoming messages: {incoming}", ln=True)
                pdf.cell(200, 10, txt=f"Outgoing messages: {outgoing}", ln=True)
                pdf.ln(10)
                
                # Most frequent SMS senders
                senders = []
                for line in sms_logs:
                    match = re.search(r'from: (\+?\d+)', line)
                    if match:
                        senders.append(match.group(1))
                
                if senders:
                    counter = Counter(senders)
                    top_senders = counter.most_common(5)
                    
                    pdf.set_font("Arial", 'B', size=14)
                    pdf.cell(200, 10, txt="Top 5 Most Frequent SMS Senders", ln=True)
                    pdf.ln(5)
                    
                    pdf.set_font("Arial", 'B', size=12)
                    pdf.cell(100, 10, txt="Phone Number", border=1)
                    pdf.cell(50, 10, txt="Message Count", border=1)
                    pdf.ln()
                    
                    pdf.set_font("Arial", size=12)
                    for number, count in top_senders:
                        pdf.cell(100, 10, txt=number, border=1)
                        pdf.cell(50, 10, txt=str(count), border=1)
                        pdf.ln()
            else:
                pdf.cell(200, 10, txt="No SMS logs found", ln=True)
                
        except FileNotFoundError:
            pdf.cell(200, 10, txt="SMS log file not found", ln=True)
        except Exception as e:
            pdf.cell(200, 10, txt=f"Error analyzing SMS logs: {str(e)}", ln=True)
        
        # Logcat Analysis
        pdf.add_page()
        pdf.set_font("Arial", 'B', size=16)
        pdf.cell(200, 10, txt="3. Logcat Analysis", ln=True)
        pdf.ln(10)
        
        # Add logcat type distribution information
        for log_type in LOG_TYPES:
            try:
                filepath = f"logs/logcat_types/{log_type.lower()}_logs.txt"
                with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                
                if lines:
                    pdf.set_font("Arial", 'B', size=14)
                    pdf.cell(200, 10, txt=f"{log_type} Logs", ln=True)
                    pdf.ln(5)
                    
                    pdf.set_font("Arial", size=12)
                    pdf.cell(200, 10, txt=f"Total entries: {len(lines)}", ln=True)
                    
                    # Add example entries (first 3)
                    if len(lines) > 1:
                        pdf.set_font("Arial", 'B', size=12)
                        pdf.cell(200, 10, txt="Example entries:", ln=True)
                        
                        pdf.set_font("Arial", size=10)
                        for i, line in enumerate(lines[1:4]):  # Skip header line and show 3 examples
                            # Truncate long lines
                            if len(line) > 100:
                                line = line[:97] + "..."
                            pdf.multi_cell(0, 10, txt=f"{i+1}. {line.strip()}")
                    
                    pdf.ln(5)
            except FileNotFoundError:
                pass
            except Exception as e:
                pdf.cell(200, 10, txt=f"Error analyzing {log_type} logs: {str(e)}", ln=True)
        
        # Save the PDF
        pdf.output(filepath)
        messagebox.showinfo("Report Generated", f"Forensic report exported to {filepath}")
    
    except Exception as e:
        messagebox.showerror("Report Generation Failed", f"Failed to generate report: {str(e)}")

# Enhanced Filter Options for Logcat Types
filter_frame = tk.Frame(tab_filter, bg=BG_COLOR)
filter_frame.pack(fill=tk.X, pady=10)

tk.Label(filter_frame, text="Log Type", bg=BG_COLOR, fg=FG_COLOR, font=FONT).grid(row=0, column=0, padx=5, pady=5)
filter_types = ["Logcat", "Calls", "SMS"] + list(LOG_TYPES.keys())
filter_type_combo = ttk.Combobox(filter_frame, values=filter_types, width=15)
filter_type_combo.set("Logcat")
filter_type_combo.grid(row=0, column=1, padx=5, pady=5)

tk.Label(filter_frame, text="Time Range", bg=BG_COLOR, fg=FG_COLOR, font=FONT).grid(row=0, column=2, padx=5, pady=5)
time_range_combo = ttk.Combobox(filter_frame, values=["Past 1 Hour", "Past 24 Hours", "Past 7 Days", "All Time"], width=15)
time_range_combo.set("Past 24 Hours")
time_range_combo.grid(row=0, column=3, padx=5, pady=5)

tk.Label(filter_frame, text="Keyword", bg=BG_COLOR, fg=FG_COLOR, font=FONT).grid(row=1, column=0, padx=5, pady=5)
filter_keyword_entry = tk.Entry(filter_frame, width=30)
filter_keyword_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5)

# Additional filter options for specific log types
tk.Label(filter_frame, text="Sub-Type", bg=BG_COLOR, fg=FG_COLOR, font=FONT).grid(row=1, column=3, padx=5, pady=5)
filter_subtype_combo = ttk.Combobox(filter_frame, values=["All"], width=15)
filter_subtype_combo.set("All")
filter_subtype_combo.grid(row=1, column=4, padx=5, pady=5)

# Add a severity filter for logs
tk.Label(filter_frame, text="Severity", bg=BG_COLOR, fg=FG_COLOR, font=FONT).grid(row=0, column=4, padx=5, pady=5)
filter_severity_combo = ttk.Combobox(filter_frame, values=["All", "Error", "Warning", "Info", "Debug", "Verbose"], width=15)
filter_severity_combo.set("All")
filter_severity_combo.grid(row=0, column=5, padx=5, pady=5)

def update_subtype_options(*args):
    """Update subtype combobox options based on selected log type"""
    log_type = filter_type_combo.get()
    
    if log_type == "Application":
        subtypes = ["All", "Activity", "Fragment", "View", "Lifecycle"]
    elif log_type == "System":
        subtypes = ["All", "Boot", "Memory", "CPU", "Battery"]
    elif log_type == "Crash":
        subtypes = ["All", "NullPointer", "OutOfMemory", "IllegalState", "ANR"]
    elif log_type == "Network":
        subtypes = ["All", "WiFi", "Mobile", "HTTP", "Socket"]
    elif log_type == "GC":
        subtypes = ["All", "Dalvik GC", "ART GC", "Explicit GC", "Concurrent GC"]
    elif log_type == "Broadcast":
        subtypes = ["All", "System", "App", "Sticky", "Ordered"]
    elif log_type == "Service":
        subtypes = ["All", "Start", "Stop", "Bind", "Unbind"]
    elif log_type == "Device":
        subtypes = ["All", "Battery", "Power", "Sensor", "Camera", "Location"]
    else:
        subtypes = ["All"]
    
    filter_subtype_combo['values'] = subtypes
    filter_subtype_combo.set("All")

# Connect the log type combobox to the update function
filter_type_combo.bind("<<ComboboxSelected>>", update_subtype_options)

def apply_filter():
    """Apply the selected filters to the logs"""
    # Get filter values
    log_type = filter_type_combo.get()
    time_range = time_range_combo.get()
    keyword = filter_keyword_entry.get()
    subtype = filter_subtype_combo.get()
    severity = filter_severity_combo.get()
    
    # Determine input file based on log type
    if log_type == "Logcat":
        input_file = "logs/android_logcat.txt"
    elif log_type == "Calls":
        input_file = "logs/call_logs.txt"
    elif log_type == "SMS":
        input_file = "logs/sms_logs.txt"
    elif log_type in LOG_TYPES:
        input_file = f"logs/logcat_types/{log_type.lower()}_logs.txt"
    else:
        filter_output.insert(tk.END, "❌ Please select a valid log type.\n")
        return
    
    # Apply filter based on options
    try:
        filter_logs(input_file, keyword=keyword, time_range=time_range, 
                  severity=severity if severity != "All" else None,
                  subtype=subtype if subtype != "All" else None,
                  output_file="logs/filtered_logs.txt")
        load_filtered_logs()
    except Exception as e:
        filter_output.delete(1.0, tk.END)
        filter_output.insert(tk.END, f"❌ Error applying filter: {str(e)}\n")

def filter_logs(input_file, keyword=None, time_range=None, severity=None, subtype=None, output_file="logs/filtered_logs.txt"):
    """Enhanced filter logs function that handles all the new options"""
    try:
        with open(input_file, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            
        now = datetime.now()
        filtered_lines = []
        
        # Define patterns for severity levels
        severity_patterns = {
            "Error": r'E/|ERROR|Exception|FATAL',
            "Warning": r'W/|WARN|WARNING',
            "Info": r'I/|INFO',
            "Debug": r'D/|DEBUG',
            "Verbose": r'V/|VERBOSE'
        }
        
        # Define patterns for subtypes based on categories
        subtype_patterns = {
            # Application subtypes
            "Activity": r'Activity|startActivity',
            "Fragment": r'Fragment',
            "View": r'View|Inflate',
            "Lifecycle": r'onCreate|onStart|onResume|onPause|onStop|onDestroy',
            
            # System subtypes
            "Boot": r'boot|start up|startup|starting',
            "Memory": r'memory|heap|ram',
            "CPU": r'cpu|processor',
            "Battery": r'battery|power',
            
            # Crash subtypes
            "NullPointer": r'NullPointerException',
            "OutOfMemory": r'OutOfMemoryError',
            "IllegalState": r'IllegalStateException',
            "ANR": r'ANR|Not Responding',
            
            # Network subtypes
            "WiFi": r'wifi|wlan',
            "Mobile": r'mobile|cellular|data connection',
            "HTTP": r'http|https|URL',
            "Socket": r'socket|tcp|udp',
            
            # GC subtypes
            "Dalvik GC": r'dalvikvm.*GC',
            "ART GC": r'art.*GC',
            "Explicit GC": r'Explicit GC',
            "Concurrent GC": r'Concurrent GC',
            
            # Broadcast subtypes
            "System": r'android\.intent\.action|system broadcast',
            "App": r'com\.',
            "Sticky": r'sticky|registerReceiver',
            "Ordered": r'ordered broadcast',
            
            # Service subtypes
            "Start": r'startService',
            "Stop": r'stopService',
            "Bind": r'bindService|onBind',
            "Unbind": r'unbindService|onUnbind',
            
            # Device subtypes
            "Battery": r'battery|BatteryManager',
            "Power": r'power|PowerManager|wake|sleep',
            "Sensor": r'sensor|Sensor',
            "Camera": r'camera|Camera',
            "Location": r'location|LocationManager|GPS'
        }
        
        for line in lines:
            include = True
            
            # Apply time filter
            if time_range and time_range != "All Time":
                date_match = re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', line)
                unix_match = re.search(r'date=(\d+)', line)
                logcat_match = re.search(r'(\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                
                has_timestamp = False
                if date_match:
                    try:
                        ts = datetime.strptime(date_match.group(), "%Y-%m-%d %H:%M:%S")
                        has_timestamp = True
                    except:
                        pass
                elif unix_match:
                    try:
                        ts = datetime.fromtimestamp(int(unix_match.group(1)) / 1000)
                        has_timestamp = True
                    except:
                        pass
                elif logcat_match:
                    try:
                        today = datetime.now()
                        date_str = f"{today.year}-{logcat_match.group(1)}"
                        ts = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
                        if ts > today:
                            ts = ts.replace(year=today.year - 1)
                        has_timestamp = True
                    except:
                        pass
                
                if has_timestamp:
                    if time_range == "Past 1 Hour" and (now - ts) > timedelta(hours=1):
                        include = False
                    elif time_range == "Past 24 Hours" and (now - ts) > timedelta(hours=24):
                        include = False
                    elif time_range == "Past 7 Days" and (now - ts) > timedelta(days=7):
                        include = False
            
            # Apply keyword filter
            if include and keyword and keyword.strip():
                if keyword.lower() not in line.lower():
                    include = False
            
            # Apply severity filter
            if include and severity and severity != "All":
                if not re.search(severity_patterns.get(severity, ""), line, re.IGNORECASE):
                    include = False
            
            # Apply subtype filter
            if include and subtype and subtype != "All":
                if not re.search(subtype_patterns.get(subtype, ""), line, re.IGNORECASE):
                    include = False
            
            # Add line to filtered results if it passes all filters
            if include:
                filtered_lines.append(line)
        
        # Write filtered lines to output file
        with open(output_file, "w", encoding="utf-8") as f:
            f.writelines(filtered_lines)
        
        return len(filtered_lines)
    
    except Exception as e:
        print(f"Error filtering logs: {e}")
        raise

def load_filtered_logs():
    """Load filtered logs into the filter output text widget"""
    try:
        filter_output.delete(1.0, tk.END)
        
        with open("logs/filtered_logs.txt", "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            
        if not lines:
            filter_output.insert(tk.END, "No logs match the selected filters.\n")
            return
        
        # Show filtered logs with line numbers
        for i, line in enumerate(lines):
            filter_output.insert(tk.END, f"{i+1}: {line}")
        
        # Show summary
        filter_output.insert(tk.END, f"\n\n✅ Found {len(lines)} matching log entries.\n")
        
        # Create a button to graph the filtered results
        tk.Button(filter_frame, text="Graph Filtered Results", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR,
                 command=graph_filtered_results).grid(row=2, column=3, padx=5, pady=5)
        
    except Exception as e:
        filter_output.delete(1.0, tk.END)
        filter_output.insert(tk.END, f"❌ Error loading filtered logs: {str(e)}\n")

def graph_filtered_results():
    """Create a graph of the filtered log results"""
    try:
        log_type = filter_type_combo.get()
        
        with open("logs/filtered_logs.txt", "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            
        if not lines:
            messagebox.showinfo("Graph", "No data to graph.")
            return
        
        # Different graph types based on log type
        if log_type in ["Calls", "SMS"]:
            # Create time-based graph for call or SMS logs
            timestamps = []
            
            for line in lines:
                # Try to extract timestamp
                date_match = re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', line)
                unix_match = re.search(r'date=(\d+)', line)
                
                if date_match:
                    try:
                        ts = datetime.strptime(date_match.group(), "%Y-%m-%d %H:%M:%S")
                        timestamps.append(ts)
                    except:
                        pass
                elif unix_match:
                    try:
                        ts = datetime.fromtimestamp(int(unix_match.group(1)) / 1000)
                        timestamps.append(ts)
                    except:
                        pass
            
            if not timestamps:
                messagebox.showinfo("Graph", "No timestamp data found in logs.")
                return
            
            # Group timestamps by hour
            timestamps.sort()
            
            # Create bins by hour
            start_time = timestamps[0].replace(minute=0, second=0, microsecond=0)
            end_time = timestamps[-1].replace(minute=59, second=59, microsecond=999999)
            
            # Create hourly bins
            hourly_bins = []
            current = start_time
            while current <= end_time:
                hourly_bins.append(current)
                current += timedelta(hours=1)
            
            # Count logs in each bin
            counts = [0] * (len(hourly_bins))
            for ts in timestamps:
                for i, bin_time in enumerate(hourly_bins[:-1]):
                    if bin_time <= ts < hourly_bins[i+1]:
                        counts[i] += 1
                        break
            
            # Plot the results
            fig, ax = plt.subplots(figsize=(12, 6))
            ax.plot(hourly_bins[:-1], counts, marker='o', linestyle='-')
            ax.set_title(f"{log_type} Frequency Over Time")
            ax.set_xlabel("Time")
            ax.set_ylabel("Count")
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            # Create a new window to display the graph
            graph_window = tk.Toplevel(root)
            graph_window.title(f"{log_type} Frequency Graph")
            graph_window.geometry("800x600")
            graph_window.configure(bg=BG_COLOR)
            
            # Embed the figure in the window
            canvas = FigureCanvasTkAgg(fig, master=graph_window)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Save reference to the current figure and axis for export
            global graph_fig, graph_ax
            graph_fig = fig
            graph_ax = ax
            
            # Add export buttons
            export_frame = tk.Frame(graph_window, bg=BG_COLOR)
            export_frame.pack(pady=10)
            
            tk.Button(export_frame, text="Export as PNG", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR,
                     command=lambda: export_chart(fig, f"{log_type.lower()}_frequency.png")).pack(side=tk.LEFT, padx=10)
            
            tk.Button(export_frame, text="Export as PDF", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR,
                     command=lambda: export_chart(fig, f"{log_type.lower()}_frequency.pdf")).pack(side=tk.LEFT, padx=10)
                     
            tk.Button(export_frame, text="Export Data as CSV", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR,
                     command=lambda: export_graph_data("csv")).pack(side=tk.LEFT, padx=10)
                     
        elif log_type == "Logcat" or log_type in LOG_TYPES:
            # For logcat, create a severity distribution chart
            severity_counts = {
                "Error": 0,
                "Warning": 0,
                "Info": 0,
                "Debug": 0,
                "Verbose": 0
            }
            
            # Define patterns for severity levels
            severity_patterns = {
                "Error": r'E/|ERROR|Exception|FATAL',
                "Warning": r'W/|WARN|WARNING',
                "Info": r'I/|INFO',
                "Debug": r'D/|DEBUG',
                "Verbose": r'V/|VERBOSE'
            }
            
            # Count severity levels
            for line in lines:
                found = False
                for severity, pattern in severity_patterns.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        severity_counts[severity] += 1
                        found = True
                        break
                if not found:
                    # Default to Info if no pattern matches
                    severity_counts["Info"] += 1
            
            # Create a pie chart
            fig, ax = plt.subplots(figsize=(10, 8))
            labels = list(severity_counts.keys())
            sizes = list(severity_counts.values())
            
            # Filter out zero values
            non_zero_labels = []
            non_zero_sizes = []
            for i, size in enumerate(sizes):
                if size > 0:
                    non_zero_labels.append(labels[i])
                    non_zero_sizes.append(size)
            
            if not non_zero_sizes:
                messagebox.showinfo("Graph", "No data to graph.")
                return
            
            colors = ['red', 'orange', 'green', 'blue', 'purple']
            ax.pie(non_zero_sizes, labels=non_zero_labels, colors=colors[:len(non_zero_labels)],
                  autopct='%1.1f%%', shadow=True, startangle=90)
            ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
            ax.set_title(f"{log_type} Severity Distribution")
            
            # Create a new window to display the graph
            graph_window = tk.Toplevel(root)
            graph_window.title(f"{log_type} Severity Distribution")
            graph_window.geometry("700x600")
            graph_window.configure(bg=BG_COLOR)
            
            # Embed the figure in the window
            canvas = FigureCanvasTkAgg(fig, master=graph_window)
            canvas.draw()
            canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Save reference to the current figure and axis for export
            def some_function():
             global graph_fig, graph_ax
            # Initialize with matplotlib figure and axes
            graph_fig = plt.figure()       # Creates a new figure
            graph_ax = graph_fig.add_subplot(111)  # Creates axes
            ...
            export_frame = tk.Frame(graph_window, bg=BG_COLOR)
            export_frame.pack(pady=10)
            
            tk.Button(export_frame, text="Export as PNG", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR,
                     command=lambda: export_chart(fig, f"{log_type.lower()}_severity.png")).pack(side=tk.LEFT, padx=10)
            
            tk.Button(export_frame, text="Export as PDF", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR,
                     command=lambda: export_chart(fig, f"{log_type.lower()}_severity.pdf")).pack(side=tk.LEFT, padx=10)
                     
            tk.Button(export_frame, text="Export Data as CSV", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR,
                     command=lambda: export_graph_data("csv")).pack(side=tk.LEFT, padx=10)
    
    except Exception as e:
        messagebox.showerror("Graph Error", f"Failed to create graph: {str(e)}")

# Add filter button
tk.Button(filter_frame, text="Apply Filter", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR,
         command=apply_filter).grid(row=2, column=1, padx=5, pady=5)

# Add save filtered button 
tk.Button(filter_frame, text="Save Filtered Logs", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR,
         command=lambda: save_filtered_logs()).grid(row=2, column=2, padx=5, pady=5)

def save_filtered_logs():
    """Save filtered logs to a file"""
    try:
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Filtered Logs"
        )
        
        if not file_path:
            return
            
        with open("logs/filtered_logs.txt", "r", encoding="utf-8", errors="replace") as src_file:
            with open(file_path, "w", encoding="utf-8") as dst_file:
                dst_file.write(src_file.read())
                
        messagebox.showinfo("Save Successful", f"Filtered logs saved to {file_path}")
    
    except Exception as e:
        messagebox.showerror("Save Failed", f"Failed to save filtered logs: {str(e)}")

# Filter output text widget
filter_output = scrolledtext.ScrolledText(tab_filter, width=80, height=25, bg=TEXT_BG_COLOR, fg=TEXT_FG_COLOR, font=FONT)
filter_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Add Export buttons to the main window
export_frame = tk.Frame(root, bg=BG_COLOR)
export_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=10)

tk.Button(export_frame, text="Export Full Report", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR,
         command=export_full_report).pack(side=tk.LEFT, padx=10)

tk.Button(export_frame, text="Export Current Graph (PNG)", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR,
         command=lambda: export_chart(graph_fig, "graph_export.png") if 'graph_fig' in globals() else 
                       messagebox.showinfo("Export", "No graph to export. Please generate a graph first.")).pack(side=tk.LEFT, padx=10)

tk.Button(export_frame, text="Export Current Graph (PDF)", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR,
         command=lambda: export_chart(graph_fig, "graph_export.pdf") if 'graph_fig' in globals() else 
                       messagebox.showinfo("Export", "No graph to export. Please generate a graph first.")).pack(side=tk.LEFT, padx=10)

tk.Button(export_frame, text="Export Current Graph Data (CSV)", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR,
         command=lambda: export_graph_data("csv") if 'graph_fig' in globals() else 
                       messagebox.showinfo("Export", "No graph to export. Please generate a graph first.")).pack(side=tk.LEFT, padx=10)

# Add visualization buttons to each logcat type tab
for log_type in LOG_TYPES:
    button_frame = tk.Frame(logcat_tabs[log_type], bg=BG_COLOR)
    button_frame.pack(fill=tk.X, pady=5)
    
    tk.Button(button_frame, text="Show Distribution", bg=BUTTON_COLOR, fg=BUTTON_TEXT_COLOR,
             command=lambda lt=log_type: plot_log_type_distribution(lt)).pack(side=tk.LEFT, padx=10)

# Create a main menu
main_menu = tk.Menu(root)
root.config(menu=main_menu)

# File menu
file_menu = tk.Menu(main_menu, tearoff=0)
main_menu.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="Import Logs", command=import_logs)
file_menu.add_command(label="Export Full Report", command=export_full_report)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.quit)

# Graph menu
graph_menu = tk.Menu(main_menu, tearoff=0)
main_menu.add_cascade(label="Visualize", menu=graph_menu)
graph_menu.add_command(label="Graph Call Logs", command=lambda: load_graph_tab("Calls"))
graph_menu.add_command(label="Graph SMS Logs", command=lambda: load_graph_tab("SMS"))
graph_menu.add_command(label="Graph Logcat Data", command=lambda: load_graph_tab("Logcat"))

# Analysis menu
analysis_menu = tk.Menu(main_menu, tearoff=0)
main_menu.add_cascade(label="Analysis", menu=analysis_menu)
analysis_menu.add_command(label="Call Log Analysis", command=lambda: notebook.select(tab_call_log))
analysis_menu.add_command(label="SMS Analysis", command=lambda: notebook.select(tab_sms))
analysis_menu.add_command(label="Logcat Analysis", command=lambda: notebook.select(tab_logcat))
analysis_menu.add_command(label="Advanced Filter", command=lambda: notebook.select(tab_filter))

# Help menu
help_menu = tk.Menu(main_menu, tearoff=0)
main_menu.add_cascade(label="Help", menu=help_menu)
help_menu.add_command(label="About", command=lambda: messagebox.showinfo("About", "Android Forensic Analyzer v1.0\nDeveloped for digital forensic analysis of Android logs."))
help_menu.add_command(label="Documentation", command=lambda: messagebox.showinfo("Documentation", "Please refer to the README.md file for detailed documentation."))

# Initialize notebook and tabs (add before menu creation if not already present)
notebook = ttk.Notebook(root)
tab_call_log = ttk.Frame(notebook)
tab_sms = ttk.Frame(notebook)
tab_logcat = ttk.Frame(notebook)
tab_filter = ttk.Frame(notebook)

# Add tabs to notebook
notebook.add(tab_call_log, text="Call Logs")
notebook.add(tab_sms, text="SMS")
notebook.add(tab_logcat, text="Logcat")
notebook.add(tab_filter, text="Filter")
notebook.pack(expand=True, fill='both')

# Start the application
if __name__ == "__main__":
    # Create global directories if they don't exist
    os.makedirs("logs", exist_ok=True)
    os.makedirs("logs/logcat_types", exist_ok=True)
    os.makedirs("logs/exports", exist_ok=True)
    
    # Check for existing log files and load them
    for log_type in LOG_TYPES:
        try:
            filepath = f"logs/logcat_types/{log_type.lower()}_logs.txt"
            if os.path.exists(filepath):
                load_logcat_type(log_type)
        except Exception as e:
            print(f"Error loading {log_type} logs: {e}")
    
    # Load call and SMS logs if they exist
    try:
        if os.path.exists("logs/call_logs.txt"):
            load_call_logs()
    except Exception as e:
        print(f"Error loading call logs: {e}")
        
    try:
        if os.path.exists("logs/sms_logs.txt"):
            load_sms_logs()
    except Exception as e:
        print(f"Error loading SMS logs: {e}")
    
    # Show welcome message
    messagebox.showinfo("Welcome", "Welcome to the Android Forensic Analyzer!\n\nThis tool helps you analyze Android logs for forensic investigation. Start by importing logs using the 'Import Logs' button or from the File menu.")
    
    # Start the main event loop
    root.mainloop()