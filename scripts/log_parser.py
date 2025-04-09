import re
import os

def filter_logs(input_file, keyword=None, log_level=None, output_file="logs/filtered_logs.txt"):
    """Filters logs by keyword or log level and saves the results."""
    if not os.path.exists(input_file):
        print(f"❌ Error: {input_file} not found.")
        return

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        filtered_lines = lines  # Start with all lines

        if keyword:
            filtered_lines = [line for line in filtered_lines if re.search(keyword, line, re.IGNORECASE)]

        if log_level:
            filtered_lines = [line for line in filtered_lines if f" {log_level}/" in line]

        if not filtered_lines:
            print(f"⚠️ No logs found matching '{keyword or log_level}'.")
            return

        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            f.writelines(filtered_lines)

        print(f"✅ Filtered logs saved to {output_file}")

    except Exception as e:
        print(f"❌ Error: {e}")

def display_logs(file_path, num_lines=50):
    """Displays the first N lines of a log file."""
    if not os.path.exists(file_path):
        print(f"❌ Error: {file_path} not found.")
        return

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        if not lines:
            print("⚠️ No logs available to display.")
            return

        print(f"\n📜 Displaying first {num_lines} lines of {file_path}:\n")
        for line in lines[:num_lines]:
            print(line.strip())

    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    display_logs("logs/android_logcat.txt")
import re
import os

def filter_logs(input_file, keyword=None, log_level=None, output_file="logs/filtered_logs.txt"):
    """Filters logs by keyword or log level and saves the results."""
    
    if not os.path.exists(input_file):
        print(f"❌ Error: {input_file} not found.")
        return

    try:
        # Ensure logs directory exists before writing
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        filtered_lines = []

        with open(input_file, "r", encoding="utf-8") as f:
            for line in f:
                if (keyword and re.search(keyword, line, re.IGNORECASE)) or (log_level and f" {log_level}/" in line):
                    filtered_lines.append(line)

        if not filtered_lines:
            print(f"⚠️ No logs found matching '{keyword or log_level}'.")
            return

        with open(output_file, "a", encoding="utf-8") as f:  # Append mode
            f.writelines(filtered_lines)

        print(f"✅ Filtered logs appended to {output_file}")

    except Exception as e:
        print(f"❌ Error: {e}")

def display_logs(file_path, num_lines=50):
    """Displays the first N lines of a log file."""
    
    if not os.path.exists(file_path):
        print(f"❌ Error: {file_path} not found.")
        return

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = [next(f).strip() for _ in range(num_lines) if not f.closed]

        if not lines:
            print("⚠️ No logs available to display.")
            return

        print(f"\n📜 Displaying first {num_lines} lines of {file_path}:\n")
        for line in lines:
            print(line)

    except StopIteration:
        print("⚠️ Log file has fewer lines than requested.")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    display_logs("logs/android_logcat.txt")
