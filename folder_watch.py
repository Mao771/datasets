import os
import time
import subprocess
import json
from sklearn.metrics import classification_report
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests as r
from numpy import mean

# Configuration
WATCH_DIR = r"tmp"  # Directory to monitor
LOG_FILE = r"scan_results.log"  # Path to log file
DEFENDER_CMD = r"c:\Program Files\Windows Defender\MpCmdRun.exe"  # Path to MpCmdRun.exe
API_URL = "http://127.0.0.1:8080/detect_elf_malware"

# Metrics tracking
true_labels = []
predicted_labels = []
processing_times = []


# Helper function to log messages
def log_message(message):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
    print(message)


# Function to process a file
def process_file(file_path):
    global true_labels, predicted_labels, processing_times

    try:
        with open(file_path, 'rb') as fb:
            start_time = time.time()
            response = r.post(API_URL, files={'file': fb})
        processing_time = time.time() - start_time
        if ('safe' in file_path) or ('not a virus' in file_path):
            label = 'not a virus'
        else:
            label = 'virus'
        print(file_path, " ", label)
        true_labels.append(label)
        predicted_labels.append(response.json()['ELF class'])
        processing_times.append(processing_time)

        print("\n\n====\n\n")
        print("Avg ELF request duration", mean(processing_times), "s")
        print(classification_report(true_labels, predicted_labels))
        print("\n\n====\n\n")
    except Exception as e:
        log_message(f"Error processing file {file_path}: {e}")


# Watchdog event handler
class FileEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            process_file(event.src_path)


def main():
    log_message("Starting directory monitor...")
    event_handler = FileEventHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        log_message("Stopping directory monitor...")
    observer.join()


if __name__ == "__main__":
    main()
