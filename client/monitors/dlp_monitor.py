import time
import asyncio
import logging
from datetime import datetime
from typing import Callable, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent, FileMovedEvent
from .base_monitor import BaseMonitor

class DLPEventHandler(FileSystemEventHandler):
    def __init__(self, monitor):
        self.monitor = monitor
        super().__init__()

    def on_modified(self, event):
        if isinstance(event, FileModifiedEvent):
            self.monitor.check_file_activity(event.src_path, "modified")

    def on_created(self, event):
        if isinstance(event, FileCreatedEvent):
            self.monitor.check_file_activity(event.src_path, "created")

    def on_moved(self, event):
        if isinstance(event, FileMovedEvent):
            self.monitor.check_file_activity(event.dest_path, "moved")

class DLPMonitor(BaseMonitor):
    """Monitor for detecting potential data loss through file operations."""

    def __init__(
        self,
        alert_callback: Callable[[str, str, str], asyncio.Future],
        loop: asyncio.AbstractEventLoop,
        paths_to_monitor: list[str],
        sensitive_keywords: Set[str],
        threshold: int = 5,
        time_window: int = 300,
        cooldown: int = 600
    ):
        """
        Initialize the DLP Monitor.

        :param alert_callback: Async callback function to send alerts
        :param loop: The asyncio event loop
        :param paths_to_monitor: List of directory paths to monitor
        :param sensitive_keywords: Set of keywords that indicate sensitive content
        :param threshold: Number of sensitive file operations before alerting
        :param time_window: Time window in seconds to count operations
        :param cooldown: Cooldown period between alerts
        """
        self.alert_callback = alert_callback
        self.loop = loop
        self.paths = paths_to_monitor
        self.keywords = sensitive_keywords
        self.threshold = threshold
        self.time_window = time_window
        self.cooldown = cooldown
        
        self.file_activities = []
        self.last_alert_time = 0
        self.observer = Observer()
        self.event_handler = DLPEventHandler(self)

    def check_file_activity(self, filepath: str, action: str):
        """Check if file contains sensitive data and track activity."""
        try:
            logging.info(f"Checking file activity: {filepath} ({action})")
            if self._is_sensitive_file(filepath):
                logging.info(f"Sensitive content detected in file: {filepath}")
                current_time = time.time()
                self.file_activities.append(current_time)
                
                # Remove old activities outside the time window
                self.file_activities = [
                    t for t in self.file_activities
                    if current_time - t <= self.time_window
                ]

                logging.info(f"Current activity count: {len(self.file_activities)}/{self.threshold}")
                # Check if we've exceeded the threshold
                if len(self.file_activities) >= self.threshold:
                    if current_time - self.last_alert_time >= self.cooldown:
                        event_name = "Potential Data Loss Detected"
                        alert_message = (
                            f"High volume of sensitive file operations detected.\n"
                            f"Last file: {filepath}\n"
                            f"Action: {action}\n"
                            f"Total operations in last {self.time_window}s: {len(self.file_activities)}"
                        )
                        logging.warning(alert_message)
                        asyncio.run_coroutine_threadsafe(
                            self.alert_callback(
                                event_name,
                                alert_message,
                                self._generate_event_id(filepath)
                            ),
                            self.loop
                        )
                        self.last_alert_time = current_time
                        self.file_activities.clear()
            else:
                logging.info(f"No sensitive content detected in file: {filepath}")

        except Exception as e:
            logging.error(f"Error processing file {filepath}: {str(e)}")

    def _is_sensitive_file(self, filepath: str) -> bool:
        """Check if file contains sensitive keywords."""
        try:
            # Skip binary files and very large files
            if not self._is_text_file(filepath):
                return False

            with open(filepath, 'r', encoding='utf-8') as file:
                content = file.read().lower()
                return any(keyword.lower() in content for keyword in self.keywords)
        except Exception:
            return False

    def _is_text_file(self, filepath: str) -> bool:
        """Check if file is a text file based on extension."""
        text_extensions = {'.txt', '.doc', '.docx', '.pdf', '.csv', '.json', '.xml', '.md'}
        return any(filepath.lower().endswith(ext) for ext in text_extensions)

    def _generate_event_id(self, filepath: str) -> str:
        """Generate a unique identifier for the event."""
        return f"dlp_{hash(filepath)}_{int(time.time())}"

    def start(self):
        """Start monitoring the specified paths."""
        for path in self.paths:
            self.observer.schedule(self.event_handler, path, recursive=True)
        self.observer.start()
        logging.info(f"DLP Monitor started watching paths: {', '.join(self.paths)}")

    def stop(self):
        """Stop the file system observer."""
        self.observer.stop()
        self.observer.join()