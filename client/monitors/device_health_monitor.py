import time
import asyncio
import threading
import logging
from datetime import datetime
from typing import Callable
import psutil
from collections import defaultdict
from .base_monitor import BaseMonitor

class DeviceHealthMonitor(BaseMonitor):
    """Class to monitor device health and performance metrics."""

    def __init__(
        self,
        alert_callback: Callable[[str, str, str], asyncio.Future],
        loop: asyncio.AbstractEventLoop,
        cpu_threshold: float = 90.0,
        mem_threshold: float = 80.0,
        check_interval: int = 5,
        cooldown: int = 300
    ):
        """
        Initializes the DeviceHealthMonitor.

        :param alert_callback: Async callback function to send alerts.
        :param loop: The asyncio event loop to schedule coroutines.
        :param cpu_threshold: CPU usage threshold percentage.
        :param mem_threshold: Memory usage threshold percentage.
        :param check_interval: Interval in seconds to check system metrics.
        :param cooldown: Time period to wait before sending another alert for the same metric.
        """
        self.alert_callback = alert_callback
        self.cpu_threshold = cpu_threshold
        self.mem_threshold = mem_threshold
        self.check_interval = check_interval
        self.cooldown = cooldown
        self.alerted_metrics = defaultdict(lambda: 0)  # {metric_name: last_alert_timestamp}
        self.lock = threading.Lock()
        self.loop = loop
        self.stop_event = threading.Event()
        
    def check_metrics(self):
        """Check system metrics and detect anomalies."""
        while not self.stop_event.is_set():
            current_time = time.time()
            with self.lock:
                # Non-blocking CPU usage check
                cpu_usage = psutil.cpu_percent(interval=0)
                logging.debug(f"Current CPU Usage: {cpu_usage}%")
                if cpu_usage > self.cpu_threshold:
                    self._handle_alert("CPU Usage", cpu_usage, current_time)

                # Check memory usage
                mem_usage = psutil.virtual_memory().percent
                logging.debug(f"Current Memory Usage: {mem_usage}%")
                if mem_usage > self.mem_threshold:
                    self._handle_alert("Memory Usage", mem_usage, current_time)

            # Wait for the check_interval or until stop_event is set
            self.stop_event.wait(self.check_interval)

    def _handle_alert(self, metric_name, metric_value, current_time):
        """Handle alert logic for a specific metric."""
        last_alert_time = self.alerted_metrics[metric_name]
        if current_time - last_alert_time >= self.cooldown:
            event_name = f"High {metric_name}"
            alert_message = f"{metric_name} exceeded threshold: {metric_value}% at {datetime.now().isoformat()}"
            logging.warning(alert_message)
            # Schedule the alert coroutine on the provided event loop
            asyncio.run_coroutine_threadsafe(
                self.alert_callback(event_name, alert_message, self._generate_event_id(metric_name)),
                self.loop
            )
            # Update last alert time
            self.alerted_metrics[metric_name] = current_time
        else:
            logging.debug(f"Cooldown active for {metric_name}. Alert not sent.")

    def _generate_event_id(self, metric_name):
        """Generate a unique identifier for an event based on the metric name."""
        return f"{metric_name.lower().replace(' ', '_')}_{int(time.time())}"

    def start(self):
        logging.info("Starting DeviceHealthMonitor...")
        self.thread = threading.Thread(target=self.check_metrics, daemon=True)
        self.thread.start()

    def stop(self):
        logging.info("Stopping DeviceHealthMonitor...")
        self.stop_event.set()
        self.thread.join()