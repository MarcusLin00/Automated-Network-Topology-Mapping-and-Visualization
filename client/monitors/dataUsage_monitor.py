import asyncio
import logging
import psutil
from .base_monitor import BaseMonitor

class DataUsageMonitor(BaseMonitor):
    def __init__(
        self,
        alert_callback: callable,
        loop: asyncio.AbstractEventLoop,
        threshold: int = 100,  # 100MB threshold for alerts
        cooldown: int = 300
    ):
        self.alert_callback = alert_callback
        self.loop = loop
        self.threshold = threshold
        self.cooldown = cooldown
        self.current_usage = 0
        self.last_bytes = 0
        self.update_timer = None

    def start(self):
        logging.info("Starting DataUsageMonitor...")
        self.last_bytes = self.get_network_usage()
        asyncio.run_coroutine_threadsafe(self.collect_data_usage(), self.loop)

    def get_current_usage(self):
        return self.current_usage

    def stop(self):
        logging.info("Stopping DataUsageMonitor...")
        if self.update_timer:
            self.update_timer.cancel()

    async def collect_data_usage(self):
        while True:
            current_bytes = self.get_network_usage()
            bytes_diff = current_bytes - self.last_bytes
            self.last_bytes = current_bytes
            
            self.update_usage(bytes_diff)
            await asyncio.sleep(5)  # Update every 5 seconds

    def get_network_usage(self):
        network_stats = psutil.net_io_counters()
        return network_stats.bytes_sent + network_stats.bytes_recv

    def update_usage(self, bytes_used: int):
        """Update the current data usage and trigger alerts if threshold exceeded"""
        self.current_usage += bytes_used
        mb_used = self.current_usage / (1024 * 1024)  # Convert to MB

        #logging for real-time updates
        logging.info(f"Current Data Usage: {mb_used:.2f} MB")
        logging.info(f"Bytes difference: {bytes_used} bytes")
      
        
        if mb_used >= self.threshold:
            self._send_alert()
            self.current_usage = 0  # Reset after alert

    def _send_alert(self):
        event_name = "High Data Usage Alert"
        message = f"Data usage exceeded threshold: {self.current_usage / (1024*1024):.2f} MB"
        asyncio.run_coroutine_threadsafe(
            self.alert_callback(event_name, message, f"data_usage_{id(self)}"),
            self.loop
        )
