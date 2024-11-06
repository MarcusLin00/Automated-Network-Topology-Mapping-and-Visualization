# monitors/port_scan_monitor.py
import time
import asyncio
import threading
import logging
from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, IP, TCP
from typing import Callable
from .base_monitor import BaseMonitor

class PortScanMonitor(BaseMonitor):
    """Class to detect port scans using scapy."""

    def __init__(
        self,
        alert_callback: Callable[[str, str], asyncio.Future],
        loop: asyncio.AbstractEventLoop,
        threshold: int = 10,
        time_window: int = 10,
        cooldown: int = 300
    ):
        """
        Initializes the PortScanMonitor.

        :param alert_callback: Async callback function to send alerts.
        :param loop: The asyncio event loop to schedule coroutines.
        :param threshold: Number of SYN packets to consider as a scan.
        :param time_window: Time window in seconds to consider SYN packets.
        :param cooldown: Time period to wait before sending another alert for the same IP.
        """
        self.alert_callback = alert_callback
        self.threshold = threshold
        self.time_window = time_window
        self.cooldown = cooldown
        self.syn_packets = defaultdict(list)  # {src_ip: [timestamp1, timestamp2, ...]}
        self.alerted_ips = {}  # {src_ip: last_alert_timestamp}
        self.lock = threading.Lock()
        self.loop = loop  # Reference to the ClientManager's event loop

    def detect(self, packet):
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            tcp_layer = packet[TCP]
            flags = tcp_layer.flags

            # Define flag constants
            SYN_FLAG = 0x02
            ACK_FLAG = 0x10

            # Check for SYN flag and not ACK
            is_syn = (flags & SYN_FLAG) and not (flags & ACK_FLAG)

            if is_syn:
                current_time = time.time()
                with self.lock:
                    self.syn_packets[src_ip].append(current_time)
                    # Remove timestamps outside the time window
                    self.syn_packets[src_ip] = [
                        timestamp for timestamp in self.syn_packets[src_ip]
                        if current_time - timestamp <= self.time_window
                    ]
                    syn_count = len(self.syn_packets[src_ip])

                logging.debug(f"SYN packet from {src_ip}. Count in window: {syn_count}")

                # Detect port scan if SYN count exceeds threshold
                if syn_count > self.threshold:
                    # Check if an alert was recently sent for this IP
                    last_alert_time = self.alerted_ips.get(src_ip, 0)
                    if current_time - last_alert_time >= self.cooldown:
                        alert_message = f"Port scan detected from IP {src_ip} at {datetime.now().isoformat()}"
                        logging.warning(alert_message)
                        # Schedule the alert coroutine on the provided event loop
                        asyncio.run_coroutine_threadsafe(
                            self.alert_callback(alert_message, self._generate_event_id(src_ip)),
                            self.loop
                        )
                        # Update the last alert time
                        self.alerted_ips[src_ip] = current_time
                        # Reset the SYN packet count to prevent immediate re-alerting
                        self.syn_packets[src_ip].clear()
                    else:
                        logging.debug(f"Cooldown active for {src_ip}. Alert not sent.")

    def _generate_event_id(self, host_ip):
        """Generate a unique identifier for an event based on host IP."""
        return f"port_scan_{host_ip}_{int(time.time())}"

    def start(self):
        logging.info("Starting PortScanMonitor...")
        sniff(filter="tcp", prn=self.detect, store=0)
