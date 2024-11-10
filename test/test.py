import socket
import ssl
import time
import asyncio
import threading
import logging
import signal
import sys
import json
from scapy.all import sniff, IP, TCP
from typing import Callable, Dict
from collections import defaultdict
from datetime import datetime
import os

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s')

# Configuration Parameters
SERVER_IP = os.getenv("SERVER_IP", "192.168.86.29")  # Replace with server's IP address
STATUS_PORT = int(os.getenv("STATUS_PORT", 5001))
ALERT_PORT = int(os.getenv("ALERT_PORT", 5002))
SCAN_THRESHOLD = int(os.getenv("SCAN_THRESHOLD", 10))  # Port scan detection threshold
TIME_WINDOW = int(os.getenv("TIME_WINDOW", 10))  # seconds
COOLDOWN_PERIOD = int(os.getenv("COOLDOWN_PERIOD", 300))  # seconds

# Load SSL context
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.load_verify_locations("server.crt")
# Optional: Disable hostname verification if necessary
# ssl_context.check_hostname = False

class PortScanDetector:
    """Class to detect port scans using scapy."""
    def __init__(
        self,
        alert_callback: Callable[[str, str], asyncio.Future],
        loop: asyncio.AbstractEventLoop,
        threshold: int = SCAN_THRESHOLD,
        time_window: int = TIME_WINDOW,
        cooldown: int = COOLDOWN_PERIOD
    ):
        """
        Initializes the PortScanDetector.

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

            # Check for SYN flag and not ACK
            if tcp_layer.flags == "S":
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
        logging.info("Starting port scan detection...")
        sniff(filter="tcp", prn=self.detect, store=0)

class ClientManager:
    """Manager to handle all client functions, including status updates and alerts."""
    def __init__(
        self,
        server_ip: str,
        status_port: int,
        alert_port: int,
        scan_threshold: int = SCAN_THRESHOLD,
        time_window: int = TIME_WINDOW,
        cooldown: int = COOLDOWN_PERIOD
    ):
        self.server_ip = server_ip
        self.status_port = status_port
        self.alert_port = alert_port
        self.scan_threshold = scan_threshold
        self.time_window = time_window
        self.cooldown = cooldown
        self.modules: Dict[str, Callable] = {}  # Dictionary to store registered functions
        self.loop = asyncio.new_event_loop()  # Create a new event loop
        self.shutdown_event = threading.Event()

    def register_module(self, name: str, module_func: Callable):
        """Register a new module to the client manager."""
        self.modules[name] = module_func

    def start_all_modules(self):
        """Start all registered modules."""
        for name, module in self.modules.items():
            logging.info(f"Starting module: {name}")
            threading.Thread(target=module, daemon=True).start()

    def send_status(self):
        """Send periodic status updates via raw UDP."""
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while not self.shutdown_event.is_set():
            try:
                status_message = f"Client is alive at {datetime.now().isoformat()}"
                udp_socket.sendto(status_message.encode("utf-8"), (self.server_ip, self.status_port))
                logging.info(f"Sent status to {self.server_ip}:{self.status_port}")
            except socket.error as e:
                logging.error(f"Socket error while sending status: {e}")
            except Exception as e:
                logging.error(f"Unexpected error while sending status: {e}")
            self.shutdown_event.wait(5)  # Send status every 5 seconds
        udp_socket.close()
        logging.info("Status sender stopped.")

    async def send_alert(self, alert_message: str, event_id: str):
        """Send alerts to the server via TCP with TLS."""
        try:
            logging.debug(f"Attempting to send alert {event_id}: {alert_message}")
            # Establish a secure connection to the server
            reader, writer = await asyncio.open_connection(
                self.server_ip, self.alert_port, ssl=ssl_context
            )
            logging.debug(f"Established connection to {self.server_ip}:{self.alert_port} with SSL.")

            # Prepare the alert data
            alert_data = {
                "message": "Port scan detected",
                "details": alert_message,
                "timestamp": datetime.now().isoformat(),
                "event_id": event_id
            }

            # Serialize the alert data to JSON and send it
            writer.write(json.dumps(alert_data).encode("utf-8"))
            await writer.drain()
            logging.info(f"Sent alert {event_id} to {self.server_ip}:{self.alert_port}")

            # Close the connection gracefully
            writer.close()
            await writer.wait_closed()
            logging.debug(f"Closed connection to {self.server_ip}:{self.alert_port}")

        except ssl.SSLError as e:
            logging.error(f"SSL error while sending alert {event_id}: {e}")
        except socket.gaierror as e:
            logging.error(f"Address-related error while sending alert {event_id}: {e}")
        except asyncio.TimeoutError:
            logging.error(f"Timeout while sending alert {event_id}.")
        except Exception as e:
            logging.error(f"Unexpected error while sending alert {event_id}: {e}")

    def run_event_loop(self):
        """Run the asyncio event loop."""
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def run(self):
        """Start the client manager, including status updates and all registered modules."""
        # Start the asyncio event loop in a separate thread
        self.loop_thread = threading.Thread(target=self.run_event_loop, daemon=True)
        self.loop_thread.start()
        logging.info("Asyncio event loop started.")

        # Start status update in a background thread
        self.status_thread = threading.Thread(target=self.send_status, daemon=True)
        self.status_thread.start()
        logging.info("Status update thread started.")

        # Initialize and register modules
        port_scan_detector = PortScanDetector(
            alert_callback=self.send_alert,
            loop=self.loop,
            threshold=self.scan_threshold,
            time_window=self.time_window,
            cooldown=self.cooldown
        )
        self.register_module("PortScanDetector", port_scan_detector.start)

        # Start all registered modules
        self.start_all_modules()

    def shutdown(self):
        """Gracefully shutdown the client manager."""
        logging.info("Shutting down ClientManager...")
        self.shutdown_event.set()
        self.status_thread.join()
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.loop_thread.join()
        logging.info("ClientManager shutdown complete.")

def main():
    manager = ClientManager(SERVER_IP, STATUS_PORT, ALERT_PORT)
    manager.run()

    # Handle graceful shutdown on SIGINT and SIGTERM
    def handle_shutdown(signum, frame):
        manager.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    # Keep the main thread alive to listen for signals
    signal.pause()

if __name__ == "__main__":
    main()