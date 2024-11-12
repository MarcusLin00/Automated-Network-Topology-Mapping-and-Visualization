# client_manager.py
import asyncio
import threading
import logging
from typing import Callable, Dict
from config import (
    SERVER_IP,
    STATUS_PORT,
    ALERT_PORT,
    SCAN_THRESHOLD,
    TIME_WINDOW,
    COOLDOWN_PERIOD,
    STATUS_INTERVAL,
    MONITORED_PATHS,
)
from networking import send_status, send_alert
from monitors import PortScanMonitor, DLPMonitor, DeviceHealthMonitor, MalwarePhishingMonitor



class ClientManager:
    """Manager to handle all client functions, including status updates and alerts."""

    def __init__(
        self,
        server_ip: str,
        status_port: int,
        alert_port: int,
        scan_threshold: int = SCAN_THRESHOLD,
        time_window: int = TIME_WINDOW,
        cooldown: int = COOLDOWN_PERIOD,
        status_interval: int = STATUS_INTERVAL,
        monitored_paths: list[str] = MONITORED_PATHS, 
        cpu_threshold: int = 90,  
        mem_threshold: int = 80, 
        check_interval: int = 5,
        
    ):
        # Network settings
        self.server_ip = server_ip
        self.status_port = status_port
        self.alert_port = alert_port
        
        # Modules settings
        self.modules: Dict[str, Callable] = {}  # Dictionary to store registered functions
        self.loop = asyncio.new_event_loop()  # Create a new event loop
        self.shutdown_event = threading.Event()
        
        # Initialize modules dictionary
        self.modules = {}


        # Monitor settings
        self.scan_threshold = scan_threshold
        self.time_window = time_window
        self.cooldown = cooldown
        self.status_interval = status_interval
        self.cpu_threshold = cpu_threshold
        self.mem_threshold = mem_threshold
        self.check_interval = check_interval
        self.monitored_paths = monitored_paths

    def send_status_updates(self):
        """Start the status update sender."""
        try:
            send_status(
                server_ip=self.server_ip,
                port=self.status_port,
                shutdown_event=self.shutdown_event,
                interval=self.status_interval
            )
        except Exception as e:
            logging.error(f"Error in status updates: {e}")

    def register_module(self, name: str, module_instance):
        """Register a new module to the client manager."""
        self.modules[name] = module_instance  

    def start_all_modules(self):
        """Start all registered modules."""
        for name, module in self.modules.items():
            logging.info(f"Starting module: {name}")
            module.start()
        logging.info(f"All modules started")

    def stop_all_modules(self):
        for name, module in self.modules.items():
            module.stop()
            logging.info(f"Module: {name} stopped.")
        logging.info(f"All modules stopped")

    def send_status_updates(self):
        """Start the status update sender."""
        send_status(self.shutdown_event, self.status_interval)

    async def send_alert_async(self, event_name: str, alert_message: str, event_id: str):
        """Wrapper to match the callback signature."""
        logging.info(f"Attempting to send alert - Event: {event_name}, Message: {alert_message}")
        try:
            await send_alert(
                event_name,     
                alert_message,   
                event_id     
            )
            logging.info("Alert sent successfully")
        except Exception as e:
            logging.error(f"Failed to send alert: {e}")

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
        self.status_thread = threading.Thread(target=self.send_status_updates, daemon=True)
        self.status_thread.start()
        logging.info("Status update thread started.")

        # Initialize and register modules

        # Initialize Port Scan Monitor
        port_scan_monitor = PortScanMonitor(
            alert_callback=self.send_alert_async,  # Use send_alert_async consistently
            loop=self.loop,
            threshold=self.scan_threshold,
            time_window=self.time_window,
            cooldown=self.cooldown
        )
        self.register_module("PortScanMonitor", port_scan_monitor)
        
        # Initialize DLP Monitor
        self.dlp_monitor = DLPMonitor(
            alert_callback=self.send_alert_async,
            loop=self.loop,
            paths_to_monitor=self.monitored_paths,  # Use the monitored_paths list
            sensitive_keywords={"confidential", "secret", "private", "internal-only"},
            threshold=3,
            time_window=60,
            cooldown=10
        )
        self.register_module("DLPMonitor", self.dlp_monitor)
        
        # Initialize Device Health Monitor 
        device_health_monitor = DeviceHealthMonitor(
            alert_callback=self.send_alert_async, 
            loop=self.loop, 
            cpu_threshold=self.cpu_threshold,  
            mem_threshold=self.mem_threshold,  
            check_interval=self.check_interval,  
            cooldown=self.cooldown  
        )
        self.register_module("DeviceHealthMonitor", device_health_monitor)

        # Initialize Malware Phishing Monitor
        malware_phishing_monitor = MalwarePhishingMonitor(
            alert_callback=self.send_alert_async,
            loop=self.loop,
            cooldown=self.cooldown
        )
        self.register_module("MalwarePhishinMonitor", malware_phishing_monitor)

        # Start all registered modules
        self.start_all_modules()

    def shutdown(self):
        logging.info("Shutting down ClientManager...")
        self.shutdown_event.set()
        self.status_thread.join()

        # Stop all modules
        self.stop_all_modules()

        self.loop.call_soon_threadsafe(self.loop.stop)
        self.loop_thread.join()
        logging.info("ClientManager shutdown complete.")
