import logging
import signal
import time
import platform
from client_manager import ClientManager
from config import SERVER_IP, STATUS_PORT, ALERT_PORT

def configure_logging():
    """Configure logging settings."""
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s')

def main():
    configure_logging()
    manager = ClientManager(SERVER_IP, STATUS_PORT, ALERT_PORT)
    manager.run()

    shutdown_event = False

    # Define shutdown handler
    def handle_shutdown(signum=None, frame=None):
        nonlocal shutdown_event
        logging.info("Shutdown signal received, shutting down...")
        manager.shutdown()
        shutdown_event = True

    # Set up signal handlers for non-Windows systems
    if platform.system() != 'Windows':
        signal.signal(signal.SIGINT, handle_shutdown)
        signal.signal(signal.SIGTERM, handle_shutdown)
    else:
        logging.info("Running on Windows; use Ctrl+C to stop the server.")

    try:
        # Keep the main loop alive until shutdown event is triggered
        while not shutdown_event:
            time.sleep(1)
    except KeyboardInterrupt:
        # Handle Ctrl+C for Windows
        handle_shutdown()
    finally:
        logging.info("Server has shut down.")

if __name__ == "__main__":
    main()
