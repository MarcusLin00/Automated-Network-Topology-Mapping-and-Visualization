# main.py
import logging
import signal
import sys
from client_manager import ClientManager
from config import SERVER_IP, STATUS_PORT, ALERT_PORT

def configure_logging():
    """Configure logging settings."""
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s:%(message)s')

def main():
    configure_logging()
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
