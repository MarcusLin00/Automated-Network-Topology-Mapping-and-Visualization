# networking.py
import socket
import ssl
import json
import asyncio
import logging
from datetime import datetime
from config import SERVER_IP, ALERT_PORT, STATUS_PORT
from ssl_context import create_ssl_context

# Initialize SSL context
SSL_CONTEXT = create_ssl_context()

async def send_alert(event_name, alert_message: str, event_id: str):
    """Send alerts to the server via TCP with TLS."""
    try:
        logging.debug(f"Attempting to send alert {event_id}: {alert_message}")
        # Establish a secure connection to the server
        reader, writer = await asyncio.open_connection(
            SERVER_IP, ALERT_PORT, ssl=SSL_CONTEXT
        )
        logging.debug(f"Established connection to {SERVER_IP}:{ALERT_PORT} with SSL.")

        # Prepare the alert data
        alert_data = {
            "event_name": event_name,
            "details": alert_message,
            "timestamp": datetime.now().isoformat(),
            "event_id": event_id
        }

        # Serialize the alert data to JSON and send it
        writer.write(json.dumps(alert_data).encode("utf-8"))
        await writer.drain()
        logging.info(f"Sent alert {event_id} to {SERVER_IP}:{ALERT_PORT}")

        # Close the connection gracefully
        writer.close()
        await writer.wait_closed()
        logging.debug(f"Closed connection to {SERVER_IP}:{ALERT_PORT}")

    except ssl.SSLError as e:
        logging.error(f"SSL error while sending alert {event_id}: {e}")
    except socket.gaierror as e:
        logging.error(f"Address-related error while sending alert {event_id}: {e}")
    except asyncio.TimeoutError:
        logging.error(f"Timeout while sending alert {event_id}.")
    except Exception as e:
        logging.error(f"Unexpected error while sending alert {event_id}: {e}")

def send_status(shutdown_event: asyncio.Event, status_interval: int = 5):
    """Send periodic status updates via UDP."""
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while not shutdown_event.is_set():
        try:
            status_message = f"Client is alive at {datetime.now().isoformat()}"
            udp_socket.sendto(status_message.encode("utf-8"), (SERVER_IP, STATUS_PORT))
            logging.info(f"Sent status to {SERVER_IP}:{STATUS_PORT}")
        except socket.error as e:
            logging.error(f"Socket error while sending status: {e}")
        except Exception as e:
            logging.error(f"Unexpected error while sending status: {e}")
        shutdown_event.wait(status_interval)  # Send status every `status_interval` seconds
    udp_socket.close()
    logging.info("Status sender stopped.")
