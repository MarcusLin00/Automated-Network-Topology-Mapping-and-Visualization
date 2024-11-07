# config.py
import os

# Configuration Parameters
SERVER_IP = os.getenv("SERVER_IP", "192.168.86.29")  # Replace with server's IP address
STATUS_PORT = int(os.getenv("STATUS_PORT", 5001))
ALERT_PORT = int(os.getenv("ALERT_PORT", 5002))
SCAN_THRESHOLD = int(os.getenv("SCAN_THRESHOLD", 20))  # Port scan detection threshold
TIME_WINDOW = int(os.getenv("TIME_WINDOW", 10))  # seconds
COOLDOWN_PERIOD = int(os.getenv("COOLDOWN_PERIOD", 60))  # seconds
STATUS_INTERVAL = int(os.getenv("STATUS_INTERVAL", 5))  # seconds
SSL_CERT_PATH = os.getenv("SSL_CERT_PATH", "server.crt")
AES_KEY_PATH = os.getenv("AES_KEY_PATH", "aes_key.pem")
AES_PASSPHRASE = os.getenv("AES_PASSPHRASE", "cs204")
