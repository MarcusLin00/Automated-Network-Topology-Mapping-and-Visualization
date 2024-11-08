# ssl_context.py
import ssl
from config import SSL_CERT_PATH

def create_ssl_context():
    """Creates and configures the SSL context."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(SSL_CERT_PATH)
    # Optional: Disable hostname verification if necessary
    # context.check_hostname = False
    return context
