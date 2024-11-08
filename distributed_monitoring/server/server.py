import asyncio
import platform
import ssl
import socket
import io
import ipaddress
import json
import logging
import threading
import time
import signal

from flask import Flask, render_template, Response, jsonify, request
from datetime import datetime
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import netifaces
import networkx as nx
import nmap
from collections import defaultdict
from werkzeug.serving import make_server
from encryption_utils import verify_and_decrypt_message, load_aes_key, derive_keys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

app = Flask(__name__)
client_statuses = {}
client_statuses_lock = threading.Lock() 

# Initialize alerts list and its lock for thread-safe access
alerts = []
alerts_lock = threading.Lock()

# SSL context for secure TCP server
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(certfile="server.crt", keyfile="server.key")

# AES and HMAC Keys
original_aes_key = load_aes_key("aes_key.pem", "cs204")
aes_key, hmac_key = derive_keys(original_aes_key)


class SafeNetworkMonitor:
    """Network Monitor that safely scans and captures network data."""

    def __init__(self):
        self.devices = {}
        self.G = nx.Graph()
        self.status = 'Idle'
        self.capture = None
        self.lock = threading.Lock()

    def _get_default_interface(self):
        try:
            gateways = netifaces.gateways()
            return gateways['default'][netifaces.AF_INET][1]
        except KeyError:
            logging.error("Default interface not found.")
            return None

    def _get_interface_info(self, interface, address_type):
        addrs = netifaces.ifaddresses(interface)
        if address_type in addrs:
            return addrs[address_type][0]
        return None

    def _get_ip_address(self):
        default_interface = self._get_default_interface()
        if default_interface:
            iface_info = self._get_interface_info(default_interface, netifaces.AF_INET)
            ip_addr = iface_info.get('addr') if iface_info else None
            return ip_addr
        logging.error("Failed to get IP address.")
        return None

    def _get_mac_address(self):
        default_interface = self._get_default_interface()
        if default_interface:
            iface_info = self._get_interface_info(default_interface, netifaces.AF_LINK)
            mac_addr = iface_info.get('addr') if iface_info else 'N/A'
            return mac_addr.upper()
        logging.error("Failed to get MAC address.")
        return 'N/A'

    def _get_default_gateway(self):
        try:
            return netifaces.gateways()['default'][netifaces.AF_INET][0]
        except KeyError:
            logging.error("Default gateway not found.")
            return None

    def _get_subnet(self):
        default_interface = self._get_default_interface()
        if default_interface:
            iface_info = self._get_interface_info(default_interface, netifaces.AF_INET)
            if iface_info:
                ip_interface = ipaddress.IPv4Interface(f"{iface_info['addr']}/{iface_info['netmask']}")
                return ip_interface.network
        return None

    def get_connected_devices(self):
        with self.lock:
            self.status = 'Scanning...'
        nm = nmap.PortScanner()
        subnet = self._get_subnet()
        if subnet:
            self._scan_network(nm, subnet)
            with self.lock:
                self.status = 'Last Scanned: ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        else:
            logging.error("Could not determine subnet for scanning.")
            with self.lock:
                self.status = 'Error: Subnet not determined'

    def _scan_network(self, nm, subnet):
        network = str(subnet)
        nm.scan(hosts=network, arguments='-sn')
        current_time = time.time()
        with self.lock:
            for host in nm.all_hosts():
                self._update_device_info(host, nm, current_time)
            self._add_current_device(current_time)
            self._remove_stale_devices(current_time)

    def _update_device_info(self, host, nm, current_time):
        ip, mac = host, nm[host]['addresses'].get('mac', 'N/A')
        if ip in self.devices:
            self.devices[ip].update(mac=mac, last_seen=current_time)
        else:
            self.devices[ip] = {'mac': mac, 'last_seen': current_time }

    def _add_current_device(self, current_time):
        my_ip, my_mac = self._get_ip_address(), self._get_mac_address()
        if my_ip:
            self.devices[my_ip] = self.devices.get(my_ip, {})
            self.devices[my_ip].update(mac=my_mac, last_seen=current_time)

    def _remove_stale_devices(self, current_time, stale_threshold=300):
        stale_devices = [ip for ip, info in self.devices.items() if current_time - info['last_seen'] > stale_threshold]
        for ip in stale_devices:
            del self.devices[ip]
        self._update_graph()

    def _update_graph(self):
        self.G.clear()
        subnet = self._get_subnet()
        if not subnet:
            logging.error("Could not determine subnet for updating graph.")
            return
        self._add_nodes_to_graph(subnet)
        self._add_edges_to_graph()

    def _add_nodes_to_graph(self, subnet):
        for ip, info in self.devices.items():
            if ipaddress.ip_address(ip) in subnet:
                self.G.add_node(ip, mac=info.get('mac', 'Unknown'))

    def _add_edges_to_graph(self):
        gateway_ip = self._get_default_gateway()
        if gateway_ip and gateway_ip in self.G.nodes:
            for ip in self.G.nodes:
                if ip != gateway_ip:
                    self.G.add_edge(gateway_ip, ip)

    def create_graph_image(self):
        with self.lock:
            G_copy = self.G.copy()
        plt.figure(figsize=(10, 8))
        pos = nx.spring_layout(G_copy)
        my_ip = self._get_ip_address()
        node_colors = self._assign_node_colors(G_copy, my_ip)
        nx.draw(G_copy, pos, with_labels=True, node_color=node_colors, node_size=500, font_size=8)
        plt.title("Network Map")
        img = io.BytesIO()
        plt.savefig(img, format='png', bbox_inches='tight')
        img.seek(0)
        plt.close()
        return img

    def _assign_node_colors(self, G_copy, my_ip):
        node_colors = []
        gateway_ip = self._get_default_gateway()
        for node in G_copy.nodes:
            if node == my_ip:
                node_colors.append('blue') 
            elif node in client_statuses:
                node_colors.append('green')  
            elif node == gateway_ip:
                node_colors.append('red')
            else:
                node_colors.append('orange')  
        return node_colors


# Flask routes
@app.route("/")
def index():
    return render_template("index.html", title="Network Scanner")

@app.route("/graph.png")
def graph_png():
    img = monitor.create_graph_image()
    return Response(img.getvalue(), mimetype="image/png")

@app.route("/devices")
def get_devices():
    with monitor.lock:
        subnet = monitor._get_subnet()
        devices_in_subnet = {
            ip: {
                **info,
                "monitored": ip in client_statuses  # Indicate if the client is actively updating status
            }
            for ip, info in monitor.devices.items()
            if subnet and ipaddress.ip_address(ip) in subnet
        }
    return jsonify(devices_in_subnet)

@app.route('/status')
def get_status():
    """Return the current status as JSON."""
    with monitor.lock:
        status = monitor.status
    return json.dumps({'status': status})

# Updated /alerts endpoint to return the alerts list
@app.route("/alerts")
def get_alerts():
    with alerts_lock:
        return jsonify(alerts)

@app.route("/resolve_alert", methods=['POST'])
def resolve_alert():
    """Handle resolving an alert by removing it from the alerts list."""
    data = request.get_json()
    if not data or 'event_id' not in data:
        return jsonify({'error': 'Invalid request. event_id is required.'}), 400
    
    event_id = data['event_id']
    
    with alerts_lock:
        # Find the alert with the given event_id
        for alert in alerts:
            if alert['event_id'] == event_id:
                alerts.remove(alert)
                logging.info(f"Resolved alert with event_id: {event_id}")
                return jsonify({'message': 'Alert resolved successfully.'}), 200
    
    # If alert with event_id not found
    return jsonify({'error': 'Alert not found.'}), 404

# Flask server running in a separate thread with control for shutdown
class FlaskServerThread(threading.Thread):
    def __init__(self, app, host, port):
        super().__init__()
        self.server = make_server(host, port, app)
        self.ctx = app.app_context()
        self.ctx.push()
        self.shutdown_flag = threading.Event()

    def run(self):
        logging.info(f"Flask server starting on {self.server.server_address}")
        self.server.serve_forever()

    def shutdown(self):
        logging.info("Shutting down Flask server...")
        self.server.shutdown()


# Async UDP server for status updates
async def udp_server(shutdown_event, cleanup_interval=1, stale_threshold=10):
    loop = asyncio.get_running_loop()
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("0.0.0.0", 5001))
    udp_socket.setblocking(False)  # Set socket to non-blocking mode
    logging.info("UDP server bound to 0.0.0.0:5001 and set to non-blocking mode.")

    last_cleanup = time.time()

    while not shutdown_event.is_set():
        try:
            # Calculate remaining time until next cleanup
            now = time.time()
            time_until_cleanup = cleanup_interval - (now - last_cleanup)
            if time_until_cleanup <= 0:
                # Perform cleanup
                with client_statuses_lock:
                    current_time = time.time()
                    stale_ips = [ip for ip, info in client_statuses.items() if current_time - info['last_seen'] > stale_threshold]
                    for ip in stale_ips:
                        logging.info(f"Removing stale client_status for IP: {ip}")
                        del client_statuses[ip]
                last_cleanup = now
                # Continue to next iteration
                continue

            # Wait for data or until it's time to cleanup
            timeout = max(time_until_cleanup, 0.1)  # Ensure a minimal timeout
            data, addr = await asyncio.wait_for(loop.sock_recvfrom(udp_socket, 1024), timeout=timeout)
            try:
                message = verify_and_decrypt_message(data, aes_key, hmac_key)
                logging.info(f"Received from {addr[0]}: {message.decode('utf-8')}")
                with client_statuses_lock:
                    client_statuses[addr[0]] = {
                        'data': message.decode("utf-8"),
                        'last_seen': time.time()
                    }
            except ValueError as e:
                print("Message authentication failed:", e)
            
        except asyncio.TimeoutError:
            # Timeout reached, loop will perform cleanup if necessary
            continue
        except Exception as e:
            logging.error(f"Error receiving UDP data: {e}")
            break

    udp_socket.close()
    logging.info("UDP server has been shut down.")



# Async TCP server for alerts with TLS
async def handle_alert(reader, writer):
    addr = writer.get_extra_info("peername")
    try:
        alert = await reader.read(1024)
        alert_text = alert.decode('utf-8')
        logging.info(f"Alert from {addr[0]}: {alert_text}")
        alertObject = json.loads(alert_text)
        # Append the alert to the alerts list with thread-safe access
        with alerts_lock:
            alerts.append({
                'timestamp': datetime.now().isoformat(),
                'source': addr[0],
                'event_name': alertObject['event_name'],
                'details': alertObject['details'],
                'event_id': alertObject['event_id']
            })
            # Ensure the alerts list does not exceed 100 entries
            if len(alerts) > 100:
                alerts.pop(0)  # Remove the oldest alert
    except Exception as e:
        logging.error(f"Error handling alert from {addr[0]}: {e}")
    finally:
        writer.close()
        await writer.wait_closed()


async def tcp_server(shutdown_event):
    try:
        server = await asyncio.start_server(handle_alert, "0.0.0.0", 5002, ssl=ssl_context)
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        logging.info(f"TCP server listening on {addrs}")

        # Serve until shutdown_event is set
        await shutdown_event.wait()

        # Initiate server shutdown
        server.close()
        await server.wait_closed()
        logging.info("TCP server has been shut down.")
    except asyncio.CancelledError:
        logging.info("TCP server is shutting down...")
    except Exception as e:
        logging.error(f"Failed to start TCP server: {e}")


# Background scanner with shutdown support
def start_background_scanner(shutdown_event):
    while not shutdown_event.is_set():
        monitor.get_connected_devices()
        for _ in range(30):
            if shutdown_event.is_set():
                break
            time.sleep(1)
    logging.info("Background scanner has been shut down.")


async def main():
    # Event to signal shutdown
    shutdown_event = asyncio.Event()

   # Cross-platform signal handling
    if platform.system() != 'Windows':
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, shutdown_event.set)
    else:
        # For Windows, we'll rely on KeyboardInterrupt outside of this function
        logging.info("Running on Windows; shutdown will rely on KeyboardInterrupt")

    # Start Flask server
    flask_server = FlaskServerThread(app, host="0.0.0.0", port=3000)
    flask_server.start()

    # Start background scanner thread
    scanner_shutdown_event = threading.Event()
    scanner_thread = threading.Thread(target=start_background_scanner, args=(scanner_shutdown_event,), daemon=True)
    scanner_thread.start()

    # Start UDP and TCP servers
    udp_task = asyncio.create_task(udp_server(shutdown_event))
    tcp_task = asyncio.create_task(tcp_server(shutdown_event))

    # Wait for shutdown_event to be set
    await shutdown_event.wait()
    logging.info("Shutdown signal received.")

    # Initiate shutdown sequence
    # Shutdown Flask server
    flask_server.shutdown()
    flask_server.join()

    # Shutdown background scanner
    scanner_shutdown_event.set()
    scanner_thread.join()

    # Cancel UDP and TCP server tasks
    udp_task.cancel()
    tcp_task.cancel()

    # Wait for servers to shut down
    try:
        await asyncio.gather(udp_task, tcp_task, return_exceptions=True)
    except Exception as e:
        logging.error(f"Error during server shutdown: {e}")

    logging.info("All servers have been shut down gracefully.")


# Initialize SafeNetworkMonitor
monitor = SafeNetworkMonitor()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Server shutdown requested by user.")
        asyncio.run(main().shutdown_event.set())
    except Exception as e:
        logging.error(f"Server encountered an unexpected error: {e}")
