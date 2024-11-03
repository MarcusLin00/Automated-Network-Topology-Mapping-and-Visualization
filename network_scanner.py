import io
import ipaddress
import json
import logging
import threading
import time

import matplotlib
matplotlib.use('Agg')  # Use 'Agg' backend for matplotlib (headless environments)
import matplotlib.pyplot as plt
import netifaces
import networkx as nx
import nmap
import pyshark
from flask import Flask, render_template, Response

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s:%(message)s')

app = Flask(__name__)


class SafeNetworkMonitor:
    """Network Monitor that safely scans and captures network data."""

    def __init__(self):
        """Initialize the SafeNetworkMonitor."""
        self.devices = {}
        self.G = nx.Graph()
        self.status = 'Idle'
        self.capture = None
        self.lock = threading.Lock()

    def _get_default_interface(self):
        """Get the default network interface used for the default gateway."""
        try:
            gateways = netifaces.gateways()
            logging.debug(f"Gateways: {gateways}")
            default_interface = gateways['default'][netifaces.AF_INET][1]
            logging.debug(f"Default interface: {default_interface}")
            return default_interface
        except KeyError as e:
            logging.error(f"Default interface not found: {e}")
            return None
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            return None

    def _get_my_ip_address(self):
        """Get the IP address of the default network interface."""
        default_interface = self._get_default_interface()
        if default_interface:
            addrs = netifaces.ifaddresses(default_interface)
            if netifaces.AF_INET in addrs:
                iface_info = addrs[netifaces.AF_INET][0]
                ip_addr = iface_info.get('addr')
                logging.debug(f"IP address of default interface {default_interface}: {ip_addr}")
                return ip_addr
        logging.error("Failed to get IP address of default interface.")
        return None

    def _get_default_mac(self):
        """Get the MAC address of the default network interface."""
        default_interface = self._get_default_interface()
        if default_interface:
            addrs = netifaces.ifaddresses(default_interface)
            if netifaces.AF_LINK in addrs:
                iface_info = addrs[netifaces.AF_LINK][0]
                mac_addr = iface_info.get('addr')
                logging.debug(f"MAC address of default interface {default_interface}: {mac_addr}")
                return mac_addr.upper()
        logging.error("Failed to get MAC address of default interface.")
        return 'N/A'

    def _get_default_gateway(self):
        """Get the default gateway IP address."""
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            logging.debug(f"Default gateway: {default_gateway}")
            return default_gateway
        except KeyError:
            logging.error("Default gateway not found.")
            return None

    def _get_subnet(self):
        """Get the subnet (network address and prefix length) for the default interface."""
        default_interface = self._get_default_interface()
        if default_interface:
            addrs = netifaces.ifaddresses(default_interface)
            if netifaces.AF_INET in addrs:
                iface_info = addrs[netifaces.AF_INET][0]
                ip_addr = iface_info.get('addr')
                netmask = iface_info.get('netmask')
                if ip_addr and netmask:
                    ip_interface = ipaddress.IPv4Interface(f"{ip_addr}/{netmask}")
                    network = ip_interface.network
                    return network
        return None

    def start_packet_capture(self):
        """Start capturing packets using pyshark."""
        try:
            interface = self._get_default_interface()
            if not interface:
                logging.error("No default network interface found.")
                return
            logging.info(f"Starting packet capture on interface: {interface}")
            # Capture broadcast, multicast, ARP, and IP traffic
            bpf_filter = ''
            logging.debug(f"Using BPF filter: {bpf_filter}")
            self.capture = pyshark.LiveCapture(
                interface=interface,
                bpf_filter=bpf_filter
            )
            for packet in self.capture.sniff_continuously():
                self.process_packet(packet)
        except Exception as e:
            logging.error(f"Error in start_packet_capture: {e}")

    def process_packet(self, packet):
        """Process a captured packet and update data usage statistics."""
        try:
            if 'IP' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                length = int(packet.length)
                subnet = self._get_subnet()
                if subnet:
                    with self.lock:
                        if ipaddress.ip_address(src_ip) in subnet:
                            # Update data sent from source IP
                            if src_ip in self.devices:
                                self.devices[src_ip]['data_sent'] += length
                                self.devices[src_ip]['last_seen'] = time.time()
                            else:
                                self.devices[src_ip] = {
                                    'mac': 'N/A',
                                    'last_seen': time.time(),
                                    'data_sent': length,
                                    'data_received': 0
                                }
                        if ipaddress.ip_address(dst_ip) in subnet:
                            # Update data received by destination IP
                            if dst_ip in self.devices:
                                self.devices[dst_ip]['data_received'] += length
                                self.devices[dst_ip]['last_seen'] = time.time()
                            else:
                                self.devices[dst_ip] = {
                                    'mac': 'N/A',
                                    'last_seen': time.time(),
                                    'data_sent': 0,
                                    'data_received': length
                                }
        except AttributeError as e:
            logging.debug(f"Packet missing expected fields: {e}")
        except Exception as e:
            logging.error(f"Error processing packet: {e}")


    def get_connected_devices(self):
        """Active scanning: discover devices using ARP requests, ICMP pings, etc."""
        with self.lock:
            self.status = 'Scanning...'
        nm = nmap.PortScanner()
        subnet = self._get_subnet()
        if subnet:
            network = str(subnet)
            logging.debug(f"Scanning network: {network}")
            nm.scan(hosts=network, arguments='-sn')
            with self.lock:
                current_time = time.time()
                for host in nm.all_hosts():
                    ip = host
                    mac = nm[host]['addresses'].get('mac', 'N/A')
                    if ip in self.devices:
                        # Update existing device
                        self.devices[ip]['mac'] = mac
                        self.devices[ip]['last_seen'] = current_time
                    else:
                        # Add new device
                        self.devices[ip] = {
                            'mac': mac,
                            'last_seen': current_time,
                            'data_sent': 0,
                            'data_received': 0
                        }
                # Update or add the current device
                my_ip = self._get_my_ip_address()
                my_mac = self._get_default_mac()
                if my_ip:
                    if my_ip in self.devices:
                        self.devices[my_ip]['mac'] = my_mac
                        self.devices[my_ip]['last_seen'] = current_time
                    else:
                        self.devices[my_ip] = {
                            'mac': my_mac,
                            'last_seen': current_time,
                            'data_sent': 0,
                            'data_received': 0
                        }
                # Remove devices not seen for a certain period
                stale_threshold = 300  # Time in seconds (e.g., 300 seconds = 5 minutes)
                stale_devices = []
                for ip, info in self.devices.items():
                    if current_time - info['last_seen'] > stale_threshold:
                        stale_devices.append(ip)
                for ip in stale_devices:
                    del self.devices[ip]
                self._update_graph()
                self.status = f"Last scanned at {time.strftime('%Y-%m-%d %H:%M:%S')}"
        else:
            logging.error("Could not determine subnet for scanning.")
            with self.lock:
                 self.status = 'Error: Subnet not determined'

    def _update_graph(self):
        """Update the network visualization graph."""
        self.G.clear()
        subnet = self._get_subnet()
        if not subnet:
            logging.error("Could not determine subnet for updating graph.")
            return
        # Add nodes for each device in the subnet
        for ip, info in self.devices.items():
            if ipaddress.ip_address(ip) in subnet:
                self.G.add_node(ip, mac=info.get('mac', 'Unknown'))
        # Add the gateway if it's in the subnet
        gateway_ip = self._get_default_gateway()
        if gateway_ip and ipaddress.ip_address(gateway_ip) in subnet:
            if gateway_ip not in self.G.nodes:
                self.G.add_node(gateway_ip, mac='Gateway')
            # Add edges from the gateway to each device
            for ip in self.G.nodes:
                if ip != gateway_ip:
                    self.G.add_edge(gateway_ip, ip)

    def create_graph_image(self):
        """Generate network visualization."""
        with self.lock:
            G_copy = self.G.copy()
        plt.figure(figsize=(10, 8))
        pos = nx.spring_layout(G_copy)
        my_ip = self._get_my_ip_address()
        node_colors = []
        for node in G_copy.nodes:
            if node == my_ip:
                node_colors.append('green')  # Your device
            elif node == self._get_default_gateway():
                node_colors.append('red')    # Gateway
            else:
                node_colors.append('blue')   # Other devices
        nx.draw(G_copy, pos,
                with_labels=True,
                node_color=node_colors,
                node_size=500,
                font_size=8)
        plt.title("Network Map")
        # Save to buffer
        img = io.BytesIO()
        plt.savefig(img, format='png', bbox_inches='tight')
        img.seek(0)
        plt.close()
        return img


# Initialize monitor
monitor = SafeNetworkMonitor()


def packet_capture_thread():
    """Thread function to start packet capture."""
    monitor.start_packet_capture()


def background_scanner():
    """Background thread function for device scanning."""
    while True:
        monitor.get_connected_devices()
        time.sleep(30)  # Scan every 30 seconds


@app.route('/graph.png')
def graph_png():
    """Serve the network graph image as a PNG."""
    img = monitor.create_graph_image()
    return Response(img.getvalue(), mimetype='image/png')


@app.route('/devices')
def get_devices():
    """Return the current device list as JSON."""
    with monitor.lock:
        subnet = monitor._get_subnet()
        if subnet:
            devices_in_subnet = {
                ip: info for ip, info in monitor.devices.items()
                if ipaddress.ip_address(ip) in subnet
            }
        else:
            devices_in_subnet = {}
    return json.dumps(devices_in_subnet)


@app.route('/status')
def get_status():
    """Return the current status as JSON."""
    with monitor.lock:
        status = monitor.status
    return json.dumps({'status': status})


@app.route('/')
def index():
    """Serve the main page."""
    return render_template('index.html', title='Network Scanner')


if __name__ == '__main__':
    # Start background scanner
    scanner_thread = threading.Thread(target=background_scanner, daemon=True)
    scanner_thread.start()

    # Start packet capture thread
    capture_thread = threading.Thread(target=packet_capture_thread, daemon=True)
    capture_thread.start()

    # Run Flask app on localhost:3000
    app.run(debug=True, host='0.0.0.0', port=3000)
