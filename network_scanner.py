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
import time
from collections import defaultdict, deque
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
            return gateways['default'][netifaces.AF_INET][1]
        except KeyError:
            logging.error("Default interface not found.")
            return None

    def _get_interface_info(self, interface, address_type):
        """Helper function to get specific interface information."""
        addrs = netifaces.ifaddresses(interface)
        if address_type in addrs:
            return addrs[address_type][0]
        return None

    def _get_ip_address(self):
        """Get the IP address of the default network interface."""
        default_interface = self._get_default_interface()
        if default_interface:
            iface_info = self._get_interface_info(default_interface, netifaces.AF_INET)
            ip_addr = iface_info.get('addr') if iface_info else None
            logging.debug(f"IP address of default interface {default_interface}: {ip_addr}")
            return ip_addr
        logging.error("Failed to get IP address.")
        return None

    def _get_mac_address(self):
        """Get the MAC address of the default network interface."""
        default_interface = self._get_default_interface()
        if default_interface:
            iface_info = self._get_interface_info(default_interface, netifaces.AF_LINK)
            mac_addr = iface_info.get('addr') if iface_info else 'N/A'
            logging.debug(f"MAC address of default interface {default_interface}: {mac_addr}")
            return mac_addr.upper()
        logging.error("Failed to get MAC address.")
        return 'N/A'

    def _get_default_gateway(self):
        """Get the default gateway IP address."""
        try:
            return netifaces.gateways()['default'][netifaces.AF_INET][0]
        except KeyError:
            logging.error("Default gateway not found.")
            return None

    def _get_subnet(self):
        """Get the subnet (network address and prefix length) for the default interface."""
        default_interface = self._get_default_interface()
        if default_interface:
            iface_info = self._get_interface_info(default_interface, netifaces.AF_INET)
            if iface_info:
                ip_interface = ipaddress.IPv4Interface(f"{iface_info['addr']}/{iface_info['netmask']}")
                return ip_interface.network
        return None

    def get_connected_devices(self):
        """Active scanning: discover devices using ARP requests, ICMP pings, etc."""
        with self.lock:
            self.status = 'Scanning...'
        nm = nmap.PortScanner()
        subnet = self._get_subnet()
        if subnet:
            self._scan_network(nm, subnet)
        else:
            logging.error("Could not determine subnet for scanning.")
            with self.lock:
                 self.status = 'Error: Subnet not determined'

    def _scan_network(self, nm, subnet):
        """Scan the network for active devices."""
        network = str(subnet)
        nm.scan(hosts=network, arguments='-sn')
        current_time = time.time()
        with self.lock:
            for host in nm.all_hosts():
                self._update_device_info(host, nm, current_time)
            self._add_current_device(current_time)
            self._remove_stale_devices(current_time)

    def _update_device_info(self, host, nm, current_time):
        """Update or add information for a scanned device."""
        ip, mac = host, nm[host]['addresses'].get('mac', 'N/A')
        if ip in self.devices:
            self.devices[ip].update(mac=mac, last_seen=current_time)
        else:
            self.devices[ip] = {'mac': mac, 'last_seen': current_time }

    def _add_current_device(self, current_time):
        """Add or update the current device in the device list."""
        my_ip, my_mac = self._get_ip_address(), self._get_mac_address()
        if my_ip:
            self.devices[my_ip] = self.devices.get(my_ip, {})
            self.devices[my_ip].update(mac=my_mac, last_seen=current_time)

    def _remove_stale_devices(self, current_time, stale_threshold=300):
        """Remove devices that haven't been seen recently."""
        stale_devices = [ip for ip, info in self.devices.items() if current_time - info['last_seen'] > stale_threshold]
        for ip in stale_devices:
            del self.devices[ip]
        self._update_graph()

    def _update_graph(self):
        """Update the network visualization graph."""
        self.G.clear()
        subnet = self._get_subnet()
        if not subnet:
            logging.error("Could not determine subnet for updating graph.")
            return
        self._add_nodes_to_graph(subnet)
        self._add_edges_to_graph()

    def _add_nodes_to_graph(self, subnet):
        """Add nodes for each device in the subnet."""
        for ip, info in self.devices.items():
            if ipaddress.ip_address(ip) in subnet:
                self.G.add_node(ip, mac=info.get('mac', 'Unknown'))

    def _add_edges_to_graph(self):
        """Add edges from the gateway to each device in the graph."""
        gateway_ip = self._get_default_gateway()
        if gateway_ip and gateway_ip in self.G.nodes:
            for ip in self.G.nodes:
                if ip != gateway_ip:
                    self.G.add_edge(gateway_ip, ip)

    def create_graph_image(self):
        """Generate network visualization as an image."""
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
                #with_labels=True,
                node_color=node_colors,
                node_size=500,
                font_size=8)
        
        label_pos = {node: (x, y - 0.08) for node, (x, y) in pos.items()}
        nx.draw_networkx_labels(G_copy, label_pos, font_size=8)


        plt.title("Network Map")
        img = io.BytesIO()
        plt.savefig(img, format='png', bbox_inches='tight')
        img.seek(0)
        plt.close()
        return img

    def _assign_node_colors(self, G_copy, my_ip):
        """Assign colors to nodes based on their type."""
        node_colors = []
        gateway_ip = self._get_default_gateway()
        for node in G_copy.nodes:
            if node == my_ip:
                node_colors.append('green')  # Your device
            elif node == gateway_ip:
                node_colors.append('red')    # Gateway
            else:
                node_colors.append('blue')   # Other devices
        return node_colors


# Initialize monitor
monitor = SafeNetworkMonitor()


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
        devices_in_subnet = {ip: info for ip, info in monitor.devices.items() if ipaddress.ip_address(ip) in subnet} if subnet else {}
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

    # Run Flask app on localhost:3000
    app.run(debug=True, host='0.0.0.0', port=3000)
