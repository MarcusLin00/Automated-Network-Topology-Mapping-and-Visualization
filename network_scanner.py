import nmap
import networkx as nx
import matplotlib.pyplot as plt
from flask import Flask, render_template, Response
from threading import Thread
from collections import defaultdict
import io
import time

# Flask app setup
app = Flask(__name__)

class NetworkScanner:
    def __init__(self):
        self.G = nx.Graph()
        self.device_info = {}
        self.nm = nmap.PortScanner()
    
    # Change network_range to scanning range (e.g 172.. is for mobile hotspot)
    def scan_network(self, network_range='172.20.10.0/24'):
        """Safely scan the network and classify devices"""
        try:
            
            self.nm.scan(hosts=network_range, arguments='-sT -T2 -p 22,80,443')
            
            for host in self.nm.all_hosts():
                services = self.nm[host].all_tcp()
                print(services)
                # Classify device based on open ports
                if 80 in services or 443 in services:
                    role = "Web Server"
                    color = 'red'
                elif 22 in services:
                    role = "SSH Server"
                    color = 'green'
                else:
                    role = "Client"
                    color = 'blue'
                
                self.device_info[host] = role
                self.G.add_node(host, role=role, color=color)
                
                # Add edges to existing nodes
                for other_host in self.device_info.keys():
                    if other_host != host:
                        self.G.add_edge(host, other_host)
                        
                print(f"Discovered: {host}, Role: {role}")
                
        except Exception as e:
            print(f"Scanning error: {str(e)}")
    
    def create_graph_image(self):
        """Generate network topology visualization"""
        plt.figure(figsize=(10, 8))
        pos = nx.spring_layout(self.G)
        colors = [nx.get_node_attributes(self.G, 'color')[node] for node in self.G.nodes]
        
        nx.draw(self.G, pos, 
                with_labels=True, 
                node_color=colors, 
                node_size=500, 
                font_size=10,
                font_weight='bold')
        
        plt.title("Network Topology")
        
        img = io.BytesIO()
        plt.savefig(img, format='png', bbox_inches='tight')
        img.seek(0)
        plt.close()  # Properly close the figure
        
        return img

# Initialize scanner
scanner = NetworkScanner()

def background_scanner():
    """Background thread for continuous network scanning"""
    while True:
        scanner.scan_network()
        time.sleep(300)  # Scan every 5 minutes

@app.route('/graph.png')
def graph_png():
    """Route to serve the network graph"""
    img = scanner.create_graph_image()
    return Response(img.getvalue(), mimetype='image/png')

@app.route('/')
def index():
    """Home page route"""
    return render_template('index.html')

# Create the HTML template
@app.route('/template')
def get_template():
    """Return the HTML template content - for development purposes"""
    return """
<!DOCTYPE html>
<html>
<head>
    <title>Network Topology Viewer</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            text-align: center;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        .graph-container {
            margin-top: 20px;
        }
        .graph-image {
            max-width: 100%;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Network Topology Viewer</h1>
        <div class="graph-container">
            <img src="{{ url_for('graph_png') }}" class="graph-image" id="graph">
        </div>
        <script>
            // Refresh the graph every 30 seconds
            setInterval(function() {
                const graph = document.getElementById('graph');
                graph.src = "{{ url_for('graph_png') }}?" + new Date().getTime();
            }, 30000);
        </script>
    </div>
</body>
</html>
"""

if __name__ == '__main__':
    # Start the background scanner thread
    scanner_thread = Thread(target=background_scanner, daemon=True)
    scanner_thread.start()
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000)