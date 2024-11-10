#!/bin/bash

# Function to get IP address for macOS and Linux
get_ip_unix() {
  if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    IP=$(ifconfig en0 | grep "inet " | awk '{print $2}')
    # Uncomment the line below if using Ethernet or another interface
    # IP=$(ifconfig en1 | grep "inet " | awk '{print $2}')
  else
    # Linux
    IP=$(hostname -I | awk '{print $1}')
  fi

  echo "$IP"
}

# Function to get IP address for Windows using PowerShell
get_ip_windows() {
  # Find interface name dynamically, prioritizing Wi-Fi, then Ethernet
  INTERFACE_NAME=$(powershell.exe -Command "(Get-NetAdapter | Where-Object { \$_.Name -match 'Wi-Fi|WiFi|Ethernet' }).Name" | tr -d '\r')

  # Fetch the IP address for the selected interface, excluding APIPA (169.254.x.x) addresses
  IP=$(powershell.exe -Command "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { \$_.InterfaceAlias -eq '$INTERFACE_NAME' -and \$_.IPAddress -notmatch '^169\.254' }).IPAddress" | tr -d '\r')

  echo "$IP"
}

# Determine OS type and get the IP address
echo "OSTYPE is: $OSTYPE"
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
  # Windows
  CURRENT_IP=$(get_ip_windows | head -n 1)  # Get only the first valid IP
else
  # macOS or Linux
  CURRENT_IP=$(get_ip_unix)
fi

# Prompt user for IP if detection fails
if [ -z "$CURRENT_IP" ]; then
  echo "Could not automatically determine IP address."
  read -p "Please enter your IP address manually: " USER_IP
  CURRENT_IP="$USER_IP"
fi

# Ensure we have a valid IP before proceeding
if [ -z "$CURRENT_IP" ]; then
  echo "No valid IP address provided. Exiting."
  exit 1
fi

echo "Detected IP: $CURRENT_IP"

# Define paths to /server and /client directories
SERVER_DIR="./server"
CLIENT_DIR="./client"

# Ensure directories exist
mkdir -p "$SERVER_DIR" "$CLIENT_DIR"

# Generate OpenSSL configuration file
cat <<EOF > openssl.cnf
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[ dn ]
C  = US
ST = State
L  = City
O  = Organization
OU = Organizational Unit
CN = $CURRENT_IP

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = $CURRENT_IP
EOF

# Generate private key and CSR directly in the server directory
openssl req -new -out "$SERVER_DIR/server.csr" -newkey rsa:2048 -nodes -keyout "$SERVER_DIR/server.key" -config openssl.cnf

# Generate self-signed certificate in the server directory
openssl x509 -req -in "$SERVER_DIR/server.csr" -signkey "$SERVER_DIR/server.key" -out "$SERVER_DIR/server.crt" -days 365 -extensions req_ext -extfile openssl.cnf

# Copy the generated certificate to the client directory
cp "$SERVER_DIR/server.crt" "$CLIENT_DIR/server.crt"

# Verification step
echo "Generated certificate for IP: $CURRENT_IP"
openssl x509 -in "$SERVER_DIR/server.crt" -text -noout | grep -A1 "Subject Alternative Name"

# Cleanup
rm -f "$SERVER_DIR/server.csr" openssl.cnf
