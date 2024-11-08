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

  if [ -z "$IP" ]; then
    echo "Could not determine IP address. Make sure you're connected to a network."
    exit 1
  fi

  echo "$IP"
}

# Function to get IP address for Windows using PowerShell
get_ip_windows() {
  # Try to get IP from Wi-Fi interface
  IP=$(powershell.exe -Command "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { \$_.InterfaceAlias -eq 'Wi-Fi' }).IPAddress")
  IP=$(echo "$IP" | tr -d '\r')

  # If IP is empty, try Ethernet interface
  if [ -z "$IP" ]; then
    IP=$(powershell.exe -Command "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { \$_.InterfaceAlias -eq 'Ethernet' }).IPAddress")
    IP=$(echo "$IP" | tr -d '\r')
  fi

  # If still empty, show an error
  if [ -z "$IP" ]; then
    echo "Could not determine IP address. Make sure you're connected to a network."
    exit 1
  fi

  echo "$IP"
}

# Determine OS type and get the IP address
echo "OSTYPE is: $OSTYPE"
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
  # Windows
  CURRENT_IP=$(get_ip_windows)
else
  # macOS or Linux
  CURRENT_IP=$(get_ip_unix)
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