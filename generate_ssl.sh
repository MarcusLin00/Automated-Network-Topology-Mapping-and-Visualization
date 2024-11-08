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
  IP=$(powershell.exe -Command "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { \$_.InterfaceAlias -eq 'Wi-Fi' -or \$_.InterfaceAlias -eq 'Ethernet' }).IPAddress")
  IP=$(echo "$IP" | tr -d '\r')

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

# Generate private key and CSR
openssl req -new -out server.csr -newkey rsa:2048 -nodes -keyout server.key -config openssl.cnf

# Generate self-signed certificate
openssl x509 -req -in server.csr -signkey server.key -out server.crt -days 365 -extensions req_ext -extfile openssl.cnf

# Verification step
echo "Generated certificate for IP: $CURRENT_IP"
openssl x509 -in server.crt -text -noout | grep -A1 "Subject Alternative Name"

# Define paths to /server and /client directories
SERVER_DIR="./server"
CLIENT_DIR="./client"

# Copy the generated certificate and key to /server
if [[ -d "$SERVER_DIR" ]]; then
  cp server.crt "$SERVER_DIR/server.crt"
  cp server.key "$SERVER_DIR/server.key"
  echo "Copied server.crt and server.key to /server directory."
else
  echo "/server directory not found."
fi

# Copy the generated certificate to /client
if [[ -d "$CLIENT_DIR" ]]; then
  cp server.crt "$CLIENT_DIR/server.crt"
  echo "Copied server.crt to /client directory."
else
  echo "/client directory not found."
fi

# Cleanup
rm -f server.csr openssl.cnf
