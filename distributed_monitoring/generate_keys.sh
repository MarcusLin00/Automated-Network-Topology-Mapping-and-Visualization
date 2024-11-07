#!/bin/bash

# Set the file paths for the AES key
AES_KEY_FILE_CLIENT="./client/aes_key.pem"
AES_KEY_FILE_SERVER="./server/aes_key.pem"

# Prompt for a passphrase to encrypt the AES key
echo "Enter a passphrase to encrypt the AES key:"
read -s PASSPHRASE

# Generate a 256-bit AES key (32 bytes)
AES_KEY=$(openssl rand -hex 32)  # Generate a 256-bit key in hexadecimal format

# Encrypt and write the AES key to the client and server PEM files with PBKDF2 and iterations
echo -n "$AES_KEY" | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -pass pass:"$PASSPHRASE" -out "$AES_KEY_FILE_CLIENT" -a
echo -n "$AES_KEY" | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -pass pass:"$PASSPHRASE" -out "$AES_KEY_FILE_SERVER" -a

# Check if the AES key was saved successfully
if [[ $? -ne 0 ]]; then
    echo "Failed to save the AES key."
    exit 1
fi

# Set restrictive permissions on both AES key files
chmod 600 "$AES_KEY_FILE_CLIENT"
chmod 600 "$AES_KEY_FILE_SERVER"

echo "AES key generated, encrypted with PBKDF2 and iterations, and saved to $AES_KEY_FILE_CLIENT and $AES_KEY_FILE_SERVER"
