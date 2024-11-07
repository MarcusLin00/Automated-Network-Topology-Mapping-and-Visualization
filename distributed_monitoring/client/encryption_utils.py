import os
import hmac
import base64
import hashlib
import subprocess
import sys  
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_and_authenticate_message(message, aes_key, hmac_key):
    """Encrypts and authenticates a message using AES-GCM and HMAC."""
    # Convert message to bytes if it's not already
    if isinstance(message, str):
        message = message.encode('utf-8')

    # Generate a random nonce (12 bytes for AES-GCM)
    nonce = os.urandom(12)
    
    # Encrypt the message with AES-GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message) + encryptor.finalize()
    tag = encryptor.tag
    
    # Construct the payload: nonce + ciphertext + tag
    payload = nonce + ciphertext + tag
    
    # Generate HMAC for the payload using hashlib.sha256
    hmac_obj = hmac.new(hmac_key, payload, digestmod=hashlib.sha256)
    hmac_digest = hmac_obj.digest()
    
    # Combine payload and HMAC, then Base64 encode for transmission
    final_message = payload + hmac_digest
    encoded_message = base64.b64encode(final_message)
    
    return encoded_message

def verify_and_decrypt_message(received_data, aes_key, hmac_key):
    # Decode the received data from Base64
    decoded_data = base64.b64decode(received_data)

    # Separate HMAC from payload (last 32 bytes is HMAC if SHA-256 was used)
    hmac_received = decoded_data[-32:]
    payload = decoded_data[:-32]

    # Verify the HMAC for authenticity using hashlib.sha256
    hmac_obj = hmac.new(hmac_key, payload, digestmod=hashlib.sha256)
    if not hmac.compare_digest(hmac_obj.digest(), hmac_received):
        raise ValueError("Message authentication failed")

    # Extract nonce, ciphertext, and tag from the payload
    nonce = payload[:12]
    ciphertext = payload[12:-16]
    tag = payload[-16:]

    # Decrypt the message with AES-GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext

def load_aes_key(file_path, passphrase):
    """Loads and decrypts an AES key from a PEM file using OpenSSL."""
    try:
        # Use OpenSSL command to decrypt the AES key from the PEM file
        decrypted_key = subprocess.check_output([
            "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "100000",
            "-in", file_path, "-pass", f"pass:{passphrase}", "-a"
        ])
        print("AES key loaded successfully.")
        return decrypted_key
    except subprocess.CalledProcessError as e:
        print("Failed to decrypt AES key. Please check your passphrase and try again.")
        print("Error details:", e)
        sys.exit(1)  

def derive_keys(original_aes_key):
    """Derives two separate 256-bit keys (32 bytes each) from the original AES key."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,  # 32 bytes for AES key, 32 bytes for HMAC key
        salt=None,
        info=b'udp-encryption',
        backend=default_backend()
    )
    derived_keys = hkdf.derive(original_aes_key)
    aes_key = derived_keys[:32]
    hmac_key = derived_keys[32:]
    return aes_key, hmac_key
