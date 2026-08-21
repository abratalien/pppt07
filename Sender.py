import json
import os
import socket
import time
from Crypto.Cipher import AES

SECRET_KEY = b"12345678901234567890123456789012"  # 32-Byte Key

sender_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sender_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

# Connect to localhost (or Receiver IP during 2-PC demo)
sender_socket.connect(("127.0.0.1", 5000))
print("🚀 Connected to Receiver! Streaming encrypted telemetry until Ctrl+C...\n")

packet_sequence = 0

try:
    while True:
        packet_sequence += 1

        telemetry_payload = {
            "sequence_id": packet_sequence,
            "timestamp": time.time(),
            "engine_id": "GTRE_GT_01",
            "temperature_c": 859.5,
            "pressure_psi": 145.2,
            "rpm": 12500,
            "vibration_mms": 0.04,
        }

        # Serialize
        raw_bytes = json.dumps(telemetry_payload).encode("utf-8")

        # AES-256-GCM Encryption
        nonce = os.urandom(12)  # Standard GCM 12-byte nonce
        cipher = AES.new(SECRET_KEY, AES.MODE_GCM, nonce=nonce)
        ciphertext, auth_tag = cipher.encrypt_and_digest(raw_bytes)

        # Wire Payload: [12B Nonce] + [16B Tag] + [Ciphertext]
        payload = nonce + auth_tag + ciphertext

        # Add 4-byte length header to prevent TCP packet sticking
        length_header = len(payload).to_bytes(4, byteorder="big")
        wire_packet = length_header + payload

        sender_socket.sendall(wire_packet)
        print(f"📡 Sent Encrypted Packet #{packet_sequence}")

        time.sleep(1)  # 1 second transmit interval

except KeyboardInterrupt:
    print("\n\n⏹️ Transmission stopped by user (Ctrl+C).")
finally:
    sender_socket.close()