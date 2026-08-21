import json
import os
import socket
import time
from Crypto.Cipher import AES

VALID_KEY = b"12345678901234567890123456789012"
MALICIOUS_KEY = b"99999999999999999999999999999999"


def send_raw_payload(sock, payload):
  length_header = len(payload).to_bytes(4, byteorder="big")
  sock.sendall(length_header + payload)


def run_attack_suite():
  attacker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  try:
    attacker_socket.connect(("127.0.0.1", 5000))
    print("👾 Attacker connected to Receiver on port 5000!\n")
  except Exception as e:
    print(
        f"❌ Connection failed: {e}. Make sure Receiver.py is running first."
    )
    return

  # 1. REPLAY ATTACK (Sending an old sequence number)
  print("--- ATTACK 1: Executing Replay Attack ---")
  stale_payload = {
      "sequence_id": 1,
      "timestamp": time.time(),
      "engine_id": "GAB_01",
      "temperature_c": 850.5,
      "pressure_psi": 145.2,
      "rpm": 12500,
      "vibration_mms": 0.04,
  }
  raw_bytes = json.dumps(stale_payload).encode("utf-8")
  nonce = os.urandom(12)
  cipher = AES.new(VALID_KEY, AES.MODE_GCM, nonce=nonce)
  ciphertext, auth_tag = cipher.encrypt_and_digest(raw_bytes)
  send_raw_payload(attacker_socket, nonce + auth_tag + ciphertext)
  print("⚠️ Replay packet (Seq #1) sent to Receiver.\n")
  time.sleep(2)

  # 2. PAYLOAD TAMPERING ATTACK
  print("--- ATTACK 2: Executing Payload Tampering Attack ---")
  valid_payload = {
      "sequence_id": 999,
      "timestamp": time.time(),
      "engine_id": "GAB_01",
      "temperature_c": 1200.0,
      "pressure_psi": 145.2,
      "rpm": 12500,
      "vibration_mms": 0.04,
  }
  raw_bytes = json.dumps(valid_payload).encode("utf-8")
  nonce = os.urandom(12)
  cipher = AES.new(VALID_KEY, AES.MODE_GCM, nonce=nonce)
  ciphertext, auth_tag = cipher.encrypt_and_digest(raw_bytes)
  tampered_ciphertext = ciphertext[:-1] + b"\x00"  # Corrupt last byte
  send_raw_payload(attacker_socket, nonce + auth_tag + tampered_ciphertext)
  print("⚠️ Tampered ciphertext packet sent to Receiver.\n")
  time.sleep(2)

  # 3. UNAUTHORIZED KEY ATTACK
  print("--- ATTACK 3: Executing Unauthorized Key Attack ---")
  unauthorized_payload = {
      "sequence_id": 1000,
      "timestamp": time.time(),
      "engine_id": "GAB_01",
      "temperature_c": 850.5,
      "pressure_psi": 145.2,
      "rpm": 12500,
      "vibration_mms": 0.04,
  }
  raw_bytes = json.dumps(unauthorized_payload).encode("utf-8")
  nonce = os.urandom(12)
  bad_cipher = AES.new(MALICIOUS_KEY, AES.MODE_GCM, nonce=nonce)
  bad_ciphertext, bad_tag = bad_cipher.encrypt_and_digest(raw_bytes)
  send_raw_payload(attacker_socket, nonce + bad_tag + bad_ciphertext)
  print("⚠️ Packet with unauthorized key sent to Receiver.\n")

  attacker_socket.close()


if __name__ == "__main__":
  run_attack_suite()