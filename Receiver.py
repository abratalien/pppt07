import json
import socket
from Crypto.Cipher import AES

SECRET_KEY = b"12345678901234567890123456789012"  # 32-Byte Key

# PHASE 4: PHYSICAL ENGINE SAFETY THRESHOLDS
MAX_SAFE_TEMP_C = 860.0  # Max safe temperature in Celsius
MAX_SAFE_VIB_MMS = 0.05  # Max safe vibration in mm/s
MAX_SAFE_RPM = 13000  # Max safe rotational speed


def recv_exact(conn, length):
  """Helper to ensure exact byte counts are read from the TCP stream."""
  buf = b""
  while len(buf) < length:
    chunk = conn.recv(length - len(buf))
    if not chunk:
      return None
    buf += chunk
  return buf


receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
receiver_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
receiver_socket.bind(("0.0.0.0", 5000))
receiver_socket.listen(1)

print("🛡️ Receiver listening on port 5000 (AES-256-GCM + Anomaly Engine)...")
conn, addr = receiver_socket.accept()
print(f"✅ Connected by {addr}\n")

last_seen_sequence = 0

try:
  while True:
    # Read length header
    raw_len = recv_exact(conn, 4)
    if not raw_len:
      print("Sender disconnected.")
      break

    payload_len = int.from_bytes(raw_len, byteorder="big")

    # Read payload
    payload = recv_exact(conn, payload_len)
    if not payload or len(payload) < 28:
      continue

    # Unpack Nonce, Auth Tag, Ciphertext
    nonce = payload[:12]
    auth_tag = payload[12:28]
    ciphertext = payload[28:]

    try:
      # Decrypt & Verify Integrity
      cipher = AES.new(SECRET_KEY, AES.MODE_GCM, nonce=nonce)
      decrypted_bytes = cipher.decrypt_and_verify(ciphertext, auth_tag)
      telemetry_payload = json.loads(decrypted_bytes.decode("utf-8"))

      incoming_seq = telemetry_payload["sequence_id"]

      # Anti-Replay Check
      if incoming_seq <= last_seen_sequence:
        print(
            f"⚠️ REPLAY/OUT-OF-ORDER ALERT! Dropped Packet ID: {incoming_seq}"
        )
      else:
        last_seen_sequence = incoming_seq

        ts = telemetry_payload["timestamp"]
        temp = telemetry_payload["temperature_c"]
        press = telemetry_payload["pressure_psi"]
        rpm = telemetry_payload["rpm"]
        vib = telemetry_payload["vibration_mms"]

        print(f"✅ Packet #{incoming_seq} | Time: {ts:.2f}")
        print(
            f"   [Sensors] Temp: {temp}°C | Press: {press} PSI | RPM: {rpm} |"
            f" Vib: {vib} mm/s"
        )

        # PHASE 4: ANOMALY DETECTION EVALUATION
        has_anomaly = False
        if temp > MAX_SAFE_TEMP_C:
          print(
              f"   🚨 [ANOMALY] Thermal Spikes Detected: {temp}°C (Limit:"
              f" {MAX_SAFE_TEMP_C}°C)"
          )
          has_anomaly = True
        if vib > MAX_SAFE_VIB_MMS:
          print(
              f"   🚨 [ANOMALY] Excessive Vibration: {vib} mm/s (Limit:"
              f" {MAX_SAFE_VIB_MMS} mm/s)"
          )
          has_anomaly = True
        if rpm > MAX_SAFE_RPM:
          print(
              f"   🚨 [ANOMALY] Engine Overspeed: {rpm} RPM (Limit:"
              f" {MAX_SAFE_RPM} RPM)"
          )
          has_anomaly = True

        if not has_anomaly:
          print("   💚 [SYSTEM HEALTH] Nominal Operating Parameters")

        print()

    except ValueError:
      print("❌ DECRYPTION FAILED! Invalid Key or Data Tampered.\n")

except KeyboardInterrupt:
  print("\n\n⏹️ Receiver stopped by user (Ctrl+C).")
finally:
  conn.close()
  receiver_socket.close()