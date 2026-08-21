# GTRE Real-Time Encrypted Telemetry System

A secure telemetry streaming pipeline using AES-256-GCM encryption and anti-replay mechanisms.

## Execution Output
![GTRE Telemetry Live Output](p77/o1.png/o2.png)

## Features
- **AES-256-GCM Encryption:** Secures sensor payloads over TCP.
- **Anti-Replay Protection:** Rejects duplicate or out-of-order sequence IDs.
- **Length-Prefixed Framing:** Ensures reliable packet boundaries over socket streams.

## How to Run
1. Receiver: `python Receiver.py`
2. Sender: `python Sender.py`