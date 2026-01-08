# Morse-Code-with-Hybrid-Encryption-RSA-and-AES-
# Hybrid Encrypted Morse Communication (ESP32 + Python)

## 📌 Overview
This project implements a **secure communication system** where Morse code messages are transmitted from a **Python client** to an **ESP32** device using a **hybrid cryptography model**.

The system combines:
- **RSA** for secure session key exchange
- **AES-GCM** for encrypted message transmission
- **UDP over Wi-Fi** for lightweight, real-time communication

The ESP32 decrypts and displays the received Morse code messages in real time.

---

## 🔐 Why Hybrid Encryption?
Asymmetric encryption (RSA) is secure but slow, while symmetric encryption (AES) is fast but requires secure key sharing.

This project uses:
- **RSA** → to securely exchange an AES session key
- **AES-GCM** → to encrypt actual Morse messages efficiently

This mirrors how real-world secure systems work (e.g., TLS).

---

## 🏗️ System Architecture
1. ESP32 boots and connects to Wi-Fi
2. ESP32 listens on a UDP port
3. Python client generates an AES session key
4. AES key is encrypted using ESP32’s RSA public key
5. ESP32 decrypts and installs the AES session key
6. Morse messages are sent using AES-GCM encryption
7. ESP32 decrypts and displays Morse messages

---

## 🧰 Tech Stack
- **Hardware:** ESP32
- **Firmware:** PlatformIO (Arduino framework)
- **Client:** Python 3
- **Cryptography:** RSA, AES-GCM
- **Networking:** UDP over Wi-Fi

---

## 📂 Project Structure
