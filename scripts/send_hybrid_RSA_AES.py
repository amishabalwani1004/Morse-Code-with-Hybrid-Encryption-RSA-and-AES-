import os
import socket
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ========= CONFIG =========
ESP_IP = "192.168.1.21"      # <-- change to your ESP32 IP from Serial Monitor
ESP_PORT = 5005
PUB_KEY_FILE = "esp32_public.pem"
# ==========================


# --- Load ESP32 public key ---
def load_public_key():
    with open(PUB_KEY_FILE, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# --- RSA encrypt (PKCS1v15) for key exchange ---
def rsa_encrypt_psk(public_key, psk_bytes: bytes) -> bytes:
    return public_key.encrypt(
        psk_bytes,
        padding.PKCS1v15()
    )


# --- Send a raw UDP string ---
def send_udp(message: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message.encode(), (ESP_IP, ESP_PORT))
    sock.close()


# --- Phase 1: send session AES key (PSK) using RSA ---
def send_session_key(public_key) -> bytes:
    # generate 32-byte AES-256 key
    psk = os.urandom(32)
    ct = rsa_encrypt_psk(public_key, psk)
    b64_ct = base64.b64encode(ct).decode()

    packet = "KEY:" + b64_ct
    send_udp(packet)

    print("[HYBRID] Session key generated & sent via RSA.")
    print("[HYBRID] PSK (hex, for debug):", psk.hex())
    return psk


# --- Phase 2: send Morse message using AES-GCM ---
def send_morse_aes(psk: bytes, morse_str: str, seq: int = 1):
    aesgcm = AESGCM(psk)
    iv = os.urandom(12)   # 96-bit nonce

    # we can include seq in AAD later if we want; for now None
    plaintext = morse_str.encode()
    ct_with_tag = aesgcm.encrypt(iv, plaintext, None)

    # AESGCM.encrypt returns ciphertext||tag (tag = last 16 bytes)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    b64_iv = base64.b64encode(iv).decode()
    b64_tag = base64.b64encode(tag).decode()
    b64_ct = base64.b64encode(ciphertext).decode()

    packet = f"MSG:{b64_iv}:{b64_tag}:{b64_ct}"
    send_udp(packet)

    print(f"[HYBRID] Sent Morse (AES-GCM, seq={seq}):", morse_str)


def main():
    pub = load_public_key()

    # ---- Phase 1: RSA key exchange ----
    psk = send_session_key(pub)

    print("\nNow sending Morse messages using AES-GCM.")
    print("Type Morse (e.g. '.... .'), or 'quit' to exit.\n")

    seq = 1
    while True:
        try:
            text = input("Morse> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[HYBRID] Exit.")
            break

        if not text:
            continue
        if text.lower() in ("q", "quit", "exit"):
            print("[HYBRID] Exit.")
            break

        send_morse_aes(psk, text, seq)
        seq += 1


if __name__ == "__main__":
    main()
