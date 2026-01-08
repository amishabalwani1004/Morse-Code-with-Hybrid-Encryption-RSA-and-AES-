from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate 2048-bit RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Save private key (esp32_private.pem)
with open("esp32_private.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Save public key (esp32_public.pem)
public_key = private_key.public_key()
with open("esp32_public.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("✅ ESP32 RSA keypair generated:")
print(" - esp32_private.pem (keep secret!)")
print(" - esp32_public.pem (can share to laptop)")
