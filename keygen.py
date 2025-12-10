# keygen.py
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pathlib import Path

def generate_keys(priv_path="issuer_priv.pem", pub_path="issuer_pub.pem"):
    key = ec.generate_private_key(ec.SECP256R1())
    priv_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    Path(priv_path).write_bytes(priv_bytes)
    Path(pub_path).write_bytes(pub_bytes)
    print(f"Generated:\n - {priv_path}\n - {pub_path}")

if __name__ == "__main__":
    generate_keys()
