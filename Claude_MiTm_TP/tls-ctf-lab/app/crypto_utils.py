"""
crypto_utils.py — Primitives cryptographiques du portail.

Sert uniquement le challenge 2 (fuite de clé privée), qui repose sur une
protection APPLICATIVE (RSA-OAEP) et non sur le transport TLS. Le flag est
publié sous forme de blob chiffré ; la clé privée correspondante est
volontairement exposée par le front-end de la cible. L'étudiant récupère la
clé et déchiffre le blob — démontrant l'absence de confidentialité persistante
(forward secrecy) lorsqu'une clé long-terme fuit.

Dépendance : cryptography (pyca).
"""

import base64
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

_KEY_DIR = os.environ.get("KEY_DIR", "/data/keys")
_PRIV_PATH = os.path.join(_KEY_DIR, "server.key")
_PUB_PATH = os.path.join(_KEY_DIR, "server.pub")


def ensure_keypair() -> rsa.RSAPrivateKey:
    """Charge la paire RSA du challenge 2, ou la génère au premier démarrage."""
    os.makedirs(_KEY_DIR, exist_ok=True)
    if os.path.exists(_PRIV_PATH):
        with open(_PRIV_PATH, "rb") as fh:
            return serialization.load_pem_private_key(fh.read(), password=None)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(_PRIV_PATH, "wb") as fh:
        fh.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    with open(_PUB_PATH, "wb") as fh:
        fh.write(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return key


def encrypt_flag(flag: str) -> str:
    """Chiffre le flag en RSA-OAEP(SHA-256) et renvoie un blob base64."""
    key = ensure_keypair()
    ct = key.public_key().encrypt(
        flag.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ct).decode()
