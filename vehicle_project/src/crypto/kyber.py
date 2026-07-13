"""
Real ML-KEM (Kyber) Implementation
NIST Standard ML-KEM-768
"""

from pqcrypto.kem import ml_kem_768
import hashlib


# -------------------------------------------------------
# Generate ML-KEM Key Pair
# -------------------------------------------------------

def generate_keypair():
    """
    Generate ML-KEM public/private key pair.
    """
    public_key, secret_key = ml_kem_768.generate_keypair()

    return public_key, secret_key


# -------------------------------------------------------
# Encapsulation
# -------------------------------------------------------

def encapsulate(public_key):
    """
    Encapsulate using receiver's public key.

    Returns:
        ciphertext
        shared_secret
    """

    ciphertext, shared_secret = ml_kem_768.encrypt(public_key)

    return ciphertext, shared_secret


# -------------------------------------------------------
# Decapsulation
# -------------------------------------------------------

def decapsulate(secret_key, ciphertext):
    """
    Recover shared secret.
    """

    shared_secret = ml_kem_768.decrypt(
        secret_key,
        ciphertext
    )

    return shared_secret


# -------------------------------------------------------
# Session Key Derivation
# -------------------------------------------------------

def derive_session_key(shared_secret, context):
    """
    Derive a 256-bit session key.
    """

    if isinstance(context, str):
        context = context.encode()

    return hashlib.sha256(
        shared_secret + context
    ).digest()