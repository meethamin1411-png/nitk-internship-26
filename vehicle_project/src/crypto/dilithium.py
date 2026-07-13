from pqcrypto.sign import ml_dsa_65


def generate_keypair():
    """
    Generate ML-DSA (Dilithium) public/private key pair.
    """
    public_key, secret_key = ml_dsa_65.generate_keypair()
    return public_key, secret_key


def sign_message(secret_key, message: bytes):
    """
    Sign a message using ML-DSA.
    """
    return ml_dsa_65.sign(secret_key, message)


def verify_signature(public_key, message: bytes, signature: bytes):
    """
    Verify ML-DSA signature.
    """
    try:
        ml_dsa_65.verify(public_key, message, signature)
        return True
    except Exception:
        return False
        